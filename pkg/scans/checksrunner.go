/*
Copyright 2021 Adevinta
*/

package scans

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/go-kit/log/level"
	uuid "github.com/satori/go.uuid"

	"github.com/adevinta/vulcan-core-cli/vulcan-core/client"
	"github.com/adevinta/vulcan-scan-engine/pkg/api"
	"github.com/adevinta/vulcan-scan-engine/pkg/api/persistence/db"
	"github.com/adevinta/vulcan-scan-engine/pkg/api/service"
	"github.com/adevinta/vulcan-scan-engine/pkg/util"
)

// MaxScanAge Max number of days a scan be in "creating checks state"
const MaxScanAge = 5

var (
	errScanTerminated = errors.New("scan is not RUNNING anymore")
)

// nexCheck function called when the payload of a new check
// for a TargetChecktypeGroup is created.
type newCheck func(api.Check) error

// JobSender send a job to be run by an agent.
type JobSender interface {
	Send(queueName string, checktypeName string, job Job) error
}

// ChecktypeInformer defines the services required by the JobCreator type to be
// able to query information about checktypes.
type ChecktypeInformer interface {
	GetChecktype(name string) (*client.Checktype, error)
}

// Store defines the methods required by the check creator to query and update
// checks and scans.
type Store interface {
	GetCreatingScans() ([]string, error)
	TryLockScan(id string) (*db.Lock, error)
	ReleaseScanLock(l *db.Lock) error
	GetScanByID(id uuid.UUID) (api.Scan, error)
	UpdateScan(id uuid.UUID, scan api.Scan, updateStates []string) (int64, error)
	InsertCheckIfNotExists(c api.Check) (string, error)
}

// CheckNotifier is used by the ChecksRunner to send notifications when a Check
// has ben created or sent to a queue.
type CheckNotifier interface {
	CheckUpdated(c api.Check, programID string)
}

type Logger interface {
	Log(keyvals ...interface{}) error
}

// ChecksRunner allows to create the checks of a scan in a stateless way.
type ChecksRunner struct {
	store          Store
	sender         JobSender
	l              Logger
	checksListener CheckNotifier
	ctinformer     ChecktypeInformer
	checkpoint     int
}

// NewJobsCreator creates and returns a new JobsCreator given its
// dependencies.
func NewJobsCreator(store Store,
	sender JobSender, ctinformer ChecktypeInformer, checkListener CheckNotifier, checkpoint int, l Logger) *ChecksRunner {
	return &ChecksRunner{
		store:          store,
		sender:         sender,
		l:              l,
		ctinformer:     ctinformer,
		checksListener: checkListener,
		checkpoint:     checkpoint,
	}
}

// CreateIncompleteScansChecks queries the db for incomplete scans. For each of
// those scans either it creates the pending checks or it finishes the scan in
// case it's older than MaxScanAge.
func (c *ChecksRunner) CreateIncompleteScansChecks() error {
	ids, err := c.store.GetCreatingScans()
	if err != nil {
		c.l.Log("error_getting_scans_to_create", err)
		return err
	}
	for _, id := range ids {
		err = c.CreateScanChecks(id)
		if err != nil {
			return err
		}
	}
	return nil
}

// CreateScanChecks checks if a scan has still checks to be created and run, if
// it does, it locks the scan and creates the pending checks. The process of
// creating the checks of is done in a way that it can be stopped unexpectedly
// at any time and it will be automatically resumed using at least once
// semantincs.
func (c *ChecksRunner) CreateScanChecks(id string) error {
	// Try to get a lock for the scan.
	lock, err := c.store.TryLockScan(id)
	if err != nil {
		return err
	}
	defer c.store.ReleaseScanLock(lock)
	// Some other worker is already processing the scan, just return.
	if !lock.Acquired {
		return nil
	}
	sid, err := uuid.FromString(id)
	if err != nil {
		return err
	}

	scan, err := c.store.GetScanByID(sid)
	if err != nil {
		return err
	}

	if scan.StartTime == nil || (time.Since(*scan.StartTime).Hours() > MaxScanAge*24) {
		// Scans older than the max age should not be RUNNING.
		status := service.ScanStatusFinished
		updateScan := api.Scan{
			ID:     sid,
			Status: &status,
		}
		n, err := c.store.UpdateScan(sid, updateScan, []string{service.ScanStatusRunning})
		level.Warn(c.l).Log("ScanTooOld", id, "Updated", n)
		return err
	}

	// The checksCreated var should be never nil for the scans that are using
	// async creation, in any case we check this in order to avoid panics.
	checksCreated := 0
	if scan.ChecksCreated != nil {
		checksCreated = *scan.ChecksCreated
	}

	// Recheck if the scan was already finished by other worker since the last query.
	if *scan.CheckCount == checksCreated {
		// Scans was already created.
		level.Warn(c.l).Log("ScanAlreadyCreated", id)
		return nil
	}

	if scan.TargetGroups == nil || len(*scan.TargetGroups) == 0 {
		// Scans with no target groups should not be RUNNING.
		level.Warn(c.l).Log("ScanWithNoTargetGroups", id)
		return nil
	}

	// The checktypes info used to create the checks of a scan should be fixed
	// thus stored in the scan, so even if that info changes meanwhile the
	// checks of the scan are being created the checks remain the same.
	if scan.ChecktypesInfo == nil {
		// Scans with no target groups should not be RUNNING.
		level.Warn(c.l).Log("ScanWithNoChecktypesInfo", id)
		return err
	}

	checktypesInfo := *scan.ChecktypesInfo

	// This variable holds the current target group.
	currentTargetG := -1
	if scan.LastTargetCheckGCreated != nil {
		currentTargetG = *scan.LastTargetCheckGCreated
	}

	currentTargetG++

	// This variable holds the next check to create inside the current target
	// group.
	currentCheckG := -1
	if scan.LastCheckCreated != nil {
		currentCheckG = *scan.LastCheckCreated
	}
	currentCheckG++

	level.Info(c.l).Log("Scan", id, "TargetGroups", len(*scan.TargetGroups), "CheckCount", scan.CheckCount,
		"StartFrom", fmt.Sprintf("%d_%d", currentTargetG, currentCheckG), "ChecksCreated", checksCreated)

	checkpointCount := 0
	start := time.Now()

	for tGroupIndex := currentTargetG; tGroupIndex < len(*scan.TargetGroups); tGroupIndex++ {
		tgroups := *scan.TargetGroups
		tg := tgroups[tGroupIndex]
		checkGroupIndex := currentCheckG
		// This function bellow creates the checks for the current target
		// checktypes group, starting at the check corresponding to the
		// currentCheckG. For each created check it calls the function in the
		// last parameter. That function takes the new created check, stores it
		// in the db, creates a job to be run by an agent and sends that job to
		// the proper queue.
		err = c.createChecksForGroup(scan, tg, currentCheckG, checktypesInfo,
			func(check api.Check) error {
				index := fmt.Sprintf("%d_%d", tGroupIndex, checkGroupIndex)
				check.ScanIndex = &index
				// In order to make the operation idempotent we set the
				// ScanIndex of the check to the corresponding offset of the
				// checks created for the scan. So, if a check for the same scan
				// with the same ScanIndex is already in the DB we keep that id.
				// To do so, the following function creates a check only if no
				// other check for the same scan and with the same scan index
				// exists. If it does it returns the id of the existing check,
				// if it does not it returns the id of the passed check. So we
				// are assuming here that we could send a job for a check to be
				// executed more than once, but it could be detected because
				// those jobs will have the same id.
				level.Debug(c.l).Log("CreatingCheck", index, "Scan", check.ScanID)
				id, err := c.store.InsertCheckIfNotExists(check)
				if err != nil {
					return err
				}
				// We ensure the check has the correct id here (see the comment above).
				if check.ID != id {
					level.Warn(c.l).Log("ExistingCheck", index, "Check", id, "Scan", check.ScanID)
					check.ID = id
				} else {
					// We only publish a change when a check has been created.
					c.checksListener.CheckUpdated(check, util.Ptr2Str(scan.ExternalID))
				}

				j, err := JobFromCheck(check)
				if err != nil {
					return err
				}
				// Send the job to be run by an agent. The sender will take care of
				// sending to the proper default queue for the check if no
				// queue name was specified in the checktype.
				err = c.sender.Send(*check.QueueName, *check.ChecktypeName, j)
				if err != nil {
					return err
				}
				level.Debug(c.l).Log("CheckSent", index, "Scan", check.ScanID)

				// Update the last create check of the scan in the DB.
				scan.LastCheckCreated = &checkGroupIndex
				checksCreated++

				// Update the scan every Checkpoint check inserts
				// Always executes for the first time to validate the scanTerminated.
				if c.checkpoint == 0 || checkpointCount%c.checkpoint == 0 {
					level.Info(c.l).Log("Checkpointing", index, "Scan", check.ScanID, "Count", checkpointCount)
					created := checksCreated
					updateScan := api.Scan{
						ID:               scan.ID,
						ChecksCreated:    &created,
						LastCheckCreated: &checkGroupIndex,
					}
					count, err := c.store.UpdateScan(scan.ID, updateScan, []string{service.ScanStatusRunning})
					if err != nil {
						return err
					}
					// If the scan has not been updated it's because is not RUNNING, for
					// instance because it has been aborted. In that case we stop
					// creating checks.
					if count == 0 {
						return errScanTerminated
					}
				}
				checkpointCount++

				checkGroupIndex++

				return nil
			})

		if err != nil {
			if errors.Is(err, errScanTerminated) {
				// Just stop creating checks for this scan.
				return nil
			}
			return err
		}
		last := tGroupIndex
		lastCheck := -1
		created := checksCreated
		updateScan := api.Scan{
			ID:                      scan.ID,
			ChecksCreated:           &created,
			LastCheckCreated:        &lastCheck,
			LastTargetCheckGCreated: &last,
			TargetGroups:            &[]api.TargetsChecktypesGroup{}, // Remove creation process data
			ChecktypesInfo:          &api.ChecktypesByAssettypes{},   // Remove creation process data
		}

		level.Info(c.l).Log("Scan", scan.ID, "GeneratedChecks", checkpointCount, "Seconds", time.Since(start).Seconds())
		_, err = c.store.UpdateScan(scan.ID, updateScan, []string{service.ScanStatusRunning})
		if err != nil {
			return err
		}
	}
	return err
}

func (c *ChecksRunner) createCheck(scan api.Scan, g api.TargetsChecktypesGroup, target api.Target, ct api.Checktype) (api.Check, error) {
	checktypeOpts := ct.Options
	targetGroupOpts := g.TargetGroup.Options
	targetOpts := target.Options
	options, err := buildOptionsForCheck(checktypeOpts, targetGroupOpts, targetOpts)
	if err != nil {
		return api.Check{}, err
	}
	name := ct.Name
	assetType := target.Type
	meta := buildCheckMetadata(scan.Tag, scan.ExternalID)
	t := ""
	if scan.Tag != nil {
		t = *scan.Tag
	}

	ctInfo, err := c.ctinformer.GetChecktype(ct.Name)
	if err != nil {
		return api.Check{}, err
	}
	id, err := uuid.NewV1()
	if err != nil {
		return api.Check{}, err
	}
	optsC := options
	optsCT := ""
	if ctInfo.Checktype.Options != nil {
		optsCT = *ctInfo.Checktype.Options
	}
	opts, err := deepMergeJsons(optsCT, optsC)
	if err != nil {
		return api.Check{}, err
	}
	queue := ""
	if ctInfo.Checktype.QueueName != nil {
		queue = *ctInfo.Checktype.QueueName
	}
	now := time.Now()
	progress := float32(0.0)
	checktypeID := ctInfo.Checktype.ID.String()
	check := api.Check{
		ID:            id.String(),
		Status:        api.CheckStateCreated,
		ScanID:        scan.ID.String(),
		Target:        target.Identifier,
		Progress:      &progress,
		ScanIndex:     nil,
		AgentID:       nil,
		ChecktypeID:   &checktypeID,
		ChecktypeName: &name,
		Image:         &ctInfo.Checktype.Image,
		Options:       &opts,
		WebHook:       nil,
		Report:        nil,
		Raw:           nil,
		QueueName:     &queue,
		Tag:           &t,
		Assettype:     &assetType,
		Metadata:      &meta,
		RequiredVars:  &ctInfo.Checktype.RequiredVars,
		CreatedAt:     &now,
		UpdatedAt:     &now,
		Timeout:       ctInfo.Checktype.Timeout,
		// This field Data must be deprecated in future versions.
		Data: []byte("{}"),
	}
	return check, nil
}

// createChecksForGroup creates the jobs, that is the messages for an agent to
// execute the checks of a given scan group starting at the given check of that
// group. For each job created, it "call backs" the function "pusher" to give
// the opportunity to the caller to store the check and send the job.
//
// The group parameter contains two lists: one with targets e.g: {"example.com",
// "192.168.0.1"} and another with checktypes, e.g.:
// {"vulcan-check-one","vulcan-checks"}. The method created the jobs doing a
// cartesian product between the two lists and removing the pairs {"target",
// "checktype"} that are not valid. A pair {target1,checktype1} is not valid if
// the information stored in the ChecktypesByAssettypes parameter statest that
// the valid asset types for the checktype1 do not include the asset type of the
// "target1", that is, if a checktype can not be executed against the asset
// type of the target1. The parameter start is used to determine in which index
// of the list of the valid pairs {targe1,checktype1} continue creating the
// jobs.
func (c *ChecksRunner) createChecksForGroup(scan api.Scan, group api.TargetsChecktypesGroup,
	start int, checktypesInfo api.ChecktypesByAssettypes, checkCreated newCheck) error {
	// We sort the targets and checktypes groups so, assuming they contain the
	// same items, we will walk them in the same order in successive calls to
	// this function.
	sort.SliceStable(group.TargetGroup.Targets, func(i, j int) bool {
		// The identifiers in a the targets slice must be unique.
		ia := group.TargetGroup.Targets[i].Identifier
		ib := group.TargetGroup.Targets[j].Identifier
		return ia < ib
	})
	sort.SliceStable(group.ChecktypesGroup.Checktypes, func(i, j int) bool {
		cta := group.ChecktypesGroup.Checktypes[i].Name
		ctb := group.ChecktypesGroup.Checktypes[j].Name
		return cta < ctb
	})
	i := 0
	for _, t := range group.TargetGroup.Targets {
		for _, ct := range group.ChecktypesGroup.Checktypes {
			validChecksForAsset, ok := checktypesInfo[t.Type]
			if !ok {
				return fmt.Errorf("invalid assettype %s", t.Type)
			}
			_, ok = validChecksForAsset[ct.Name]
			if !ok {
				// If the check is not present in the map for assettype it means
				// the checktype cannot run against this asset.
				continue
			}
			if i < start {
				i++
				continue
			}
			check, err := c.createCheck(scan, group, t, ct)
			if err != nil {
				return err
			}
			err = checkCreated(check)
			if err != nil {
				return err
			}
			i++
		}
	}
	return nil
}

// deepMergeJsons merges two json from their string representation.
func deepMergeJsons(jsonA, jsonB string) (string, error) {
	if jsonA != "" && jsonB == "" {
		return jsonA, nil
	}

	if jsonA == "" && jsonB != "" {
		return jsonB, nil
	}
	merged := map[string]interface{}{}
	err := json.Unmarshal([]byte(jsonA), &merged)
	if err != nil {
		return "", err
	}
	err = json.Unmarshal([]byte(jsonB), &merged)
	if err != nil {
		return "", err
	}
	res, err := json.Marshal(merged)
	if err != nil {
		return "", err
	}
	return string(res), nil
}

func buildCheckMetadata(tag, externalID *string) map[string]string {
	meta := map[string]string{
		"program": "unknown-program",
		"team":    "unknown-team",
	}
	if externalID != nil && *externalID != "" {
		meta["program"] = *externalID
	}
	if tag == nil || *tag == "" {
		return meta
	}
	meta["team"] = *tag
	return meta
}

// mergeOptions takes two check options.
func mergeOptions(optsA map[string]interface{}, optsB map[string]interface{}) map[string]interface{} {
	merged := map[string]interface{}{}
	for k, v := range optsA {
		merged[k] = v
	}
	for k, v := range optsB {
		merged[k] = v
	}
	return merged
}

func buildOptionsForCheck(checktypeOpts, targetGroupOpts, targetOpts string) (string, error) {
	totalOptions := map[string]interface{}{}
	if checktypeOpts != "" {
		json.Unmarshal([]byte(checktypeOpts), &totalOptions)
	}
	if targetGroupOpts != "" {
		aux := map[string]interface{}{}
		if err := json.Unmarshal([]byte(targetGroupOpts), &aux); err != nil {
			return "", nil
		}
		totalOptions = mergeOptions(totalOptions, aux)
	}
	if targetOpts != "" {
		aux := map[string]interface{}{}
		if err := json.Unmarshal([]byte(targetOpts), &aux); err != nil {
			return "", nil
		}
		totalOptions = mergeOptions(totalOptions, aux)
	}
	content, err := json.Marshal(totalOptions)
	if err != nil {
		return "", err
	}
	return string(content), nil
}
