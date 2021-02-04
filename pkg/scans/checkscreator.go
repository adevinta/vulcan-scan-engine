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

	"github.com/go-kit/kit/log/level"
	uuid2 "github.com/goadesign/goa/uuid"
	uuid "github.com/satori/go.uuid"

	"github.com/adevinta/vulcan-core-cli/vulcan-core/client"
	"github.com/adevinta/vulcan-scan-engine/pkg/api"
	"github.com/adevinta/vulcan-scan-engine/pkg/api/persistence/db"
	"github.com/adevinta/vulcan-scan-engine/pkg/api/service"
)

// MaxScanAge Max number of days a scan be in "creating checks state"
const MaxScanAge = 5

var (
	// ErrScanTerminated is returned if the scan is terminated while the check
	// creator is still creating its checks.
	ErrScanTerminated = errors.New("scan is not RUNNING anymore")
)

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

// PushCheck function called when the payload of a new check is created.
type PushCheck func(*client.CheckPayload) error

// Logger defines the shape of the logger required by the persistence.
type Logger interface {
	Log(vals ...interface{}) error
}

// ChecktypesByAssettypes is used as a lookup table to check if a checktype can
// be run against a concrete assettype.
type ChecktypesByAssettypes map[string]map[string]struct{}

type CheckSender interface {
	Notify(m *client.CheckPayload) error
}

// ChecksCreator allows to create the checks of a scan in a stateless way. That
// is: It can resume creating the checks of a scan even if the creation process
// was unexpectedly stopped.
type ChecksCreator struct {
	store  Store
	sender CheckSender
	l      Logger
}

// NewChecksCreator creates and returns a new ChecksCreator given its
// dependencies.
func NewChecksCreator(store Store,
	sender CheckSender, l Logger) *ChecksCreator {
	return &ChecksCreator{
		store:  store,
		sender: sender,
		l:      l,
	}
}

// CreateIncompleteScansChecks queries the db for incomplete scans and for each
// of them: either it creates the pending checks or it finishes the scan if it
// is older than MaxScanAge days.
func (c *ChecksCreator) CreateIncompleteScansChecks() error {
	ids, err := c.store.GetCreatingScans()
	if err != nil {
		level.Error(c.l).Log("error_getting_scans_to_create", err)
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

// CreateScanChecks checks if a scan has still checks to be created and if it
// does it locks the scan and creates them. The process of creating the checks
// of a scan is done in a way that it can be stopped unexpectedly at any time
// and restarted from the last check it was created.
func (c *ChecksCreator) CreateScanChecks(id string) error {
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

	if scan.TargetGroups == nil {
		// Scans with no target groups should not be RUNNING.
		status := service.ScanStatusFinished
		scan.Status = &status
		level.Warn(c.l).Log("ScanWithNoTargetGroups", id)
		_, err = c.store.UpdateScan(sid, scan, []string{service.ScanStatusRunning})
		return err
	}

	if scan.StartTime == nil || (time.Since(*scan.StartTime).Hours() > MaxScanAge*24) {
		// Scans with older than the max age should not be RUNNING.
		status := service.ScanStatusFinished
		scan.Status = &status
		level.Warn(c.l).Log("ScanTooOld", id)
		_, err = c.store.UpdateScan(sid, scan, []string{service.ScanStatusRunning})
		return err
	}

	// The checktypes info used to create the checks of a scan should be fixed,
	// thus stored in the scan, so even if that info changes meanwhile the
	// checks of the scan are being created the checks to create for this scan
	// remain the same.
	if scan.ChecktypesInfo == nil {
		// Scans with no target groups should not be RUNNING.
		status := service.ScanStatusFinished
		scan.Status = &status
		level.Warn(c.l).Log("ScanWithNoChecktypesInfo", id)
		_, err = c.store.UpdateScan(sid, scan, []string{service.ScanStatusRunning})
		return err
	}

	checktypesInfo := scan.ChecktypesInfo

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
	// The checksCreated var should be never nil for the scans that are using
	// async creation, in any case we check this in order to avoid panics.
	checksCreated := 0
	if scan.ChecksCreated != nil {
		checksCreated = *scan.ChecksCreated
	}
	level.Debug(c.l).Log("CreatingChecks", len(*scan.TargetGroups))
	tgroups := *scan.TargetGroups
	for tGroupIndex := currentTargetG; tGroupIndex < len(*scan.TargetGroups); tGroupIndex++ {
		tg := tgroups[tGroupIndex]
		checkGroupIndex := currentCheckG
		err = c.createChecks(scan.Tag, tg, checktypesInfo, currentCheckG, func(cp *client.CheckPayload) error {
			check := api.Check{Data: []byte("{}")}
			check.ScanID = scan.ID.String()
			// We create a new uuid and use it to create a new check.
			cID := uuid2.NewV4()
			check.ID = cID.String()
			// Set the id also in the payload sent to the persistence. That's
			// required in order to make idempotent the operation of creating
			// checks by the persistence.
			cp.Check.ID = &cID
			ssid, err := uuid2.FromString(scan.ID.String())
			if err != nil {
				return err
			}
			cp.Check.ScanID = &ssid
			cp.Check.ProgramID = scan.ExternalID
			index := fmt.Sprintf("%d_%d", tGroupIndex, checkGroupIndex)
			check.ScanIndex = &index
			// In order to make the operation idempotent we set the ScanIndex of
			// the check to the corresponding offset of the checks created for
			// the scan. So, if a check for the same scan with the same
			// ScanIndex is already in the DB we keep that same id for the
			// check. To do so, the following function creates a check only if
			// there is no check for the same scan with the same scan index. If
			// there is, it returns the id of that existing check. This ensures
			// that if we send the same check multiple times to the sns they
			// will have the same id.
			level.Debug(c.l).Log("CreatingCheck", index, "Scan", check.ScanID)
			id, err := c.store.InsertCheckIfNotExists(check)
			if err != nil {
				return err
			}
			check.ID = id
			cpID, err := uuid2.FromString(id)
			if err != nil {
				return err
			}
			cp.Check.ID = &cpID
			err = c.sender.Notify(cp)
			if err != nil {
				return err
			}
			level.Debug(c.l).Log("CheckCreated", index, "Scan", check.ScanID)
			scan.LastCheckCreated = &checkGroupIndex
			checksCreated++
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
			checkGroupIndex++
			// If the scan has not been updated it's because is not RUNNING, for
			// instance because it has been aborted. In that case we stop
			// creating checks.
			if count == 0 {
				return ErrScanTerminated
			}
			return nil
		})
		if err != nil {
			if errors.Is(err, ErrScanTerminated) {
				// Just stop creating checks for this scan.
				return nil
			}
			return err
		}
		last := tGroupIndex
		lastCheck := -1
		updateScan := api.Scan{
			ID:                      scan.ID,
			LastCheckCreated:        &lastCheck,
			LastTargetCheckGCreated: &last,
		}
		_, err = c.store.UpdateScan(scan.ID, updateScan, []string{service.ScanStatusRunning})
		if err != nil {
			return err
		}
	}
	return err
}

func (c *ChecksCreator) createChecks(tag *string, group api.TargetsChecktypesGroup,
	checktypesInfo ChecktypesByAssettypes, start int, pusher PushCheck) error {

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
	for _, a := range group.TargetGroup.Targets {
		for _, c := range group.ChecktypesGroup.Checktypes {
			validChecksForAsset, ok := checktypesInfo[a.Type]
			if !ok {
				return fmt.Errorf("invalid assettype %s", a.Type)
			}
			_, ok = validChecksForAsset[c.Name]
			if !ok {
				// If the check is not present in the map for assettype it means
				// the checktype cannot run against this asset.
				continue
			}

			if i < start {
				i++
				continue
			}
			// It's better to assign those values to single variables even if it
			// is not needed just to make clear the order in which the options
			// are overridden. Concretely one variable overrides the options of
			// the previous ones if they define the same fields.
			checktypeOpts := c.Options
			targetGroupOpts := group.TargetGroup.Options
			targetOpts := a.Options
			options, err := buildOptionsForCheck(checktypeOpts, targetGroupOpts, targetOpts)
			if err != nil {
				return err
			}
			name := c.Name
			assettype := a.Type
			check := client.CheckPayload{
				Check: &client.CheckData{
					ChecktypeName: &name,
					Options:       &options,
					Target:        a.Identifier,
					Tag:           tag,
					Assettype:     &assettype,
				},
			}
			err = pusher(&check)
			if err != nil {
				return err
			}
			i++
		}
	}
	return nil
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
