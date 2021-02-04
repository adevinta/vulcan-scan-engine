/*
Copyright 2021 Adevinta
*/

package service

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"

	uuid2 "github.com/goadesign/goa/uuid"
	uuid "github.com/satori/go.uuid"
	validator "gopkg.in/go-playground/validator.v9"

	"github.com/adevinta/errors"
	"github.com/adevinta/vulcan-core-cli/vulcan-core/client"
	metrics "github.com/adevinta/vulcan-metrics-client"
	"github.com/adevinta/vulcan-scan-engine/pkg/api"
)

const (

	// ScanStatusRunning status when a Scan is created.
	ScanStatusRunning = "RUNNING"

	// ScanStatusFinished status when a Scan has all the checks in a terminal status.
	ScanStatusFinished = "FINISHED"

	// ScanStatusAborted status when a Scan has all the checks in a terminal status and
	// at least one is in an ABORTED status.
	ScanStatusAborted = "ABORTED"

	// Scan metrics.
	componentTag         = "component:scanengine"
	scanCountMetric      = "vulcan.scan.count"
	scanCompletionMetric = "vulcan.scan.completion"
	metricsScanCreated   = "created"
	metricsScanFinished  = "finished"
)

var (
	checkStates = states{
		[]string{"CREATED"},
		[]string{"QUEUED"},
		[]string{"ASSIGNED"},
		[]string{"RUNNING"},
		[]string{"PURGING"},
		[]string{"MALFORMED", "ABORTED", "KILLED", "FAILED", "FINISHED", "TIMEOUT", "INCONCLUSIVE"},
	}
	// ScansByExternalIDLimit the number of scans to return when querying by external
	// id.
	ScansByExternalIDLimit uint32 = 5
)

// states holds all prosibles states of a finite state machine
// in a way that is easy to determine the states less or equal than a
// given state. This implementation supposes that there are only few states
// so the cost of walking through all the states is close to constant.
type states [][]string

func (c states) Init() {
	for _, s := range c {
		sort.Strings(s)
	}
}
func (c states) LessOrEqual(s string) ([]string, error) {
	res := []string{}
	var found bool
	for i := 0; i < len(c); i++ {
		res = append(res, c[i]...)
		x := sort.SearchStrings(c[i], s)
		if x < len(c[i]) && c[i][x] == s {
			found = true
			break
		}
	}
	if !found {
		return []string{}, ErrNotDefinedCheckState
	}
	return res, nil
}
func (c states) Terminal() []string {
	return c[len(c)-1]
}
func (c states) IsTerminal(s string) bool {
	t := c.Terminal()
	x := sort.SearchStrings(t, s)
	return (x < len(t) && t[x] == s)
}
func init() {
	checkStates.Init()
}

type ScansPersistence interface {
	CreateScan(id uuid.UUID, scan api.Scan) (int64, error)
	UpsertCheck(scanID, id uuid.UUID, check api.Check, updateStates []string) (int64, error)
	GetScanChecks(scanID uuid.UUID) ([]api.Check, error)
	GetScanByID(id uuid.UUID) (api.Scan, error)
	UpdateScan(id uuid.UUID, scan api.Scan, updateStates []string) (int64, error)
	GetScansByExternalIDWithLimit(ID string, limit *uint32) ([]api.Scan, error)
	GetChecksStatusStats(scanID uuid.UUID) (map[string]int, error)
	DeleteScanChecks(scanID uuid.UUID) error
}

type CoreAPI interface {
	UploadFileScans(ctx context.Context, path string, payload *client.FileScanPayload) (*http.Response, error)
	DecodeScan(resp *http.Response) (*client.Scan, error)
	AbortScans(ctx context.Context, path string) (*http.Response, error)
	IndexAssettypes(ctx context.Context, path string) (*http.Response, error)
	DecodeAssettypeCollection(resp *http.Response) (client.AssettypeCollection, error)
}

// ScanNotifier defines the services needed by the Scan srv to send
// notifications when a scan finishes.
type ScanNotifier interface {
	Notify(scan api.ScanNotification) error
}

// AsyncChecksCreator ...
type AsyncChecksCreator interface {
	CreateScanChecks(id string) error
}

type scanStats struct {
	TotalNumberOfChecks        int
	NumberOfChecksPerChecktype map[string]int
}

// ScansService implements the functionality needed to create and query scans.
type ScansService struct {
	db            ScansPersistence
	logger        log.Logger
	vulcanCore    CoreAPI
	notifier      ScanNotifier
	ccreator      *CheckCreator
	metricsClient metrics.Client
	accreator     AsyncChecksCreator
}

// New Creates and returns ScansService with all the dependencies wired in.
func New(logger log.Logger, db ScansPersistence, client CoreAPI, notifier ScanNotifier,
	metricsClient metrics.Client, accreator AsyncChecksCreator) ScansService {
	creator := &CheckCreator{assettypeInformer: client}
	return ScansService{
		db:            db,
		logger:        logger,
		vulcanCore:    client,
		notifier:      notifier,
		ccreator:      creator,
		accreator:     accreator,
		metricsClient: metricsClient,
	}

}

// GetScan returns the scan corresponding with a given id.
func (s ScansService) GetScan(ctx context.Context, strID string) (api.Scan, error) {
	id, err := uuid.FromString(strID)
	if err != nil {
		return api.Scan{}, errors.Assertion(fmt.Sprintf("not valid scan ID %s", strID))
	}
	scan, err := s.db.GetScanByID(id)
	if err != nil {
		return api.Scan{}, err
	}
	return scan, nil
}

// AbortScan is called in order to signal the vulcan core to try to abort and on going scan.
func (s ScansService) AbortScan(ctx context.Context, strID string) error {
	id, err := uuid.FromString(strID)
	if err != nil {
		return errors.Assertion(fmt.Sprintf("not valid scan ID %s", strID))
	}
	_, err = s.db.GetScanByID(id)
	if err != nil {
		return err
	}
	// The goa generated method AbortScansPath only accept goa uuid.
	goaUUID, _ := uuid2.FromString(strID)
	resp, err := s.vulcanCore.AbortScans(ctx, client.AbortScansPath(goaUUID))
	if err != nil {
		return errors.Default(fmt.Sprintf("can not abort scan %s in vulcan core: %v", strID, err))
	}
	switch resp.StatusCode {
	case http.StatusAccepted:
		return nil
	case http.StatusNotFound:
		return errors.NotFound(fmt.Sprintf("can not abort scan %s in vulcan core", strID))
	case http.StatusConflict:
		return errors.Duplicated(fmt.Sprintf("scan %s has already been marked as aborted", strID))
	default:
		return errors.Default(fmt.Sprintf("can not abort scan %s in vulcan core. Status code %d", strID, resp.StatusCode))
	}
}

// GetScansByExternalID returns the scans that have the same external ids.
func (s ScansService) GetScansByExternalID(ctx context.Context, ID string, all bool) ([]api.Scan, error) {
	var limit *uint32
	if !all {
		limit = &ScansByExternalIDLimit
	}
	scans, err := s.db.GetScansByExternalIDWithLimit(ID, limit)
	if err != nil {
		return nil, err
	}
	return scans, nil
}

func (s ScansService) CreateScanChecksAsync(ctx context.Context, scan *api.Scan) (uuid.UUID, error) {
	if scan == nil {
		return uuid.Nil, errors.Default("unexpected nil value creating a scan")
	}
	now := time.Now()
	scan.StartTime = &now
	id, err := uuid.NewV4()
	if err != nil {
		return uuid.Nil, err
	}
	scan.ID = id
	status := ScanStatusRunning
	scan.Status = &status
	ctypesInfo, err := s.checktypesByAssettype(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	scan.ChecktypesInfo = ctypesInfo
	stats, err := s.getScanStats(ctx, ctypesInfo, scan)
	if err != nil {
		return uuid.Nil, err
	}
	scan.CheckCount = &stats.TotalNumberOfChecks
	ccreated := 0
	scan.ChecksCreated = &ccreated
	_, err = s.db.CreateScan(id, *scan)
	if err != nil {
		return uuid.Nil, err
	}
	// Push metrics.
	s.pushScanMetrics(metricsScanCreated, ptr2Str(scan.Tag), ptr2Str(scan.ExternalID), stats)
	_ = level.Warn(s.logger).Log("ScanCreated", id)
	go func() {
		err := s.accreator.CreateScanChecks(id.String())
		if err != nil {
			_ = level.Error(s.logger).Log("ErrorCreatingChecks", err)
		}
	}()
	return id, nil
}

func (s ScansService) getScanStats(ctx context.Context, checktypesInfo ChecktypesByAssettypes, scan *api.Scan) (scanStats, error) {
	stats := scanStats{
		NumberOfChecksPerChecktype: map[string]int{},
	}
	if scan.TargetGroups == nil {
		// If this field is nil it means this scan is using a versión of the
		// create scan request that does not support metrics any more, just
		// return empty stats.
		return scanStats{}, nil
	}
	for _, group := range *scan.TargetGroups {
		for _, a := range group.TargetGroup.Targets {
			for _, c := range group.ChecktypesGroup.Checktypes {
				validChecksForAsset, ok := checktypesInfo[a.Type]
				if !ok {
					return scanStats{}, fmt.Errorf("invalid assettype %s", a.Type)
				}
				_, ok = validChecksForAsset[c.Name]
				if !ok {
					// If the check is not present in the map for assettype it means
					// the checktype cannot run against this asset.
					continue
				}
				stats.TotalNumberOfChecks = stats.TotalNumberOfChecks + 1
				tag := fmt.Sprint("checktype:", c.Name)
				n := stats.NumberOfChecksPerChecktype[tag]
				stats.NumberOfChecksPerChecktype[tag] = n + 1
			}
		}
	}
	return stats, nil
}

func (s ScansService) checktypesByAssettype(ctx context.Context) (ChecktypesByAssettypes, error) {
	resp, err := s.vulcanCore.IndexAssettypes(ctx, client.IndexAssettypesPath())
	if err != nil {
		return nil, err
	}
	assettypes, err := s.vulcanCore.DecodeAssettypeCollection(resp)
	if err != nil {
		return nil, err
	}
	ret := ChecktypesByAssettypes{}
	for _, a := range assettypes {
		if a.Assettype == nil {
			continue
		}
		if _, ok := ret[*a.Assettype]; !ok {
			ret[*a.Assettype] = map[string]struct{}{}
		}
		for _, c := range a.Name {
			ret[*a.Assettype][c] = struct{}{}
		}
	}
	return ret, nil
}

func (s ScansService) Create(ctx context.Context, scan *api.Scan) (uuid.UUID, error) {
	// Store scan
	now := time.Now()
	scan.StartTime = &now
	id, err := uuid.NewV4()
	if err != nil {
		return uuid.Nil, err
	}
	scan.ID = id
	status := ScanStatusRunning
	scan.Status = &status
	_, err = s.db.CreateScan(id, *scan)
	if err != nil {
		return uuid.Nil, err
	}
	_ = level.Warn(s.logger).Log("ScanCreated", id)
	return id, nil
}

// CreateScan creates a new scan by calling the vulcan-core api and stores
// all the data regarding the scan in the local database.
func (s ScansService) CreateScan(ctx context.Context, scan *api.Scan) (uuid.UUID, error) {
	var (
		checksPayload []*client.CheckPayload
		err           error
	)
	if scan == nil {
		return uuid.Nil, errors.Default("unexpected nil in scan parameter")
	}
	// TODO: Remove this "if". It's here to maintain backward compatibility
	// with the old format of the scan where only one asset group and policy
	// was allowed to be created.
	if scan.TargetGroups != nil {
		checksPayload, err = s.ccreator.CreateScanChecks(ctx, *scan)
	} else {
		checksPayload, err = createScanChecks(*scan)
	}
	if err != nil {
		return uuid.Nil, err
	}
	scanPayload := client.ScanPayload{
		Scan: &client.ScanChecksPayload{
			Checks: checksPayload,
		},
	}
	if len(scanPayload.Scan.Checks) < 1 {
		return uuid.Nil, errors.Validation("at least one target and checktype needed")
	}
	content, err := json.Marshal(&scanPayload)
	if err != nil {
		return uuid.Nil, errors.Default(fmt.Sprintf("can not marshal scan payload: %v", err))
	}

	file, err := ioutil.TempFile("", "scan_")
	if err != nil {
		return uuid.Nil, errors.Default(fmt.Sprintf("can not create temp file: %v", err))
	}
	defer file.Close() //nolint
	if _, err = file.Write(content); err != nil {
		return uuid.Nil, errors.Default(fmt.Sprintf("can not write to file: %v", err))
	}
	defer os.Remove(file.Name()) //nolint

	filePayload := client.FileScanPayload{
		Upload:    file.Name(),
		ProgramID: scan.ExternalID,
		Tag:       scan.Tag,
	}

	resp, err := s.vulcanCore.UploadFileScans(ctx, client.UploadFileScansPath(), &filePayload)
	if err != nil {
		return uuid.Nil, errors.Default(fmt.Sprintf("can not create scan in vulcan core: %v", err))
	}
	defer resp.Body.Close() //nolint

	if resp.StatusCode != http.StatusCreated {
		return uuid.Nil, errors.Default(fmt.Sprintf("can not create scan in vulcan core. Status code: %d", resp.StatusCode))
	}

	scanResponse, err := s.vulcanCore.DecodeScan(resp)
	if err != nil {
		return uuid.Nil, errors.Default(fmt.Sprintf("can not decode scan: %+v", err))
	}
	// Ensure scan data
	if scanResponse.Scan == nil {
		return uuid.Nil, errors.Default("empty scan data received when creating a scan in vulcan-core")
	}
	id, err := uuid.FromString(scanResponse.Scan.ID.String())
	if err != nil {
		return uuid.Nil, errors.Default(fmt.Sprintf("invalid scan ID generated by vulcan core: %v", err))
	}

	ctypesInfo, err := s.checktypesByAssettype(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	stats, err := s.getScanStats(ctx, ctypesInfo, scan)
	if err != nil {
		return uuid.Nil, err
	}

	// Push metrics
	s.pushScanMetrics(metricsScanCreated, ptr2Str(scan.Tag), ptr2Str(scan.ExternalID), stats)

	// Store scan
	scan.ID = id
	now := time.Now()
	scan.StartTime = &now
	counts := len(scanPayload.Scan.Checks)
	scan.CheckCount = &counts
	_, err = s.db.CreateScan(id, *scan)
	if err != nil {
		return uuid.Nil, err
	}
	_ = level.Warn(s.logger).Log("ScanCreated", scanResponse.Scan.ID.String())
	_, _, err = s.updateScanStatus(id)
	if err != nil {
		return uuid.Nil, err
	}
	return id, nil
}

// ProcessScanCheckNotification process and update the checks. The func will
// return nil if the event must be marked as consumed by the caller.
func (s ScansService) ProcessScanCheckNotification(ctx context.Context, msg []byte) error {
	_ = level.Debug(s.logger).Log("ProcessingMessage", string(msg))
	c := api.Check{}
	err := json.Unmarshal(msg, &c)
	if err != nil {
		_ = level.Error(s.logger).Log(err)
		return nil
	}
	err = validator.New().Struct(c)
	if err != nil {
		_ = level.Error(s.logger).Log("ErrorValidatingCheckUpdateEvent", err)
		return nil
	}

	scanID, err := uuid.FromString(c.ScanID)
	if err != nil {
		_ = level.Error(s.logger).Log("NotValidScanID", err)
		return nil
	}
	c.ScanID = scanID.String()
	id, err := uuid.FromString(c.ID)
	if err != nil {
		_ = level.Error(s.logger).Log("NotValidScanID", err)
		return nil
	}

	progress := ptr2Float(c.Progress)
	// Don't take into account inconsistent progress in a message with a
	// terminal status.
	if checkStates.IsTerminal(c.Status) && (progress != 1.0) {
		_ = level.Error(s.logger).Log("FixingInvalidProgressInTerminalStatus", progress, "Status", c.Status)
		progress = 1
		c.Progress = &progress
	}

	// The progress could still be incorrect if the check is not in a terminal
	// status. In that case we want to discard the message because we can not
	// deduce the progress from the status.
	if progress > 1.0 || progress < 0.0 {
		_ = level.Error(s.logger).Log("NotValidProgress", c.Progress)
		return nil
	}

	updateStates, err := checkStates.LessOrEqual(c.Status)
	if err != nil {
		// State not valid, log the error but mark the event as processed.
		_ = level.Error(s.logger).Log(err, c.Status)
		return nil
	}
	c.Data = msg
	count, err := s.db.UpsertCheck(scanID, id, c, updateStates)
	if err != nil {
		return err
	}

	// If the upsert didn't affect any check we have to try to update the status.
	if count == 0 {
		_ = level.Info(s.logger).Log("NoEffectProcessingCheckUpdate", string(msg))
	}
	count, scanState, err := s.updateScanStatus(scanID)
	if err != nil {
		return err
	}

	if count > 0 {
		_ = level.Info(s.logger).Log("ScanStatusUpdated", string(msg))
		_ = level.Debug(s.logger).Log("ScanStatusSet", scanID.String()+";"+scanState)
	}

	// If the scan was finished we ensure we delete the checks.
	if scanState == ScanStatusFinished {
		err = s.db.DeleteScanChecks(scanID)
		if err != nil {
			return err
		}
	}

	// If the current scans is finished and this check state update was the one
	// that caused it to be in that state the we notify the scan is finished.
	if count > 0 && scanState == ScanStatusFinished {
		err = s.notifyCurrentScanInfo(scanID)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s ScansService) notifyCurrentScanInfo(scanID uuid.UUID) error {
	scan, err := s.GetScan(context.Background(), scanID.String())
	if err != nil {
		return err
	}

	s.pushScanMetrics(metricsScanFinished, ptr2Str(scan.Tag), ptr2Str(scan.ExternalID), scanStats{})

	m := api.ScanNotification{
		ScanID:        scan.ID.String(),
		ProgramID:     ptr2Str(scan.ExternalID),
		Status:        ptr2Str(scan.Status),
		Tag:           ptr2Str(scan.Tag),
		Trigger:       ptr2Str(scan.Trigger),
		ScheduledTime: ptr2Time(scan.ScheduledTime),
		StartTime:     ptr2Time(scan.StartTime),
		EndTime:       ptr2Time(scan.EndTime),
		CheckCount:    ptr2Int(scan.CheckCount),
	}
	return s.notifier.Notify(m)
}

func (s ScansService) updateScanStatus(id uuid.UUID) (int64, string, error) {
	scan, err := s.db.GetScanByID(id)
	if errors.IsKind(err, errors.ErrNotFound) {
		// We don't have any information regarding this scan, either because we
		// received a check update before a CreateScan finished or the scan that
		// the check belongs to was not created using the scan engine. In any
		// case we try to create an entry in the scans table with basic data.
		count, errInit := s.initScanStatus(id)
		return count, "", errInit
	}

	if err != nil {
		return 0, "", err
	}

	// TODO: Remove this branch when the scan engine removes support for creating
	// the checks synchronously because there won't be any scan without
	// CheckCount
	if scan.CheckCount == nil {
		// We don't know (hopefully yet) the number of the checks that compose
		// the scan so we will just try to update the status of the scan to
		// RUNNING.
		status := ScanStatusRunning
		_ = level.Warn(s.logger).Log("UnableToCalculateScanProgress", id.String())
		count, err := s.db.UpdateScan(id, api.Scan{ID: id, Status: &status}, []string{ScanStatusRunning})
		return count, ScanStatusRunning, err
	}

	if *scan.CheckCount < 1 {
		_ = level.Error(s.logger).Log(ErrAtLeastOneTargetAndChecktype)
		return 0, "", ErrAtLeastOneTargetAndChecktype
	}

	n := *scan.CheckCount

	if scan.Status != nil && *scan.Status == ScanStatusFinished {
		return 0, ScanStatusFinished, nil
	}

	stats, err := s.db.GetChecksStatusStats(scan.ID)
	if err != nil {
		return 0, "", nil
	}
	update := statusFromChecks(id, stats, float32(n), s.logger)
	count, err := s.db.UpdateScan(id, update, []string{ScanStatusRunning})

	// Push scan progress metrics
	s.metricsClient.Push(metrics.Metric{
		Name:  scanCompletionMetric,
		Typ:   metrics.Histogram,
		Value: float64(ptr2Float(update.Progress)),
		Tags:  []string{componentTag, buildScanTag(ptr2Str(scan.Tag), ptr2Str(scan.ExternalID))},
	})

	return count, *update.Status, err
}

func (s ScansService) initScanStatus(id uuid.UUID) (int64, error) {
	status := ScanStatusRunning
	var progress float32
	now := time.Now()
	scanUpdate := api.Scan{
		Status:    &status,
		Progress:  &progress,
		StartTime: &now,
		ID:        id,
	}
	return s.db.UpdateScan(id, scanUpdate, []string{ScanStatusRunning})
}

// pushScanMetrics pushes metrics related to the scan status and its checks if applicable.
func (s ScansService) pushScanMetrics(scanStatus, teamTag, programID string, stats scanStats) {
	scanTag := buildScanTag(teamTag, programID)
	scanStatusTag := fmt.Sprint("scanstatus:", scanStatus)
	checkStatusTag := "checkstatus:requested"

	s.metricsClient.Push(metrics.Metric{
		Name:  scanCountMetric,
		Typ:   metrics.Count,
		Value: 1,
		Tags:  []string{componentTag, scanTag, scanStatusTag},
	})

	for checkTypeTag, count := range stats.NumberOfChecksPerChecktype {
		s.metricsClient.Push(metrics.Metric{
			Name:  "vulcan.scan.check.count",
			Typ:   metrics.Count,
			Value: float64(count),
			Tags:  []string{componentTag, scanTag, checkStatusTag, checkTypeTag},
		})
	}
}

func buildScanTag(teamTag string, programID string) string {
	var teamLabel, programLabel string

	if teamTag == "" {
		teamLabel = "unknown"
	} else {
		teamTagParts := strings.Split(teamTag, ":")
		teamLabel = teamTagParts[len(teamTagParts)-1]
	}

	if programID == "" {
		programLabel = "unknown"
	} else {
		programLabel = programID
		// Check for global program
		if strings.Contains(programID, "@") {
			programLabel = strings.Split(programID, "@")[1]
		}
	}

	return fmt.Sprint("scan:", teamLabel, "-", programLabel)
}

func statusFromChecks(scanID uuid.UUID, checkStats map[string]int, n float32, l log.Logger) api.Scan {
	var finished float32
	anyAborted := false
	level.Debug(l).Log("ScanStats", fmt.Sprintf("%+v", checkStats))
	for status, count := range checkStats {
		if status == "" || count == 0 {
			continue
		}
		if checkStates.IsTerminal(status) {
			finished = finished + float32(count)
			if status == "ABORTED" {
				anyAborted = true
			}
		}
	}
	var p float32
	var status string
	var endTime *time.Time
	if finished == n {
		p = 1.0
		if anyAborted {
			status = ScanStatusAborted
		} else {
			status = ScanStatusFinished
		}
		now := time.Now()
		endTime = &now
	} else {
		p = finished / n
		status = ScanStatusRunning
	}
	return api.Scan{
		ID:       scanID,
		Progress: &p,
		Status:   &status,
		EndTime:  endTime,
	}
}

func createScanChecks(scan api.Scan) ([]*client.CheckPayload, error) {
	checks := []*client.CheckPayload{}
	targetGroupOpts := map[string]interface{}{}
	targetsGroup := scan.Targets
	typesGroup := scan.ChecktypesGroup
	if targetsGroup.Options != "" {
		err := json.Unmarshal([]byte(targetsGroup.Options), &targetGroupOpts)
		if err != nil {
			return []*client.CheckPayload{}, errors.Assertion(err)
		}
	}
	for _, t := range targetsGroup.Targets {
		targetOpts := map[string]interface{}{}
		if t.Options != "" {
			err := json.Unmarshal([]byte(t.Options), &targetOpts)
			if err != nil {
				return []*client.CheckPayload{}, errors.Assertion(err)
			}
		}
		targetOpts = mergeOptions(targetGroupOpts, targetOpts)
		for _, ct := range typesGroup.Checktypes {
			ct := ct // This fixes the gotcha of reusing the structure.
			data := client.CheckData{
				ChecktypeName: &ct.Name, // Related with the gotcha mentioned above.
				Target:        t.Identifier,
			}
			checkOpts := map[string]interface{}{}
			if ct.Options != "" {
				err := json.Unmarshal([]byte(ct.Options), &checkOpts)
				if err != nil {
					return []*client.CheckPayload{}, errors.Assertion(err)
				}
			}
			checkOpts = mergeOptions(targetOpts, checkOpts)
			if len(checkOpts) > 0 {
				opts, err := json.Marshal(checkOpts)
				if err != nil {
					return []*client.CheckPayload{}, errors.Default(err)
				}
				strOpts := string(opts)
				data.Options = &strOpts
			}
			data.Tag = scan.Tag
			payload := client.CheckPayload{
				Check: &data,
			}
			checks = append(checks, &payload)
		}

	}
	return checks, nil
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

func ptr2Str(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// ptr2Float returns the value passed in if it isn't nil.
// Returns 0 otherwise.
func ptr2Float(val *float32) float32 {
	if val == nil {
		return 0
	}
	return *val
}

func ptr2Time(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return *t
}

func ptr2Int(i *int) int {
	if i == nil {
		return 0
	}
	return *i
}
