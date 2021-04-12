/*
Copyright 2021 Adevinta
*/

package service

import (
	"context"
	"encoding/json"
	errs "errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"

	uuid "github.com/satori/go.uuid"
	validator "gopkg.in/go-playground/validator.v9"

	"github.com/adevinta/errors"

	"github.com/adevinta/vulcan-core-cli/vulcan-core/client"
	metrics "github.com/adevinta/vulcan-metrics-client"
	"github.com/adevinta/vulcan-scan-engine/pkg/api"
	"github.com/adevinta/vulcan-scan-engine/pkg/api/persistence"
	"github.com/adevinta/vulcan-scan-engine/pkg/notify"
	"github.com/adevinta/vulcan-scan-engine/pkg/stream"
	"github.com/adevinta/vulcan-scan-engine/pkg/util"
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
	checkCountMetric     = "vulcan.scan.check.count"
	metricsScanCreated   = "created"
	metricsScanFinished  = "finished"
)

// ChecktypesInformer represents an informer for the mapping
// between checktypes and supported asset types.
type ChecktypesInformer interface {
	IndexAssettypes(ctx context.Context, path string) (*http.Response, error)
	DecodeAssettypeCollection(resp *http.Response) (client.AssettypeCollection, error)
}

// ChecksCreator abstracts the actual implementation
// for the checks creation process.
type ChecksCreator interface {
	CreateScanChecks(id string) error
}

type scanStats struct {
	TotalNumberOfChecks        int
	NumberOfChecksPerChecktype map[string]int
}

// ChecktypesByAssettypes is used as a lookup table to check if a checktype can
// be run against a concrete assettype.
type ChecktypesByAssettypes map[string]map[string]struct{}

// ScansService implements the functionality needed to create and query scans.
type ScansService struct {
	db             persistence.ScansStore
	logger         log.Logger
	ctInformer     ChecktypesInformer
	metricsClient  metrics.Client
	ccreator       ChecksCreator
	scansNotifier  notify.Notifier
	checksNotifier notify.Notifier
	streamClient   stream.Client
}

// New Creates and returns ScansService with all the dependencies wired in.
func New(logger log.Logger, db persistence.ScansStore, client ChecktypesInformer,
	metricsClient metrics.Client, ccreator ChecksCreator, scansNotifier notify.Notifier,
	checksNotifier notify.Notifier, streamClient stream.Client) ScansService {
	return ScansService{
		db:             db,
		logger:         logger,
		ctInformer:     client,
		ccreator:       ccreator,
		metricsClient:  metricsClient,
		scansNotifier:  scansNotifier,
		checksNotifier: checksNotifier,
		streamClient:   streamClient,
	}

}

// ListScans returns the list of scans.
func (s ScansService) ListScans(ctx context.Context, extID string, offset, limit uint32) ([]api.Scan, error) {
	var err error
	scans := []api.Scan{}
	if extID == "" {
		scans, err = s.db.GetScans(offset, limit)
	} else {
		scans, err = s.db.GetScansByExternalID(extID, offset, limit)
	}
	return scans, err
}

// GetScan returns the scan corresponding with a given id.
func (s ScansService) GetScan(ctx context.Context, scanID string) (api.Scan, error) {
	id, err := uuid.FromString(scanID)
	if err != nil {
		return api.Scan{}, errors.Assertion(fmt.Sprintf("not valid scan ID %s", scanID))
	}
	scan, err := s.db.GetScanByID(id)
	if err != nil {
		return api.Scan{}, err
	}
	return scan, nil
}

// GetScanChecks returns the checks for the scan with the given id.
func (s ScansService) GetScanChecks(ctx context.Context, scanID, status string) ([]api.Check, error) {
	id, err := uuid.FromString(scanID)
	if err != nil {
		return []api.Check{}, errors.Assertion(fmt.Sprintf("not valid scan ID %s", scanID))
	}
	checks := []api.Check{}
	if status == "" {
		checks, err = s.db.GetScanChecks(id)
	} else {
		checks, err = s.db.GetScanChecksByStatus(id, status)
	}
	return checks, err
}

// GetScanStats returns the check stats for the given scan ID.
func (s ScansService) GetScanStats(ctx context.Context, scanID string) ([]api.CheckStats, error) {
	id, err := uuid.FromString(scanID)
	if err != nil {
		return nil, errors.Assertion(fmt.Sprintf("not valid scan ID %s", scanID))
	}
	stats, err := s.db.GetScanStats(id)
	if err != nil {
		return nil, err
	}
	var checkStats []api.CheckStats
	for status, total := range stats {
		if total > 0 {
			checkStats = append(checkStats, api.CheckStats{
				Status: status,
				Total:  total,
			})
		}
	}
	return checkStats, nil
}

// GetCheck returns the check for the given check ID.
func (s ScansService) GetCheck(ctx context.Context, checkID string) (api.Check, error) {
	id, err := uuid.FromString(checkID)
	if err != nil {
		return api.Check{}, errors.Assertion(fmt.Sprintf("not valid check ID %s", checkID))
	}
	return s.db.GetCheckByID(id)
}

// AbortScan is called in order to signal the vulcan core to try to abort and on going scan.
func (s ScansService) AbortScan(ctx context.Context, scanID string) error {
	id, err := uuid.FromString(scanID)
	if err != nil {
		return errors.Assertion(fmt.Sprintf("not valid scan ID %s", scanID))
	}
	scan, err := s.db.GetScanByID(id)
	if err != nil {
		return err
	}

	if scan.Status != nil && (*scan.Status == ScanStatusAborted ||
		*scan.Status == ScanStatusFinished) {
		errMssg := fmt.Sprintf("scan is in terminal status %s", *scan.Status)
		return &errors.Error{
			Kind:           errs.New("conflict"),
			Message:        errMssg,
			HTTPStatusCode: http.StatusConflict,
		}
	}

	checks, err := s.db.GetScanChecks(id)
	if err != nil {
		return err
	}
	var checkIDs []string
	for _, c := range checks {
		checkIDs = append(checkIDs, c.ID)
	}
	return s.streamClient.AbortChecks(ctx, checkIDs)
}

func (s ScansService) CreateScan(ctx context.Context, scan *api.Scan) (uuid.UUID, error) {
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
	s.pushScanMetrics(metricsScanCreated, util.Ptr2Str(scan.Tag), util.Ptr2Str(scan.ExternalID), stats)
	_ = level.Warn(s.logger).Log("ScanCreated", id)
	go func() {
		err := s.ccreator.CreateScanChecks(id.String())
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
	resp, err := s.ctInformer.IndexAssettypes(ctx, client.IndexAssettypesPath())
	if err != nil {
		return nil, err
	}
	assettypes, err := s.ctInformer.DecodeAssettypeCollection(resp)
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

// ProcessScanCheckNotification process and update the checks. The func will
// return nil if the event must be marked as consumed by the caller.
func (s ScansService) ProcessScanCheckNotification(ctx context.Context, msg []byte) error {
	_ = level.Debug(s.logger).Log("ProcessingMessage", string(msg))

	// Parse check mssg
	checkMssg := api.Check{}
	err := json.Unmarshal(msg, &checkMssg)
	if err != nil {
		_ = level.Error(s.logger).Log(err)
		return nil
	}
	err = validator.New().Struct(checkMssg)
	if err != nil {
		_ = level.Error(s.logger).Log("ErrorValidatingCheckUpdateEvent", err)
		return nil
	}
	checkMssg.Data = msg
	checkProgress := util.Ptr2Float(checkMssg.Progress)

	// Retrieve DB check
	checkID, err := uuid.FromString(checkMssg.ID)
	if err != nil {
		_ = level.Error(s.logger).Log("NotValidCheckID", err)
	}
	dbCheck, err := s.db.GetCheckByID(checkID)
	if err != nil {
		_ = level.Error(s.logger).Log("CheckForMsgDoesNotExist", err)
		return nil
	}
	scanID, err := uuid.FromString(dbCheck.ScanID)
	if err != nil {
		_ = level.Error(s.logger).Log("NotValidScanID", err)
		return nil
	}

	// Don't take into account inconsistent progress in a message with a terminal status.
	if api.CheckStates.IsTerminal(checkMssg.Status) && (checkProgress != 1.0) {
		_ = level.Error(s.logger).Log("FixingInvalidProgressInTerminalStatus", checkProgress, "Status", checkMssg.Status)
		checkProgress = 1
		checkMssg.Progress = &checkProgress
	}

	// The progress could still be incorrect if the check is not in a terminal status.
	// In that case we want to discard the message because we can not deduce the progress
	// from the status.
	if checkProgress > 1.0 || checkProgress < 0.0 {
		_ = level.Error(s.logger).Log("NotValidProgress", checkMssg.Progress)
		return nil
	}

	// Only update scan and checks data if there is an status change.
	// Intermediate check messages data (e.g.: progress reporting) are not persisted.
	// We have to take into account the particular check message sent by the agent for
	// report and raw data which does not state an explicit status.
	if checkMssg.Status == "" || api.CheckStates.IsHigher(checkMssg.Status, dbCheck.Status) {
		checkCount, err := s.db.UpsertCheck(scanID, checkID, checkMssg, api.CheckStates.LessOrEqual(checkMssg.Status))
		if err != nil {
			return err
		}
		if checkCount == 0 {
			_ = level.Info(s.logger).Log("NoEffectProcessingCheckUpdate", string(msg))
		}

		scanCount, scan, err := s.updateScanStatus(scanID)
		if err != nil {
			return err
		}
		if scanCount > 0 {
			_ = level.Info(s.logger).Log("ScanStatusUpdated", string(msg))
			_ = level.Debug(s.logger).Log("ScanStatusSet", scanID.String()+";"+util.Ptr2Str(scan.Status))
		}

		check := mergeChecks(dbCheck, checkMssg)

		// If check message implies a status change from the
		// one stored in DB, propagate it and push metrics.
		if checkMssg.Status != "" && checkCount > 0 {
			err = s.notifyCheck(check, util.Ptr2Str(scan.ExternalID))
			if err != nil {
				return err
			}
		}

		// If the current scans is finished and this check state update was the one
		// that caused it to be in that state then we notify the scan is finished.
		if scanCount > 0 && *scan.Status == ScanStatusFinished {
			err = s.notifyScan(scanID)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (s ScansService) notifyScan(scanID uuid.UUID) error {
	scan, err := s.GetScan(context.Background(), scanID.String())
	if err != nil {
		return err
	}

	s.pushScanMetrics(metricsScanFinished, util.Ptr2Str(scan.Tag), util.Ptr2Str(scan.ExternalID), scanStats{})

	return s.scansNotifier.Push(scan.ToScanNotification(), nil)
}

func (s ScansService) notifyCheck(check api.Check, programID string) error {
	s.pushCheckMetrics(check, programID)

	ctname := "unknown"
	if check.ChecktypeName != nil {
		ctname = *check.ChecktypeName
	}
	attributes := map[string]string{
		"checktype_name": ctname,
		"status":         check.Status,
	}
	return s.checksNotifier.Push(check.ToCheckNotification(), attributes)
}

func (s ScansService) updateScanStatus(id uuid.UUID) (int64, api.Scan, error) {
	scan, err := s.db.GetScanByID(id)
	if errors.IsKind(err, errors.ErrNotFound) {
		// We don't have any information regarding this scan, either because we
		// received a check update before a CreateScan finished or the scan that
		// the check belongs to was not created using the scan engine. In any
		// case we try to create an entry in the scans table with basic data.
		count, errInit := s.initScanStatus(id)
		return count, api.Scan{}, errInit
	}

	if err != nil {
		return 0, api.Scan{}, err
	}

	// TODO: Remove this branch when the scan engine removes support for creating
	// the checks synchronously because there won't be any scan without
	// CheckCount
	if scan.CheckCount == nil {
		// We don't know (hopefully yet) the number of the checks that compose
		// the scan so we will just try to update the status of the scan to
		// RUNNING.
		statusRunning := ScanStatusRunning
		scan.Status = &statusRunning
		_ = level.Warn(s.logger).Log("UnableToCalculateScanProgress", id.String())
		count, err := s.db.UpdateScan(id, api.Scan{ID: id, Status: scan.Status}, []string{ScanStatusRunning})
		return count, scan, err
	}

	if *scan.CheckCount < 1 {
		_ = level.Error(s.logger).Log(ErrAtLeastOneTargetAndChecktype)
		return 0, api.Scan{}, ErrAtLeastOneTargetAndChecktype
	}

	n := *scan.CheckCount

	if scan.Status != nil && util.Ptr2Str(scan.Status) == ScanStatusFinished {
		return 0, scan, nil
	}

	stats, err := s.db.GetScanStats(scan.ID)
	if err != nil {
		return 0, api.Scan{}, err
	}
	update := statusFromChecks(scan, stats, float32(n), s.logger)
	count, err := s.db.UpdateScan(id, update, []string{ScanStatusRunning})

	// Push scan progress metrics
	s.metricsClient.Push(metrics.Metric{
		Name:  scanCompletionMetric,
		Typ:   metrics.Histogram,
		Value: float64(util.Ptr2Float(update.Progress)),
		Tags:  []string{componentTag, buildScanTag(util.Ptr2Str(scan.Tag), util.Ptr2Str(scan.ExternalID))},
	})

	return count, update, err
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
			Name:  checkCountMetric,
			Typ:   metrics.Count,
			Value: float64(count),
			Tags:  []string{componentTag, scanTag, checkStatusTag, checkTypeTag},
		})
	}
}

// pushCheckMetrics pushes metrics related to the check status.
func (s ScansService) pushCheckMetrics(check api.Check, programID string) {
	scanTag := buildScanTag(util.Ptr2Str(check.Tag), programID)
	checkStatusTag := fmt.Sprint("checkstatus:", check.Status)
	checktypeTag := fmt.Sprint("checktype:", util.Ptr2Str(check.ChecktypeName))

	s.metricsClient.Push(metrics.Metric{
		Name:  checkCountMetric,
		Typ:   metrics.Count,
		Value: 1,
		Tags:  []string{componentTag, scanTag, checkStatusTag, checktypeTag},
	})
}

// buildScanTag builds the metrics scan tag.
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

func statusFromChecks(scan api.Scan, checkStats map[string]int, n float32, l log.Logger) api.Scan {
	var finished float32
	anyAborted := false
	level.Debug(l).Log("ScanStats", fmt.Sprintf("%+v", checkStats))
	for status, count := range checkStats {
		if status == "" || count == 0 {
			continue
		}
		if api.CheckStates.IsTerminal(status) {
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
	scan.Progress = &p
	scan.Status = &status
	scan.EndTime = endTime
	return scan
}

func mergeChecks(old api.Check, new api.Check) api.Check {
	c := old
	if new.Status != "" {
		c.Status = new.Status
	}
	if util.Ptr2Float(new.Progress) != 0 {
		c.Progress = new.Progress
	}
	if util.Ptr2Str(new.Report) != "" {
		c.Report = new.Report
	}
	if util.Ptr2Str(new.Raw) != "" {
		c.Raw = new.Raw
	}
	return c
}
