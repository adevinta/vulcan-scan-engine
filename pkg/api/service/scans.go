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

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"

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

	// Scan metrics.
	componentTag         = "component:scanengine"
	scanCountMetric      = "vulcan.scan.count"
	scanCompletionMetric = "vulcan.scan.completion"
	checkCountMetric     = "vulcan.scan.check.count"
	metricsScanCreated   = "created"
	metricsScanFinished  = "finished"

	// LogFields
	notValidProgressField = "InvalidProgress"
	fixingProgressField   = "FixingInvalidProgress"
)

// ChecktypesInformer represents an informer for the mapping
// between checktypes and supported asset types.
type ChecktypesInformer interface {
	GetAssettypes() (*client.AssettypeCollection, error)
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
	if extID == "" {
		return s.db.GetScans(offset, limit)
	}
	return s.db.GetScansByExternalID(extID, offset, limit)
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
	if status == "" {
		return s.db.GetScanChecks(id)
	}
	return s.db.GetScanChecksByStatus(id, status)
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

	if scan.Status != nil && (*scan.Status == ScanStatusFinished) {
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
	scan.ChecktypesInfo = &ctypesInfo
	stats, err := s.getScanStats(ctx, ctypesInfo, scan)
	if err != nil {
		return uuid.Nil, err
	}
	scan.CheckCount = &stats.TotalNumberOfChecks
	zero := 0
	scan.ChecksCreated = &zero
	scan.ChecksFinished = &zero
	var floatZero float32 = 0.0
	scan.Progress = &floatZero
	_, err = s.db.CreateScan(id, *scan)
	if err != nil {
		return uuid.Nil, err
	}

	// Push metrics.
	s.pushScanMetrics(metricsScanCreated, util.Ptr2Str(scan.Tag), util.Ptr2Str(scan.ExternalID), stats)
	time2Create := time.Since(*scan.StartTime)
	externalID := ""
	if scan.ExternalID != nil {
		externalID = *scan.ExternalID
	}
	tag := ""
	if scan.Tag != nil {
		tag = *scan.Tag
	}
	_ = level.Info(s.logger).Log("ScanCreated", id, "CreationTime", time2Create.String(), "CheckCount", scan.CheckCount,
		"ExternalID", externalID, "Tag", tag)
	return id, nil
}

func (s ScansService) getScanStats(ctx context.Context, checktypesInfo api.ChecktypesByAssettypes, scan *api.Scan) (scanStats, error) {
	stats := scanStats{
		NumberOfChecksPerChecktype: map[string]int{},
	}
	if scan.TargetGroups == nil {
		// If this field is nil it means this scan is using a version of the
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

func (s ScansService) checktypesByAssettype(ctx context.Context) (api.ChecktypesByAssettypes, error) {
	assettypes, err := s.ctInformer.GetAssettypes()
	if err != nil {
		return nil, err
	}
	ret := api.ChecktypesByAssettypes{}
	for _, a := range *assettypes {
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

	// Parse check message.
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

	checkID, err := uuid.FromString(checkMssg.ID)
	if err != nil {
		_ = level.Error(s.logger).Log("NotValidCheckID", err)
		return nil
	}

	// If the progress is incorrect and the status of the check is terminal we
	// rapair it. If it's incorrect but the status is not terminal we just
	// ignore the message.
	if checkProgress > 1.0 || checkProgress < 0.0 {
		if !api.CheckStates.IsTerminal(checkMssg.Status) {
			_ = level.Error(s.logger).Log(notValidProgressField, checkMssg.Progress, "Status", checkMssg.Status, "CheckID", checkMssg.ID)
			return nil
		}
		_ = level.Error(s.logger).Log(fixingProgressField, checkProgress, "Status", checkMssg.Status, "CheckID", checkMssg.ID)
		checkProgress = 1
		checkMssg.Progress = &checkProgress
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

	_, err = s.db.UpsertCheck(scanID, checkID, checkMssg, api.CheckStates.LessOrEqual(checkMssg.Status))
	if err != nil {
		return err
	}
	// If the message does not have any status specified is because it is only
	// for comunicating other info like the url of the logs, so we don't need to
	// take it into account for sending metrics or publising a status change.
	if checkMssg.Status == "" {
		return nil
	}
	// As a check message does not contain all the information
	// of a check we must merge with the the info of the check in the DB.
	check := mergeChecks(dbCheck, checkMssg)
	if err != nil {
		return err
	}
	s.pushCheckMetrics(check)
	err = s.notifyCheck(check)
	if err != nil {
		return err
	}

	// If the status of the check is not terminal it will not affect the status
	// of the scan, so we are done.
	if !api.CheckStates.IsTerminal(checkMssg.Status) {
		return nil
	}

	// Count the check as finished in its scan. Note that this operation is
	// idempotent, that means: even if called multiple times, for a given check
	// it will only increase by one the number of checks finished in the scan.
	_, err = s.db.AddCheckAsFinished(checkID)
	if err != nil {
		return err
	}
	scanCount, status, err := s.updateScanStatus(scanID)
	if err != nil {
		return err
	}
	if scanCount > 0 {
		_ = level.Info(s.logger).Log("ScanStatusUpdated", string(msg))
		_ = level.Debug(s.logger).Log("ScanStatusSet", scanID.String()+";"+status)
	}
	if status == ScanStatusFinished {
		err = s.notifyScan(scanID)
		if err != nil {
			return err
		}
		n, err := s.db.DeleteScanChecks(scanID)
		_ = level.Info(s.logger).Log("DeleteFinishedChecks", scanID, "Count", n)
		return err
	}
	return err
}

func (s ScansService) notifyScan(scanID uuid.UUID) error {
	scan, err := s.GetScan(context.Background(), scanID.String())
	if err != nil {
		return err
	}

	s.pushScanMetrics(metricsScanFinished, util.Ptr2Str(scan.Tag), util.Ptr2Str(scan.ExternalID), scanStats{})

	return s.scansNotifier.Push(scan.ToScanNotification(), nil)
}

func (s ScansService) notifyCheck(check api.Check) error {
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

func (s ScansService) updateScanStatus(id uuid.UUID) (int64, string, error) {
	scan, err := s.db.GetScanStatus(id)
	if errors.IsKind(err, errors.ErrNotFound) {
		return 0, "", err
	}
	if err != nil {
		return 0, "", err
	}

	if scan.Status == nil {
		err := fmt.Errorf("scan with id %s does not have mandatory field status", id.String())
		return 0, "", err
	}

	if util.Ptr2Str(scan.Status) == ScanStatusFinished {
		return 0, ScanStatusFinished, nil
	}

	if scan.CheckCount == nil {
		err := fmt.Errorf("scan with id %s does not have mandatory field CheckCount", id.String())
		return 0, "", err
	}

	if *scan.CheckCount < 1 {
		_ = level.Error(s.logger).Log(ErrAtLeastOneTargetAndChecktype)
		return 0, "", ErrAtLeastOneTargetAndChecktype
	}

	if scan.ChecksFinished == nil {
		err := fmt.Errorf("scan with id %s does not have mandatory field ChecksFinished", id.String())
		return 0, "", err
	}
	status := *scan.Status
	count := *scan.CheckCount
	finished := *scan.ChecksFinished
	progress := float32(finished) / float32(count)
	update := api.Scan{}
	update.ID = id
	update.Progress = &progress
	if (status == ScanStatusRunning) && (count == finished) {
		status = ScanStatusFinished
		update.Status = &status
		now := time.Now()
		update.EndTime = &now
	}
	n, err := s.db.UpdateScan(id, update, []string{ScanStatusRunning})
	tag := buildScanTag(util.Ptr2Str(scan.Tag), util.Ptr2Str(scan.ExternalID))
	// Push scan progress metrics.
	s.metricsClient.Push(metrics.Metric{
		Name:  scanCompletionMetric,
		Typ:   metrics.Histogram,
		Value: float64(util.Ptr2Float(update.Progress)),
		Tags:  []string{componentTag, tag},
	})

	return n, status, err
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
func (s ScansService) pushCheckMetrics(check api.Check) {
	var program, team string
	if check.Metadata != nil {
		metadata := *check.Metadata
		program = metadata["program"]
		team = metadata["team"]
	}
	scanTag := buildScanTag(team, program)
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
		teamLabel = teamTag
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
