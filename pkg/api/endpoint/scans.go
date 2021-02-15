/*
Copyright 2021 Adevinta
*/

package endpoint

import (
	"context"
	"fmt"
	"time"

	"github.com/go-kit/kit/endpoint"
	uuid "github.com/satori/go.uuid"

	"github.com/adevinta/errors"
	"github.com/adevinta/vulcan-scan-engine/pkg/api"
	"github.com/adevinta/vulcan-scan-engine/pkg/util"
)

// ScanCreator defines the service interface required by the endpoint CreateScan
type ScanCreator interface {
	CreateScan(context.Context, *api.Scan) (uuid.UUID, error)
}

// ScanGetter defines the service interface required by the endpoint GetScan
type ScanGetter interface {
	ListScans(ctx context.Context) ([]api.Scan, error)
	GetScan(ctx context.Context, scanID string) (api.Scan, error)
	GetScanChecks(ctx context.Context, scanID string) ([]api.Check, error)
	GetScansByExternalID(ctx context.Context, ID string, all bool) ([]api.Scan, error)
	AbortScan(ctx context.Context, scanID string) error
}

// ScanRequest defines the request accepted by CreateScan endpoint.
type ScanRequest struct {
	ID            string     `json:"id" urlvar:"id"`
	ExternalID    string     `json:"external_id" urlquery:"external_id"`
	All           string     `urlquery:"all"`
	ScheduledTime *time.Time `json:"scheduled_time"`
	// TODO: Remove TargetGroup and ChecktypeGroup when we deprecate the version 1
	// of the endpoint for creating scans.
	TargetGroup     api.TargetGroup              `json:"target_group"`
	ChecktypesGroup api.ChecktypesGroup          `json:"check_types_groups"`
	TargetGroups    []api.TargetsChecktypesGroup `json:"target_groups"`
	Trigger         string                       `json:"trigger"`
	Tag             string                       `json:"tag,omitempty"`
}

// ScanResponse represents the response
// for a scan creation request.
type ScanResponse struct {
	ScanID string `json:"scan_id"`
}

// GetScansResponse represents the response
// for a list scans request.
type GetScansResponse struct {
	Scans []GetScanResponse `json:"scans"`
}

// GetScanResponse represents the response
// for a get scan request.
type GetScanResponse struct {
	ID            string     `json:"id"`
	ExternalID    string     `json:"external_id"`
	Status        string     `json:"status"`
	Trigger       string     `json:"trigger"`
	ScheduledTime *time.Time `json:"scheduled_time"`
	StartTime     *time.Time `json:"start_time"`
	EndTime       *time.Time `json:"end_time"`
	Progress      *float32   `json:"progress"`
	CheckCount    *int       `json:"check_count"`
	ChecksCreated *int       `json:"checks_created"`
	AbortedAt     *time.Time `json:"aborted_at,omitempty"`
}

// GetCheckResponse represents the response
// for a get check request.
type GetCheckResponse struct {
	ID            string `json:"id"`
	Status        string `json:"status"`
	Target        string `json:"target"`
	ChecktypeName string `json:"checktype_name,omitempty"`
	Image         string `json:"image,omitempty"`
	Options       string `json:"options,omitempty"`
	Report        string `json:"report,omitempty"`
	Raw           string `json:"raw,omitempty"`
	Tag           string `json:"tag,omitempty"`
	Assettype     string `json:"assettype,omitempty"`
}

// GetChecksResponse represents the response
// for a get scan checks request.
type GetChecksResponse struct {
	Checks []GetCheckResponse `json:"checks"`
}

func makeCreateScanEndpoint(s ScanCreator) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		requestBody, ok := request.(*ScanRequest)
		if !ok {
			return nil, errors.Assertion("Type assertion failed")
		}
		scan := &api.Scan{
			ExternalID:    &requestBody.ExternalID,
			Trigger:       &requestBody.Trigger,
			Tag:           &requestBody.Tag,
			ScheduledTime: requestBody.ScheduledTime,
		}

		scan.TargetGroups = &requestBody.TargetGroups

		// Creates the scan
		id, err := s.CreateScan(ctx, scan)
		if err != nil {
			return nil, err
		}
		scanResponse := ScanResponse{id.String()}
		return Created{scanResponse}, nil
	}
}

func makeListScansEndpoint(s ScanGetter) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req, ok := request.(*ScanRequest)
		if !ok {
			return nil, errors.Assertion("Type assertion failed")
		}
		all := req.All == "true"

		var scans []api.Scan
		if req.ExternalID == "" {
			scans, err = s.ListScans(ctx)
		} else {
			scans, err = s.GetScansByExternalID(ctx, req.ExternalID, all)
		}
		if err != nil {
			return nil, err
		}

		resp, err := buildGetScansResponse(scans)
		if err != nil {
			return nil, err
		}
		return Ok{resp}, nil
	}
}

func makeGetScanEndpoint(s ScanGetter) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		requestBody, ok := request.(*ScanRequest)
		if !ok {
			return nil, errors.Assertion("Type assertion failed")
		}

		scan, err := s.GetScan(ctx, requestBody.ID)
		if err != nil {
			return nil, err
		}
		resp, err := buildGetScanResponse(scan)
		if err != nil {
			return nil, err
		}
		return Ok{resp}, nil
	}
}

func makeGetScanChecksEndpoint(s ScanGetter) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		requestBody, ok := request.(*ScanRequest)
		if !ok {
			return nil, errors.Assertion("Type assertion failed")
		}

		checks, err := s.GetScanChecks(ctx, requestBody.ID)
		if err != nil {
			return nil, err
		}
		resp, err := buildChecksResponse(checks)
		if err != nil {
			return nil, err
		}
		return Ok{resp}, nil
	}
}

func makeAbortScanEndpoint(s ScanGetter) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		requestBody, ok := request.(*ScanRequest)
		if !ok {
			return nil, errors.Assertion("Type assertion failed")
		}
		err = s.AbortScan(ctx, requestBody.ID)
		if err != nil {
			return nil, err
		}
		return Accepted{}, nil
	}
}

func buildGetScanResponse(scan api.Scan) (GetScanResponse, error) {
	// The field StartTime is mandatory
	if scan.StartTime == nil {
		return GetScanResponse{}, errors.Default(fmt.Sprintf("scan start time is nil for scan %s", scan.ID.String()))
	}
	if scan.Progress == nil {
		zeroProgress := float32(0.0)
		scan.Progress = &zeroProgress
	}
	if scan.Trigger == nil {
		scan.Trigger = new(string)
	}
	extID := ""
	if scan.ExternalID != nil {
		extID = *scan.ExternalID
	}
	resp := GetScanResponse{
		ID:            scan.ID.String(),
		ExternalID:    extID,
		Status:        *scan.Status,
		ScheduledTime: scan.ScheduledTime,
		StartTime:     scan.StartTime,
		EndTime:       scan.EndTime,
		Trigger:       *scan.Trigger,
		Progress:      scan.Progress,
		CheckCount:    scan.CheckCount,
		ChecksCreated: scan.ChecksCreated,
		AbortedAt:     scan.AbortedAt,
	}
	return resp, nil
}

func buildGetScansResponse(scans []api.Scan) (GetScansResponse, error) {
	scansInfo := GetScansResponse{
		Scans: []GetScanResponse{},
	}
	for _, s := range scans {
		resp, err := buildGetScanResponse(s)
		if err != nil {
			return GetScansResponse{}, err
		}
		scansInfo.Scans = append(scansInfo.Scans, resp)
	}
	return scansInfo, nil
}

func buildChecksResponse(checks []api.Check) (GetChecksResponse, error) {
	checksResp := GetChecksResponse{
		Checks: []GetCheckResponse{},
	}
	for _, c := range checks {
		checksResp.Checks = append(checksResp.Checks, GetCheckResponse{
			ID:            c.ID,
			Status:        c.Status,
			Target:        c.Target,
			ChecktypeName: util.Ptr2Str(c.ChecktypeName),
			Image:         util.Ptr2Str(c.Image),
			Options:       util.Ptr2Str(c.Options),
			Report:        util.Ptr2Str(c.Report),
			Raw:           util.Ptr2Str(c.Raw),
			Tag:           util.Ptr2Str(c.Tag),
			Assettype:     util.Ptr2Str(c.Assettype),
		})
	}
	return checksResp, nil
}
