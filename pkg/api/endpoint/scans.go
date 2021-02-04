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
)

// ScanCreator defines the service interface required by the endpoint CreateScan
type ScanCreator interface {
	CreateScan(context.Context, *api.Scan) (uuid.UUID, error)
}

// ScanGetter defines the service interface required by the endpoint GetScan
type ScanGetter interface {
	GetScan(ctx context.Context, strID string) (api.Scan, error)
	GetScansByExternalID(ctx context.Context, ID string, all bool) ([]api.Scan, error)
	AbortScan(ctx context.Context, strID string) error
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

// ScanResponse ...
type ScanResponse struct {
	ScanID string `json:"scan_id"`
}

// GetScansResponse ...
type GetScansResponse struct {
	Scans []GetScanResponse `json:"scans"`
}

// GetScanResponse  ...
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
}

// Check Represents the data send for each check belonging to a scan.
type Check struct {
	ChecktypeID string    `json:"checktype_id"`
	ID          uuid.UUID `json:"id"`
	Options     string    `json:"options"`
	Progress    float64   `json:"progress"`
	Raw         string    `json:"raw"`
	Report      string    `json:"report"`
	ScanID      string    `json:"scan_id"`
	Status      string    `json:"status"`
	Target      string    `json:"target"`
	Webhook     string    `json:"webhook"`
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
		resp, err := BuildScanResponse(scan)
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

func makeGetScanByExternalIDEndpoint(s ScanGetter) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		requestBody, ok := request.(*ScanRequest)
		if !ok {
			return nil, errors.Assertion("Type assertion failed")
		}
		all := requestBody.All == "true"
		scans, err := s.GetScansByExternalID(ctx, requestBody.ExternalID, all)
		if err != nil {
			return nil, err
		}
		resp, err := BuildScanByExternalIDResponse(scans)
		if err != nil {
			return nil, err
		}
		return Ok{resp}, nil
	}
}

// BuildScanResponse Builds a scan response from information regarding a scan.
func BuildScanResponse(scan api.Scan) (GetScanResponse, error) {
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
	}
	return resp, nil
}

// BuildScanByExternalIDResponse returns an slice of Scans responses given a list of scans and its corresponding
// checks.
func BuildScanByExternalIDResponse(scans []api.Scan) (GetScansResponse, error) {
	scansInfo := GetScansResponse{
		Scans: []GetScanResponse{},
	}
	for _, s := range scans {
		resp, err := BuildScanResponse(s)
		if err != nil {
			return GetScansResponse{}, err
		}
		scansInfo.Scans = append(scansInfo.Scans, resp)
	}
	return scansInfo, nil
}
