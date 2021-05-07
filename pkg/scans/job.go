/*
Copyright 2021 Adevinta
*/

package scans

import (
	"errors"
	"time"

	"github.com/adevinta/vulcan-scan-engine/pkg/api"
)

// Job stores the information necessary to create a new check job to be sent to
// an agent.
type Job struct {
	CheckID       string            `json:"check_id"`      // Required
	ScanID        string            `json:"scan_id"`       // Required
	ScanStartTime time.Time         `json:"start_time"`    // Required
	Image         string            `json:"image"`         // Required
	Target        string            `json:"target"`        // Required
	Timeout       int               `json:"timeout"`       // Required
	AssetType     string            `json:"assettype"`     // Optional
	Options       string            `json:"options"`       // Optional
	RequiredVars  []string          `json:"required_vars"` // Optional
	Metadata      map[string]string `json:"metadata"`      // Optional
	TargetQueue   string            `json:"target_queue"`  // Optional
}

// JobFromCheck crates a Job with the required info for a check to be run by an
// agent.
func JobFromCheck(c api.Check) (Job, error) {
	var j Job
	j.AssetType = *c.Assettype
	j.CheckID = c.ID
	if c.Image == nil {
		return Job{}, errors.New("image field us mandatory")
	}
	j.Image = *c.Image
	if c.Metadata == nil {
		return Job{}, errors.New("metadata field us mandatory")
	}
	j.Metadata = *c.Metadata

	if c.Options == nil {
		return Job{}, errors.New("options field us mandatory")
	}
	j.Options = *c.Options

	if c.RequiredVars == nil {
		return Job{}, errors.New("requiredvars field is mandatory")
	}
	j.RequiredVars = *c.RequiredVars
	j.ScanID = c.ScanID
	if c.CreatedAt == nil {
		return Job{}, errors.New("createdAt field is mandatory")
	}
	j.ScanStartTime = *c.CreatedAt

	j.Target = c.Target
	if c.Timeout == nil {
		return Job{}, errors.New("timeout field is mandatory")
	}
	j.Timeout = *c.Timeout

	j.TargetQueue = *c.TargetQueue

	return j, nil
}
