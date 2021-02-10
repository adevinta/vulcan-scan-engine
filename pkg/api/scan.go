package api

import (
	"time"

	"github.com/adevinta/vulcan-scan-engine/pkg/util"
	uuid "github.com/satori/go.uuid"
)

var (
	CheckStateCreated      = "CREATED"
	CheckStateQueued       = "QUEUED"
	CheckStateAssingned    = "ASSIGNED"
	CheckStateRunning      = "RUNNING"
	CheckStatePurging      = "PURGING"
	CheckStateMalformed    = "MALFORMED"
	CheckStateKilled       = "KILLED"
	CheckStateFailed       = "FAILED"
	CheckStateFinished     = "FINISHED"
	CheckStateInconclusive = "INCONCLUSIVE"
)

// Scan holds all the data related to a scan.
type Scan struct {
	ID              uuid.UUID                 `json:"id,omitempty"`
	ExternalID      *string                   `json:"external_id,omitempty"`
	Status          *string                   `json:"status,omitempty"`
	ScheduledTime   *time.Time                `json:"scheduled_time,omitempty"`
	StartTime       *time.Time                `json:"start_time,omitempty"`
	EndTime         *time.Time                `json:"endtime_time,omitempty"`
	Progress        *float32                  `json:"progress,omitempty"`
	Trigger         *string                   `json:"trigger,omitempty"`
	Targets         *TargetGroup              `json:"targets,omitempty"`
	ChecktypesGroup *ChecktypesGroup          `json:"check_types_groups,omitempty"`
	TargetGroups    *[]TargetsChecktypesGroup `json:"target_groups,omitempty"`
	Tag             *string                   `json:"tag,omitempty"`
	CheckCount      *int                      `json:"check_count,omitempty"`

	LastTargetCheckGCreated *int                           `json:"last_target_check_g_created,omitempty"`
	LastCheckCreated        *int                           `json:"last_check_created,omitempty"`
	ChecksCreated           *int                           `json:"checks_created,omitempty"`
	ChecktypesInfo          map[string]map[string]struct{} `json:"checkstypes_info,omitempty"`
}

// ScanNotification represents the data of a scan sent to an SNS topic.
type ScanNotification struct {
	ScanID        string    `json:"scan_id"`
	ProgramID     string    `json:"program_id"`
	Tag           string    `json:"tag"`
	Status        string    `json:"status"`
	Trigger       string    `json:"trigger"`
	ScheduledTime time.Time `json:"scheduled_time"`
	StartTime     time.Time `json:"start_time"`
	EndTime       time.Time `json:"endtime_time"`
	CheckCount    int       `json:"check_count"`
}

// ToScanNotification returns a ScanNotification from a Scan.
func (s Scan) ToScanNotification() ScanNotification {
	return ScanNotification{
		ScanID:        s.ID.String(),
		ProgramID:     util.Ptr2Str(s.ExternalID),
		Status:        util.Ptr2Str(s.Status),
		Tag:           util.Ptr2Str(s.Tag),
		Trigger:       util.Ptr2Str(s.Trigger),
		ScheduledTime: util.Ptr2Time(s.ScheduledTime),
		StartTime:     util.Ptr2Time(s.StartTime),
		EndTime:       util.Ptr2Time(s.EndTime),
		CheckCount:    util.Ptr2Int(s.CheckCount),
	}
}

// Check holds all the information this service needs to process regarding a check.
type Check struct {
	ID            string             `json:"id" validate:"required"`
	Status        string             `json:"status"`
	ScanID        string             `json:"scan_id"`
	Target        string             `json:"target"`
	Progress      *float32           `json:"progress,omitempty"`
	ScanIndex     *string            `json:"scan_index,omitempty"`
	AgentID       *string            `json:"agent_id,omitempty"`
	ChecktypeID   *string            `json:"checktype_id,omitempty"`
	ChecktypeName *string            `json:"checktype_name,omitempty"`
	Image         *string            `json:"image,omitempty"`
	Options       *string            `json:"options,omitempty"`
	WebHook       *string            `json:"webhook,omitempty"`
	Report        *string            `json:"report,omitempty"`
	Raw           *string            `json:"raw,omitempty"`
	QueueName     *string            `json:"queue_name,omitempty"`
	Tag           *string            `json:"tag,omitempty"`
	Assettype     *string            `json:"assettype,omitempty"`
	Metadata      *map[string]string `json:"metadata,omitempty"`
	RequiredVars  *[]string          `json:"required_vars,omitempty"`
	StartTime     *time.Time         `json:"start_time,omitempty"`
	Timeout       *int               `json:"timeout,omitempty"`
	Data          []byte             `json:"-"`
}

// CheckNotification represents the data of a check sent to an SNS topic.
type CheckNotification struct {
	ID            string   `json:"id"`
	Status        string   `json:"status"`
	ScanID        string   `json:"scan_id"`
	Target        string   `json:"target"`
	Progress      *float32 `json:"progress,omitempty"`
	AgentID       *string  `json:"agent_id,omitempty"`
	ChecktypeID   *string  `json:"checktype_id,omitempty"`
	ChecktypeName *string  `json:"checktype_name,omitempty"`
	Options       *string  `json:"options,omitempty"`
	WebHook       *string  `json:"webhook,omitempty"`
	Report        *string  `json:"report,omitempty"`
	Raw           *string  `json:"raw,omitempty"`
	QueueName     *string  `json:"queue_name,omitempty"`
	Tag           *string  `json:"tag,omitempty"`
}

// ToCheckNotification returns a CheckNotification from a Check.
func (c Check) ToCheckNotification() CheckNotification {
	return CheckNotification{
		ID:            c.ID,
		Status:        c.Status,
		ScanID:        c.ScanID,
		Target:        c.Target,
		Progress:      c.Progress,
		AgentID:       c.AgentID,
		ChecktypeID:   c.ChecktypeID,
		ChecktypeName: c.ChecktypeName,
		Options:       c.Options,
		WebHook:       c.WebHook,
		Report:        c.Report,
		Raw:           c.Raw,
		QueueName:     c.QueueName,
		Tag:           c.Tag,
	}
}

// TargetsChecktypesGroup defines a set of targets and the checktypes a scan
// must run against them.
type TargetsChecktypesGroup struct {
	TargetGroup     TargetGroup     `json:"target_group"`
	ChecktypesGroup ChecktypesGroup `json:"checktypes_group"`
}

// TargetGroup Defines a group of targets against which to execute the checktypes.
type TargetGroup struct {
	Name    string   `json:"name"`
	Options string   `json:"options"`
	Targets []Target `json:"targets"`
}

// Target represents a target of a scan.
type Target struct {
	Identifier string `json:"identifier"`
	Type       string `json:"type"`
	Options    string `json:"options"`
}

// ChecktypesGroup represents a group of checktypes that are used to generated the checks
// of a scan.
type ChecktypesGroup struct {
	Name       string      `json:"name"`
	Checktypes []Checktype `json:"checktypes"`
}

// Checktype defines one kind of check that belongs to a ChecktypesGroup.
type Checktype struct {
	Name        string  `json:"name"`
	Options     string  `json:"options"`
	Description *string `json:"description,omitempty"`
	Enabled     *bool   `json:"enabled,omitempty"`
	ID          *string `form:"id,omitempty" `
	Image       *string `json:"image,omitempty" `
	Timeout     *int    `json:"timeout,omitempty"`
}
