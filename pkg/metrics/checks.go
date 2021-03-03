/*
Copyright 2021 Adevinta
*/

package metrics

import (
	"fmt"
	"strings"

	metrics "github.com/adevinta/vulcan-metrics-client"

	"github.com/adevinta/vulcan-scan-engine/pkg/api"
)

const (
	componentTag = "component:scanengine"
)

// Checks provides functionality to update checks metrics.
type Checks struct {
	Client metrics.Client
}

// CheckUpdated updates the metrics of a check by listening to status changes.
func (c *Checks) CheckUpdated(ch api.Check, programID string) {
	team := "unknown-team"
	if ch.Metadata != nil {
		meta := *ch.Metadata
		if t, ok := meta["team"]; ok {
			team = t
		}
	}
	checktype := "unknown"
	if ch.ChecktypeName != nil {
		checktype = *ch.ChecktypeName
	}
	c.push(team, programID, checktype, ch.Status)
}

// Push increases by one the counter of checks created or with
// a status change of a scan.
func (c *Checks) push(team, programID, checktype, status string) {
	scanTag := buildScanTag(team, programID)
	checktypeTag := fmt.Sprint("checktype:", strings.ToLower(checktype))
	checkStatusTag := fmt.Sprint("checkstatus:", strings.ToLower(status))

	c.Client.Push(metrics.Metric{
		Name:  "vulcan.scan.check.count",
		Typ:   metrics.Count,
		Value: 1,
		Tags:  []string{componentTag, scanTag, checktypeTag, checkStatusTag},
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
