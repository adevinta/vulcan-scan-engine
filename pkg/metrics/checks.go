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

// Checks provides functionality to update checks metrics.
type Checks struct {
	Client metrics.Client
}

// CheckUpdated updates the metrics of a check by listening to status changes.
func (c *Checks) CheckUpdated(ch api.Check) {
	team := "unknown-team"
	if ch.Metadata != nil {
		meta := *ch.Metadata
		if t, ok := meta["team"]; ok {
			team = t
		}
	}
	scan := ch.ID
	checktype := "unknown"
	if ch.ChecktypeName != nil {
		checktype = *ch.ChecktypeName
	}
	c.push(team, scan, checktype, ch.Status)
}

// Push increases by one the counter of checks created or with
// a status change of a scan.
func (c *Checks) push(team, scan, checktype, status string) {
	componentTag := fmt.Sprintf("scan:%s-%s", strings.ToLower(team), strings.ToLower(scan))
	checktypeTag := fmt.Sprintf("checktype:%s", strings.ToLower(checktype))
	checkStatusTag := fmt.Sprintf("checkstatus:%s", strings.ToLower(status))

	c.Client.Push(metrics.Metric{
		Name:  "scan.check.count",
		Typ:   metrics.Count,
		Value: 1,
		Tags:  []string{componentTag, checktypeTag, checkStatusTag},
	})
}
