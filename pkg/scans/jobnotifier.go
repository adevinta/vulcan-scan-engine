/*
Copyright 2021 Adevinta
*/

package scans

import (
	"encoding/json"
)

const jobEventType = "check-job-event"

// Notifier allows to push a given job with its attributes the given topic.
type Notifier interface {
	Push(message interface{}, attributes map[string]string) error
}

// JobsNotifier allows to push jobs to the target topic.
type JobsNotifier struct {
	notifier Notifier
}

// NewJobNotifier creates a new JobNotifier given a Notifier instance.
func NewJobNotifier(notifier Notifier) (JobsNotifier, error) {
	return JobsNotifier{
		notifier: notifier,
	}, nil
}

// Push pushes a job to the target topic.
func (j JobsNotifier) Push(job Job, attributes map[string]string) error {
	content, err := json.Marshal(job)
	if err != nil {
		return err
	}

	// Add required attributes.
	attributes["event_type"] = jobEventType
	attributes["asset_type"] = job.AssetType
	// Optional attributes.
	if job.TargetQueue != "" {
		attributes["target_queue"] = job.TargetQueue
	}
	for k, v := range job.Metadata {
		switch k {
		case "team":
			attributes["team"] = v
		case "program":
			attributes["program"] = v
		}
	}
	return j.notifier.Push(string(content), attributes)
}
