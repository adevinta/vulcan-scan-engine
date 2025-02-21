/*
Copyright 2021 Adevinta
*/

package scans

import (
	"encoding/json"
	"errors"
)

const defaultQueueName = "default"
const prefixQueueName = "prefix"

// ErrNoDefaultQueueDefined is returned when the initial default queues
// configuration does not contain a entry with the key "default".
var ErrNoDefaultQueueDefined = errors.New("at least a queue with the name 'default' must be defined")

// NamedQueuesSender allows to send messages to a queue given its name.
type NamedQueuesSender interface {
	Send(queueName string, body string) error
}

// JobsQueueSender allows to send jobs to the proper agent queue considering a
// map of default queues for checks.
type JobsQueueSender struct {
	sender      NamedQueuesSender
	defCTQueues map[string]string
}

// NewJobQueueSender creates a new JobQueueSender given the corresponder named
// queues message sender and the default queue names for checktypes.
func NewJobQueueSender(sender NamedQueuesSender, defaultCTQueues map[string]string) (*JobsQueueSender, error) {
	if _, ok := defaultCTQueues[defaultQueueName]; !ok {
		return nil, ErrNoDefaultQueueDefined
	}

	return &JobsQueueSender{
		sender:      sender,
		defCTQueues: defaultCTQueues,
	}, nil
}

// Send sends a job to the specified queue.
func (j *JobsQueueSender) Send(queueName string, checktypeName string, job Job) error {
	// if the name of the queue is empty we look for the default queue name
	// for the checktype
	if queueName == "" {
		queueName = j.defCTQueues[checktypeName]
		// If no name for the checktype has been defined just use the default queue.
		if queueName == "" {
			queueName = j.defCTQueues[defaultQueueName]
		}
	}

	content, err := json.Marshal(job)
	if err != nil {
		return err
	}

	if err = j.sender.Send(queueName, string(content)); err != nil {
		return err
	}

	if x, ok := j.defCTQueues[prefixQueueName]; ok {
		return j.sender.Send(x, string(content))
	}

	return nil
}
