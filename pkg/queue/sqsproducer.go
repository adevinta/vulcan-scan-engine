/*
Copyright 2021 Adevinta
*/

package queue

import (
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-sdk-go/service/sqs/sqsiface"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
)

var (
	// ErrQueueDoesNotExist is returned when the MultipleSQSProducer tries to send
	// a message to a queue that is not defined.
	ErrQueueDoesNotExist = errors.New("queue does not exist")
)

// SQSProducer reads and consumes sqs messages.
type SQSProducer struct {
	sqs      sqsiface.SQSAPI
	logger   log.Logger
	queueURL string
}

// NewSQSProducer creates a new SQSProducer that allows to send messages to
// the given queueARN.
func NewSQSProducer(queueARN string, endpoint string, log log.Logger) (*SQSProducer, error) {
	sess, err := session.NewSession()
	if err != nil {
		_ = level.Error(log).Log("CreatingAWSSession", err)
		return nil, err
	}

	arn, err := arn.Parse(queueARN)
	if err != nil {
		_ = level.Error(log).Log("ParsingSQSQueueARN", err)
		return nil, fmt.Errorf("error parsing SQS queue ARN: %v", err)
	}

	awsCfg := aws.NewConfig()
	if arn.Region != "" {
		awsCfg = awsCfg.WithRegion(arn.Region)
	}
	if endpoint != "" {
		awsCfg = awsCfg.WithEndpoint(endpoint)
	}
	sqsSrv := sqs.New(sess, awsCfg)

	params := &sqs.GetQueueUrlInput{
		QueueName: aws.String(arn.Resource),
	}
	if arn.AccountID != "" {
		params.SetQueueOwnerAWSAccountId(arn.AccountID)
	}
	resp, err := sqsSrv.GetQueueUrl(params)
	if err != nil {
		_ = level.Error(log).Log("ErrorRetrievingSQSURL", err)
		return nil, fmt.Errorf("error retrieving SQS queue URL: %v", err)
	}
	if resp.QueueUrl == nil {
		return nil, errors.New("unexpected nill getting SQSProducer queue ARN")
	}
	return &SQSProducer{
		queueURL: *resp.QueueUrl,
		sqs:      sqsSrv,
	}, nil
}

// SendMessage sends a message to the producer defined queue.
func (s *SQSProducer) SendMessage(body string) error {
	msg := &sqs.SendMessageInput{
		QueueUrl:    &s.queueURL,
		MessageBody: &body,
	}
	_, err := s.sqs.SendMessage(msg)
	return err
}

// MultiSQSProducer allows to send messages to different named queues.
type MultiSQSProducer struct {
	producers map[string]*SQSProducer
}

// NewMultiSQSProducer creates a new MultipleSQSProducer given a map containing
// the name of the queues as keys and the ARN for those queues as values.
func NewMultiSQSProducer(queues map[string]string, endpoint string, log log.Logger) (*MultiSQSProducer, error) {
	var m = make(map[string]*SQSProducer)
	for n, a := range queues {
		producer, err := NewSQSProducer(a, endpoint, log)
		if err != nil {
			return nil, err
		}
		m[n] = producer
	}
	return &MultiSQSProducer{m}, nil
}

// Send send a message to a queue with the given name. If the queue
// is not defined in the producer a QueueDoesNotExistError is returned.
func (m *MultiSQSProducer) Send(queueName string, body string) error {
	p, ok := m.producers[queueName]
	if !ok {
		return ErrQueueDoesNotExist
	}
	return p.SendMessage(body)
}
