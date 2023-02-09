/*
Copyright 2021 Adevinta
*/

package queue

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-sdk-go/service/sqs/sqsiface"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
)

const (
	maxNumberOfMsg = 10
)

var (
	errInvalidEvent      = errors.New("Invalid event")
	errErrorReadCanceled = errors.New("Canceled read from sqs")
)

// Config holds the required sqs config information.
type Config struct {
	NumberOfProcessors uint8  `mapstructure:"number_of_processors"`
	Endpoint           string `mapstructure:"endpoint"`
	QueueArn           string `mapstructure:"queue_arn"`
	WaitTime           int64  `mapstructure:"wait_time"`
	Timeout            int64  `mapstructure:"timeout"`
	Disabled           bool   `mapstructure:"disabled"`
	LogMessages        bool   `mapstructure:"log_messages"`
}

type messageStore interface {
	CreateDocument(doc interface{}, data []byte) (int64, error)
}

type message struct {
	Message *string
}

// MessageProcessor defines the functions required by the SQSConsumer to process a message.
type MessageProcessor interface {
	Process(context.Context, []byte) error
}

// SQSConsumer reads and consumes sqs messages.
type SQSConsumer struct {
	sqs           sqsiface.SQSAPI
	processor     MessageProcessor
	store         messageStore
	logger        log.Logger
	receiveParams sqs.ReceiveMessageInput
	maxWaitTime   int64
	logMessages   bool
	disabled      bool
}

// UpdateProcessorGroup defines a group of check notification processors.
type UpdateProcessorGroup struct {
	consumers []*SQSConsumer
	wg        *sync.WaitGroup
}

// NewUpdateProcessorGroup creates a ProcessorGroup using the given config,
// message processor and logger.
func NewUpdateProcessorGroup(c Config, processor MessageProcessor, store messageStore, log log.Logger) (UpdateProcessorGroup, error) {
	var consumerGroup UpdateProcessorGroup
	consumers := []*SQSConsumer{}
	for i := uint8(0); i < c.NumberOfProcessors; i++ {
		consumer, err := NewConsumer(c, processor, store, log)
		if err != nil {
			return consumerGroup, err // nolint
		}
		consumers = append(consumers, consumer)
	}
	consumerGroup.consumers = consumers
	consumerGroup.wg = &sync.WaitGroup{}
	return consumerGroup, nil // nolint
}

// StartProcessing signals all the consumers in the group to start processing
// messages in the queue.
func (u *UpdateProcessorGroup) StartProcessing(ctx context.Context) {
	for _, c := range u.consumers {
		cCtx, _ := context.WithCancel(ctx)
		u.wg.Add(1)
		go c.StarProcessing(cCtx, u.wg)
	}
}

// WaitFinish locks the calling goroutine until all the consumers finished
// processing messages.
func (u *UpdateProcessorGroup) WaitFinish() {
	u.wg.Wait()
}

// NewConsumer creates and initializes an SQSConsumer.
func NewConsumer(c Config, processor MessageProcessor, store messageStore, log log.Logger) (*SQSConsumer, error) {
	var consumer *SQSConsumer
	if c.Disabled {
		_ = level.Info(log).Log("SQSConsumerDisabled", true)
		return &SQSConsumer{
			logger:   log,
			disabled: true,
		}, nil
	}
	sess, err := session.NewSession()
	if err != nil {
		_ = level.Error(log).Log("CreatingAWSSession", err)
		return consumer, err
	}

	arn, err := arn.Parse(c.QueueArn)
	if err != nil {
		_ = level.Error(log).Log("ParsingSQSQueueARN", err)
		return nil, fmt.Errorf("error parsing SQS queue ARN: %v", err)
	}
	awsCfg := aws.NewConfig()
	if arn.Region != "" {
		awsCfg = awsCfg.WithRegion(arn.Region)
	}
	if c.Endpoint != "" {
		awsCfg = awsCfg.WithEndpoint(c.Endpoint)
	}
	srv := sqs.New(sess, awsCfg)

	params := &sqs.GetQueueUrlInput{
		QueueName: aws.String(arn.Resource),
	}
	if arn.AccountID != "" {
		params.SetQueueOwnerAWSAccountId(arn.AccountID)
	}
	resp, err := srv.GetQueueUrl(params)
	if err != nil {
		_ = level.Error(log).Log("ErrorRetrievingSQSURL", err)
		return consumer, fmt.Errorf("error retrieving SQS queue URL: %v", err)
	}
	receiveParams := sqs.ReceiveMessageInput{
		QueueUrl:            aws.String(*resp.QueueUrl),
		MaxNumberOfMessages: aws.Int64(maxNumberOfMsg),
		WaitTimeSeconds:     aws.Int64(0),
		VisibilityTimeout:   aws.Int64(c.Timeout),
	}

	return &SQSConsumer{
		logMessages:   c.LogMessages,
		disabled:      c.Disabled,
		store:         store,
		processor:     processor,
		logger:        log,
		sqs:           srv,
		receiveParams: receiveParams,
		maxWaitTime:   c.WaitTime,
	}, nil
}

// StarProcessing stars processing messages by reading from the queue an passing them to the MessageProcessor.
func (s *SQSConsumer) StarProcessing(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	if s.disabled {
		_ = level.Info(s.logger).Log("SQSConsumerDisabled", s.disabled)
		return
	}
	_ = level.Info(s.logger).Log("SQSConsumerLogMessages", s.logMessages)
	var exit bool
	for !exit {
		select {
		case <-ctx.Done():
			exit = true
		default:
			err := s.readAndProcess(ctx)
			if err != nil {
				_ = level.Error(s.logger).Log("ErrorReadingMessages", err)
			}
		}
	}
}

func (s *SQSConsumer) readAndProcess(ctx context.Context) error {
	resp, err := s.sqs.ReceiveMessageWithContext(ctx, &s.receiveParams)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok && aerr.Code() == request.CanceledErrorCode {
			return errErrorReadCanceled
		}
		return err
	}

	if len(resp.Messages) == 0 {
		s.receiveParams.WaitTimeSeconds = aws.Int64(s.maxWaitTime)
		return nil
	}
	s.receiveParams.WaitTimeSeconds = aws.Int64(0)
	for _, m := range resp.Messages {
		if m == nil {
			_ = level.Error(s.logger).Log("GotNilSQSMessage")
			continue
		}
		if m.Body == nil {
			_ = level.Error(s.logger).Log("SQSMessageWithoutBody", m)
			// Invalid message delete from queue without processing.
			_, err := s.sqs.DeleteMessage(&sqs.DeleteMessageInput{
				ReceiptHandle: m.ReceiptHandle,
				QueueUrl:      s.receiveParams.QueueUrl,
			})
			if err != nil {
				_ = level.Error(s.logger).Log("ErrorDeletingProcessedMessage", err.Error())
			}
			continue
		}

		err := s.process(ctx, *m)
		if err != nil {
			// Do not delete messages incorrectly processed.
			_ = level.Error(s.logger).Log("ErrorProcessingSQSMessage", err.Error(), "MessageID", *m.MessageId)
			continue
		}

		_, err = s.sqs.DeleteMessage(&sqs.DeleteMessageInput{
			ReceiptHandle: m.ReceiptHandle,
			QueueUrl:      s.receiveParams.QueueUrl,
		})
		if err != nil {
			_ = level.Error(s.logger).Log("ErrorDeletingSQSMessage", err)
			continue
		}

		if s.logMessages {
			_, err = s.store.CreateDocument(*m, []byte(*m.Body))
			if err != nil {
				_ = level.Error(s.logger).Log("ErrorStoringProcessedMessage", err)
				continue
			}
		}
		err = level.Info(s.logger).Log("MsgProcessed", string(*m.MessageId))
		if err != nil {
			fmt.Printf("Error writting to log %v", err)
		}
	}
	return nil
}

func (s *SQSConsumer) process(ctx context.Context, m sqs.Message) error {
	_ = level.Info(s.logger).Log("ProcessingMessageWithID", *m.MessageId)
	if m.Body == nil {
		return errInvalidEvent
	}
	_ = level.Debug(s.logger).Log("MessageBody", string(*m.Body))
	return s.processor.Process(ctx, []byte(*m.Body))
}
