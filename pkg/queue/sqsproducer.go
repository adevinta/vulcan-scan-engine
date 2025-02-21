/*
Copyright 2021 Adevinta
*/

package queue

import (
	"context"
	"net/url"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/config"
	amazonsqs "github.com/aws/aws-sdk-go-v2/service/sqs"
	transport "github.com/aws/smithy-go/endpoints"
	"github.com/go-kit/log"
	"github.com/samber/lo"

	"github.com/ThreeDotsLabs/watermill"
	"github.com/ThreeDotsLabs/watermill-aws/sqs"
	"github.com/ThreeDotsLabs/watermill/message"
)

// SQSProducer reads and consumes sqs messages.
type SQSProducer struct {
	publisher *sqs.Publisher
}

// TODO: This assumes the queues are from the environment AWS region/account.

// NewSQSProducer creates a new SQSProducer that allows to send messages to
// the given queueARN.
func NewSQSProducer(endpoint string, log log.Logger) (*SQSProducer, error) {
	logger := watermill.NewStdLogger(false, false)

	sqsOpts := []func(*amazonsqs.Options){}
	if endpoint != "" {
		sqsOpts = append(sqsOpts, amazonsqs.WithEndpointResolverV2(sqs.OverrideEndpointResolver{
			Endpoint: transport.Endpoint{
				URI: *lo.Must(url.Parse(endpoint)),
			},
		}))
	}

	publisher, err := sqs.NewPublisher(sqs.PublisherConfig{
		AWSConfig: lo.Must(config.LoadDefaultConfig(context.Background())),
		CreateQueueConfig: sqs.QueueConfigAttributes{
			VisibilityTimeout: "60",
		},
		OptFns: sqsOpts,
	}, logger)
	if err != nil {
		return nil, err
	}

	return &SQSProducer{
		publisher: publisher,
	}, nil
}

// SendMessage sends a message to the producer defined queue.
func (s *SQSProducer) Send(queueArn string, body string) error {
	a, err := arn.Parse(queueArn)
	if err != nil {
		return err
	}
	return s.publisher.Publish(a.Resource, message.NewMessage(watermill.NewULID(), []byte(body)))
}
