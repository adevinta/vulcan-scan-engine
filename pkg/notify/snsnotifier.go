/*
Copyright 2021 Adevinta
*/

package notify

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sns"
	"github.com/aws/aws-sdk-go/service/sns/snsiface"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
)

// ErrNumberOfAttributesExceeded is returned when the attributes map contains
// more than 10 attributes (which is the AWS SNS limit for SQS subscriptions).
// See: https://docs.aws.amazon.com/sns/latest/dg/sns-message-attributes.html
var ErrNumberOfAttributesExceeded = errors.New("message has more than 10 attributes defined")

// Notifier represents a generic notifier API.
type Notifier interface {
	Push(message interface{}, attributes map[string]string) error
}

// Config holds the required sqs config information.
type Config struct {
	Endpoint string `mapstructure:"endpoint"`
	TopicArn string `mapstructure:"topic_arn"`
	Enabled  bool   `mapstructure:"enabled"`
}

// SNSNotifier send push event to a sns topic.
type SNSNotifier struct {
	c   Config
	sns snsiface.SNSAPI
	l   log.Logger
}

// NewSNSNotifier creates a new SNSNotifier with the given configuration.
func NewSNSNotifier(c Config, log log.Logger) (*SNSNotifier, error) {
	arn, err := arn.Parse(c.TopicArn)
	if err != nil {
		_ = level.Error(log).Log("ParsingSNSTopicARN", err)
		return nil, err
	}

	sess, err := session.NewSession()
	if err != nil {
		_ = level.Error(log).Log("CreatingAWSSession", err)
		return nil, err
	}

	awsCfg := aws.NewConfig()
	if arn.Region != "" {
		awsCfg = awsCfg.WithRegion(arn.Region)
	}
	if c.Endpoint != "" {
		awsCfg = awsCfg.WithEndpoint(c.Endpoint)
	}
	n := &SNSNotifier{
		c:   c,
		l:   log,
		sns: sns.New(sess, awsCfg),
	}
	return n, nil
}

// Push pushes a notification to the configured sns topic.
func (s *SNSNotifier) Push(message interface{}, attributes map[string]string) error {
	if !s.c.Enabled {
		_ = level.Info(s.l).Log("PushNotification", "Disabled")
		return nil
	}
	_ = level.Debug(s.l).Log("PushNotification", "Pushing")
	content, err := json.Marshal(&message)
	if err != nil {
		return err
	}

	if len(attributes) > 10 {
		_ = level.Error(s.l).Log("ErrorPushNotification", ErrNumberOfAttributesExceeded,
			"Message", string(content), "Attributes", fmt.Sprintf("%+v", attributes))
		return ErrNumberOfAttributesExceeded
	}

	input := &sns.PublishInput{
		Message:           aws.String(string(content)),
		TopicArn:          aws.String(s.c.TopicArn),
		MessageAttributes: prepareMessageAttributes(attributes),
	}

	output, err := s.sns.Publish(input)
	if err != nil {
		_ = level.Error(s.l).Log("ErrorPushNotification", err, "Message", aws.StringValue(input.Message))
		return (err)
	}

	messageID := ""
	if output != nil {
		messageID = aws.StringValue(output.MessageId)
	}

	_ = level.Debug(s.l).Log(
		"PushNotification", "OK",
		"Message", aws.StringValue(input.Message),
		"MessageID", messageID)
	return nil
}

func prepareMessageAttributes(attributes map[string]string) map[string]*sns.MessageAttributeValue {
	var attrs map[string]*sns.MessageAttributeValue
	if attributes != nil {
		attrs = make(map[string]*sns.MessageAttributeValue)
		t := "String"
		for n, v := range attributes {
			// See: https://bryce.is/writing/code/jekyll/update/2015/11/01/3-go-gotchas.html
			localV := v
			attrs[n] = &sns.MessageAttributeValue{
				DataType:    &t,
				StringValue: &localV,
			}
		}
	}

	return attrs
}
