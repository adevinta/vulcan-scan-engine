/*
Copyright 2021 Adevinta
*/

package notify

import (
	"encoding/json"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sns"
	"github.com/aws/aws-sdk-go/service/sns/snsiface"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
)

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
	var attrs map[string]*sns.MessageAttributeValue
	if attributes != nil {
		attrs = make(map[string]*sns.MessageAttributeValue)
		t := "String"
		for n, v := range attributes {
			attrs[n] = &sns.MessageAttributeValue{
				DataType:    &t,
				StringValue: &v,
			}
		}
	}
	input := &sns.PublishInput{
		Message:           aws.String(string(content)),
		TopicArn:          aws.String(s.c.TopicArn),
		MessageAttributes: attrs,
	}
	_ = level.Debug(s.l).Log("PushNotificationMessage", aws.StringValue(input.Message))
	_, err = s.sns.Publish(input)
	if err != nil {
		_ = level.Error(s.l).Log("ErrorPushNotification", err)
		return (err)
	}
	_ = level.Debug(s.l).Log("PushNotification", "OK")
	return nil
}
