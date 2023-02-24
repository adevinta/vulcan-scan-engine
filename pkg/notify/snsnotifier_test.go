/*
Copyright 2021 Adevinta
*/

package notify

import (
	"os"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/aws/aws-sdk-go/service/sns"
	"github.com/aws/aws-sdk-go/service/sns/snsiface"
	"github.com/go-kit/log"
)

type snsMock struct {
	snsiface.SNSAPI
	notification *sns.PublishInput
}

func (m *snsMock) Publish(s *sns.PublishInput) (*sns.PublishOutput, error) {
	m.notification = s
	return nil, nil
}

func TestSNSNotifier_Push(t *testing.T) {
	type fields struct {
		c   Config
		sns *snsMock
		l   log.Logger
	}

	tests := []struct {
		name       string
		fields     fields
		message    map[string]interface{}
		attributes map[string]string
		want       *sns.PublishInput
		wantErr    bool
	}{
		{
			name: "PushesMsgsToTopic",
			fields: fields{
				sns: &snsMock{},
				l:   log.NewLogfmtLogger(os.Stdout),
				c: Config{
					TopicArn: "arn:aTopic",
					Enabled:  true,
				},
			},
			message:    map[string]interface{}{"a": "b"},
			attributes: map[string]string{"a": "b"},
			want: &sns.PublishInput{
				Message:  aws.String(`{"a":"b"}`),
				TopicArn: aws.String("arn:aTopic"),
				MessageAttributes: map[string]*sns.MessageAttributeValue{
					"a": {
						DataType:    strToPtr("String"),
						StringValue: strToPtr("b"),
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &SNSNotifier{
				c:   tt.fields.c,
				sns: tt.fields.sns,
				l:   tt.fields.l,
			}
			if err := s.Push(tt.message, tt.attributes); (err != nil) != tt.wantErr {
				t.Errorf("SNSNotifier.Push() error = %v, wantErr %v", err, tt.wantErr)
			}
			diff := cmp.Diff(tt.want, tt.fields.sns.notification, cmpopts.IgnoreUnexported(sns.PublishInput{}))
			if diff != "" {
				t.Errorf("want!= got. Diffs:%s", diff)
			}
		})
	}
}

func TestPrepareMessageAttributes(t *testing.T) {
	tests := []struct {
		name       string
		attributes map[string]string
		want       map[string]*sns.MessageAttributeValue
	}{
		{
			name:       "PushesMsgsToTopic",
			attributes: map[string]string{"a": "ONE", "b": "TWO"},
			want: map[string]*sns.MessageAttributeValue{
				"a": {
					DataType:    strToPtr("String"),
					StringValue: strToPtr("ONE"),
				},
				"b": {
					DataType:    strToPtr("String"),
					StringValue: strToPtr("TWO"),
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := prepareMessageAttributes(tt.attributes)

			diff := cmp.Diff(got, tt.want)
			if diff != "" {
				t.Errorf("want != got. Diffs:%s", diff)
			}
		})
	}
}

func strToPtr(s string) *string {
	return &s
}
