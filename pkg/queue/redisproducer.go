/*
Copyright 2021 Adevinta
*/

package queue

import (
	"fmt"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/hibiken/asynq"
)

type RedisConfig struct {
	Host string
	Port int
	Usr  string
	Pwd  string
	DB   int
}

type RedisProducer struct {
	client *asynq.Client
	log    log.Logger
}

// NewSQSProducer creates a new SQSProducer that allows to send messages to
// the given queueARN.
func NewRedisProducer(config RedisConfig, log log.Logger) *RedisProducer {
	if config.Host == "" {
		return nil
	}
	return &RedisProducer{
		client: asynq.NewClient(&asynq.RedisClientOpt{
			Addr:     fmt.Sprintf("%s:%d", config.Host, config.Port),
			DB:       config.DB,
			Username: config.Usr,
			Password: config.Pwd}),
		log: log,
	}
}

// SendMessage sends a message to the producer defined queue.
func (s *RedisProducer) SendMessage(queueName string, body []byte) error {
	level.Info(s.log).Log("enqueue", queueName)
	task := asynq.NewTask("checks", body)
	m, err := s.client.Enqueue(task, asynq.Queue(queueName))
	level.Debug(s.log).Log("enqueued", m.ID, m.Queue)
	return err
}
