/*
Copyright 2021 Adevinta
*/

package scheduler

import (
	"context"
	"errors"
	"sync"
	"time"
)

var (
	// ErrInvalidPeriod indicates that the rate specified for the task is not
	// valid.
	ErrInvalidPeriod = errors.New("Invalid period")
)

// Logger defines the log interface used by the Scheduler.
type Logger interface {
	Log(vals ...interface{}) error
}

// Task represents a maintenance task.
type Task interface {
	Name() string
	Type() string
	Execute() error
}

// Scheduler is responsible for scheduling and executing
// the maintenance tasks.
type Scheduler struct {
	log   Logger
	tasks []taskSchedule
}

// taskSchedule represents a task and its
// execution rate time in minutes.
type taskSchedule struct {
	task   Task
	period time.Duration
}

// NewScheduler creates a new maintenance scheduler with given tasks.
func NewScheduler(log Logger) *Scheduler {
	return &Scheduler{
		log:   log,
		tasks: []taskSchedule{},
	}
}

// AddTask adds a new task to the scheduler.
func (s *Scheduler) AddTask(task Task, period time.Duration) error {
	if period <= 0 {
		return ErrInvalidPeriod
	}
	s.tasks = append(s.tasks, taskSchedule{task, period})
	return nil
}

// Start makes the scheduler start executing its tasks. It accepts a context
// that, if cancelled, will make the Scheduler to gracefully stop, it returns a
// waiting group that can be used to to wait for the scheduler to finish.
func (s *Scheduler) Start(ctx context.Context) *sync.WaitGroup {
	// TODO: Analyze the option of returning a channel instead of a wg that
	// maybe is too specific to be used "outside" the component.
	wg := new(sync.WaitGroup)
	for _, t := range s.tasks {
		s.scheduleTask(ctx, wg, t)
	}
	return wg
}

func (s *Scheduler) scheduleTask(ctx context.Context, wg *sync.WaitGroup, t taskSchedule) {
	ticker := time.NewTicker(t.period)
	task := t.task
	wg.Add(1)
	go func() {
		defer wg.Done()
	LOOP:
		for { // nolint
			select {
			case <-ticker.C:
				err := t.task.Execute()
				if err != nil {
					s.log.Log(task.Name(), task.Type(), err)
				}
			case <-ctx.Done():
				ticker.Stop()
				break LOOP
			}
		}
	}()
}
