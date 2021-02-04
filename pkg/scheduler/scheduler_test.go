/*
Copyright 2021 Adevinta
*/

package scheduler

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

var (
	// ErrInvalidTask indicates that the task specified does not exist.
	ErrInvalidTask = errors.New("Invalid Task")

	// ErrInvalidOptions indicates that the options specified for a task are not valid.
	ErrInvalidOptions = errors.New("Invalid Options")
)

type logger struct{}

func (l *logger) Log(vals ...interface{}) error {
	fmt.Println(vals...)
	return nil
}

type taskState struct {
	state []string
	sync.Mutex
}

type testTask interface {
	SetQueue(*taskState)
	Task() Task
}

type testTaskSchedule struct {
	Task   testTask
	Period time.Duration
}

// mockOkTask.
type mockOkTask struct{}

func (t *mockOkTask) Name() string {
	return "MyMockOkTask"
}

func (t *mockOkTask) Type() string {
	return "MockOkTask"
}

func (t *mockOkTask) Execute() error {
	return nil
}

func (t *mockOkTask) SetQueue(*taskState) {
}

func (t *mockOkTask) Task() Task {
	return t
}

// mockKoTask.
type mockKoTask struct{}

func (t *mockKoTask) Name() string {
	return "MyMockKoTask"
}

func (t *mockKoTask) Type() string {
	return "MockKoTask"
}

func (t *mockKoTask) Execute() error {
	return errors.New("KO")
}

func (t *mockKoTask) SetQueue(*taskState) {
}

func (t *mockKoTask) Task() Task {
	return t
}

// mockWriterTask is a mock
// task which writes OK into a slice
// every time it gets executed.
type mockWriterTask struct {
	state *taskState
	i     int
}

func (t *mockWriterTask) Name() string {
	return "MyMockWriterTask"
}

func (t *mockWriterTask) Type() string {
	return "MockWriterTask"
}

func (t *mockWriterTask) Execute() error {
	t.state.Lock()
	defer t.state.Unlock()
	s := t.state.state
	s = append(s, "OK")
	t.state.state = s
	return nil
}

func (t *mockWriterTask) SetQueue(st *taskState) {
	t.state = st
}

func (t *mockWriterTask) Task() Task {
	return t
}

func TestStart(t *testing.T) {
	testCases := []struct {
		name       string
		tasks      []testTaskSchedule
		expected   string
		msToCancel int // number of ms to wait before stopping scheduler.
	}{
		{
			name: "one task happy path",
			tasks: []testTaskSchedule{
				{
					Task:   &mockWriterTask{},
					Period: 500 * time.Millisecond,
				},
			},
			expected:   "OK",
			msToCancel: 600,
		},
		{
			name: "one KO task",
			tasks: []testTaskSchedule{
				{
					Task:   &mockKoTask{},
					Period: 200 * time.Millisecond,
				},
			},
			expected:   "",
			msToCancel: 600,
		},
		{
			name: "one OK task one KO task",
			tasks: []testTaskSchedule{
				{
					Task:   &mockWriterTask{},
					Period: 200 * time.Millisecond,
				},
				{
					Task:   &mockKoTask{},
					Period: 200 * time.Millisecond,
				},
			},
			expected:   "OK",
			msToCancel: 300,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			tasks := []taskSchedule{}
			state := &taskState{}
			for _, t := range tc.tasks {
				t.Task.SetQueue(state)
				tasks = append(tasks, taskSchedule{t.Task.Task(), t.Period})
			}
			scheduler := NewScheduler(&logger{})
			for _, t := range tasks {
				scheduler.AddTask(t.task, t.period)
			}
			var cancel context.CancelFunc
			ctx := context.Background()
			ctx, cancel = context.WithCancel(ctx)
			wg := scheduler.Start(ctx)
			go func() {
				<-time.After(time.Duration(tc.msToCancel) * time.Millisecond)
				cancel()
			}()
			wg.Wait()
			var str strings.Builder
			for _, mssg := range state.state {
				str.WriteString(mssg)
			}

			if tc.expected != str.String() {
				t.Fatalf("Expected '%s', but got: '%s'", tc.expected, str.String())
			}
		})
	}
}

func TestAddTask(t *testing.T) {
	testCases := []struct {
		name        string
		tasks       []Task
		periods     []time.Duration
		expectedErr error
	}{
		{
			name: "happy path",
			tasks: []Task{
				&mockOkTask{},
			},
			periods: []time.Duration{
				2 * time.Second,
			},
			expectedErr: nil,
		},
		{
			name: "invalid period 0",
			tasks: []Task{
				&mockOkTask{},
			},
			periods: []time.Duration{
				0,
			},
			expectedErr: ErrInvalidPeriod,
		},
		{
			name: "invalid period <0",
			tasks: []Task{
				&mockOkTask{},
			},
			periods: []time.Duration{
				-1,
			},
			expectedErr: ErrInvalidPeriod,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			for i, task := range tc.tasks {
				scheduler := NewScheduler(nil)
				err := scheduler.AddTask(task, tc.periods[i])
				if err != tc.expectedErr {
					if tc.expectedErr != nil {
						t.Fatalf("Expected error %v, but got: %v", tc.expectedErr, err)
					} else {
						t.Fatalf("Expected no error, but got: %v", err)
					}
				}
			}
		})
	}
}
