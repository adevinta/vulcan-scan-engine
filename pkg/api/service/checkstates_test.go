package service

import (
	"reflect"
	"testing"
)

func TestLessOrEqual(t *testing.T) {
	testCases := []struct {
		state string
		want  []string
	}{
		{
			"CREATED",
			[]string{"CREATED"},
		},
		{
			"QUEUED",
			[]string{"CREATED", "QUEUED"},
		},
		{
			"ASSIGNED",
			[]string{"CREATED", "QUEUED", "ASSIGNED"},
		},
		{
			"RUNNING",
			[]string{"CREATED", "QUEUED", "ASSIGNED", "RUNNING"},
		},
		{
			"PURGING",
			[]string{"CREATED", "QUEUED", "ASSIGNED", "RUNNING", "PURGING"},
		},
		{
			"MALFORMED",
			[]string{"CREATED", "QUEUED", "ASSIGNED", "RUNNING", "PURGING",
				"ABORTED", "FAILED", "FINISHED", "INCONCLUSIVE", "KILLED", "MALFORMED", "TIMEOUT"},
		},
		{
			"ABORTED",
			[]string{"CREATED", "QUEUED", "ASSIGNED", "RUNNING", "PURGING",
				"ABORTED", "FAILED", "FINISHED", "INCONCLUSIVE", "KILLED", "MALFORMED", "TIMEOUT"},
		},
		{
			"KILLED",
			[]string{"CREATED", "QUEUED", "ASSIGNED", "RUNNING", "PURGING",
				"ABORTED", "FAILED", "FINISHED", "INCONCLUSIVE", "KILLED", "MALFORMED", "TIMEOUT"},
		},
		{
			"FAILED",
			[]string{"CREATED", "QUEUED", "ASSIGNED", "RUNNING", "PURGING",
				"ABORTED", "FAILED", "FINISHED", "INCONCLUSIVE", "KILLED", "MALFORMED", "TIMEOUT"},
		},
		{
			"FINISHED",
			[]string{"CREATED", "QUEUED", "ASSIGNED", "RUNNING", "PURGING",
				"ABORTED", "FAILED", "FINISHED", "INCONCLUSIVE", "KILLED", "MALFORMED", "TIMEOUT"},
		},
		{
			"TIMEOUT",
			[]string{"CREATED", "QUEUED", "ASSIGNED", "RUNNING", "PURGING",
				"ABORTED", "FAILED", "FINISHED", "INCONCLUSIVE", "KILLED", "MALFORMED", "TIMEOUT"},
		},
		{
			"INCONCLUSIVE",
			[]string{"CREATED", "QUEUED", "ASSIGNED", "RUNNING", "PURGING",
				"ABORTED", "FAILED", "FINISHED", "INCONCLUSIVE", "KILLED", "MALFORMED", "TIMEOUT"},
		},
		// Corner case to support upsert when agent pushes log and report data
		// within a check message without explicit status.
		{
			"",
			[]string{"CREATED", "QUEUED", "ASSIGNED", "RUNNING", "PURGING",
				"ABORTED", "FAILED", "FINISHED", "INCONCLUSIVE", "KILLED", "MALFORMED", "TIMEOUT"},
		},
	}

	for _, tc := range testCases {
		if states := checkStates.LessOrEqual(tc.state); !reflect.DeepEqual(states, tc.want) {
			t.Fatalf("expected:\n%v\nbut got:\n%v", tc.want, states)
		}
	}
}

func TestHigh(t *testing.T) {
	testCases := []struct {
		state string
		want  []string
	}{
		{
			"CREATED",
			[]string{"ABORTED", "FAILED", "FINISHED", "INCONCLUSIVE", "KILLED", "MALFORMED", "TIMEOUT",
				"PURGING", "RUNNING", "ASSIGNED", "QUEUED"},
		},
		{
			"QUEUED",
			[]string{"ABORTED", "FAILED", "FINISHED", "INCONCLUSIVE", "KILLED", "MALFORMED", "TIMEOUT",
				"PURGING", "RUNNING", "ASSIGNED"},
		},
		{
			"ASSIGNED",
			[]string{"ABORTED", "FAILED", "FINISHED", "INCONCLUSIVE", "KILLED", "MALFORMED", "TIMEOUT",
				"PURGING", "RUNNING"},
		},
		{
			"RUNNING",
			[]string{"ABORTED", "FAILED", "FINISHED", "INCONCLUSIVE", "KILLED", "MALFORMED", "TIMEOUT",
				"PURGING"},
		},
		{
			"PURGING",
			[]string{"ABORTED", "FAILED", "FINISHED", "INCONCLUSIVE", "KILLED", "MALFORMED", "TIMEOUT"},
		},
		{
			"ABORTED",
			[]string{},
		},
		{
			"FAILED",
			[]string{},
		},
		{
			"FINISHED",
			[]string{},
		},
		{
			"INCONCLUSIVE",
			[]string{},
		},
		{
			"KILLED",
			[]string{},
		},
		{
			"MALFORMED",
			[]string{},
		},
		{
			"TIMEOUT",
			[]string{},
		},
		// Corner case to support upsert when agent pushes log and report data
		// within a check message without explicit status.
		{
			"",
			[]string{"ABORTED", "FAILED", "FINISHED", "INCONCLUSIVE", "KILLED", "MALFORMED", "TIMEOUT",
				"PURGING", "RUNNING", "ASSIGNED", "QUEUED", "CREATED"},
		},
	}

	for _, tc := range testCases {
		if states := checkStates.High(tc.state); !reflect.DeepEqual(states, tc.want) {
			t.Fatalf("expected:\n%v\nbut got:\n%v", tc.want, states)
		}
	}
}

func TestIsHigher(t *testing.T) {
	testCases := []struct {
		status string
		base   string
		want   bool
	}{
		{
			status: "CREATED",
			base:   "CREATED",
			want:   false,
		},
		{
			status: "QUEUED",
			base:   "CREATED",
			want:   true,
		},
		{
			status: "FINISHED",
			base:   "INCONCLUSIVE",
			want:   false,
		},
		{
			status: "FINISHED",
			base:   "FINISHED",
			want:   false,
		},
		{
			status: "ABORTED",
			base:   "PURGING",
			want:   true,
		},
		{
			status: "ASSIGNED",
			base:   "RUNNING",
			want:   false,
		},
		{
			status: "RUNNING",
			base:   "ASSIGNED",
			want:   true,
		},
	}

	for _, tc := range testCases {
		if got := checkStates.IsHigher(tc.status, tc.base); got != tc.want {
			t.Fatalf("expected IsHigher for %s against %s to be %v, but got %v",
				tc.status, tc.base, tc.want, got)
		}
	}
}
