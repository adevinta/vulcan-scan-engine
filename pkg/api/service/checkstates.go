package service

import "sort"

var (
	checkStates = states{
		[]string{"CREATED"},
		[]string{"QUEUED"},
		[]string{"ASSIGNED"},
		[]string{"RUNNING"},
		[]string{"PURGING"},
		[]string{"MALFORMED", "ABORTED", "KILLED", "FAILED", "FINISHED", "TIMEOUT", "INCONCLUSIVE"},
	}
	// ScansByExternalIDLimit the number of scans to return when querying by external id.
	ScansByExternalIDLimit uint32 = 5
)

// states holds all prosibles states of a finite state machine
// in a way that is easy to determine the states less or equal than a
// given state. This implementation supposes that there are only few states
// so the cost of walking through all the states is close to constant.
type states [][]string

func (c states) Init() {
	for _, s := range c {
		sort.Strings(s)
	}
}

// LessOrEqual returns the states from state machine
// that are preceding s, if s is not an existent state
// in state machine, all states are returned.
func (c states) LessOrEqual(s string) []string {
	res := []string{}
	for i := 0; i < len(c); i++ {
		res = append(res, c[i]...)
		x := sort.SearchStrings(c[i], s)
		if x < len(c[i]) && c[i][x] == s {
			break
		}
	}
	return res
}
func (c states) Terminal() []string {
	return c[len(c)-1]
}
func (c states) IsTerminal(s string) bool {
	t := c.Terminal()
	x := sort.SearchStrings(t, s)
	return (x < len(t) && t[x] == s)
}
func init() {
	checkStates.Init()
}