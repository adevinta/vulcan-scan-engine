/*
Copyright 2021 Adevinta
*/

package api

import "sort"

var (
	CheckStates = States{
		[]string{"CREATED"},
		[]string{"QUEUED"},
		[]string{"ASSIGNED"},
		[]string{"RUNNING"},
		[]string{"PURGING"},
		[]string{"MALFORMED", "ABORTED", "KILLED", "FAILED", "FINISHED", "TIMEOUT", "INCONCLUSIVE"},
	}
)

// States holds all prosibles States of a finite state machine
// in a way that is easy to determine the States less or equal than a
// given state. This implementation supposes that there are only few States
// so the cost of walking through all the States is close to constant.
type States [][]string

func (c States) Init() {
	for _, s := range c {
		sort.Strings(s)
	}
}

// LessOrEqual returns the states from state machine
// that are preceding s, if s is not an existent state
// in state machine, all states are returned.
func (c States) LessOrEqual(s string) []string {
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

func (c States) High(s string) []string {
	res := []string{}
	for i := len(c) - 1; i >= 0; i-- {
		x := sort.SearchStrings(c[i], s)
		if x < len(c[i]) && c[i][x] == s {
			break
		}
		res = append(res, c[i]...)
	}
	return res
}

func (c States) IsHigher(s, base string) bool {
	for _, v := range c.High(base) {
		if s == v {
			return true
		}
	}
	return false
}

func (c States) Terminal() []string {
	return c[len(c)-1]
}

func (c States) IsTerminal(s string) bool {
	t := c.Terminal()
	x := sort.SearchStrings(t, s)
	return (x < len(t) && t[x] == s)
}

func init() {
	CheckStates.Init()
}
