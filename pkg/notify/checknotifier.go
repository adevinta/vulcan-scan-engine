/*
Copyright 2021 Adevinta
*/

package notify

import (
	"github.com/adevinta/vulcan-core-cli/vulcan-core/client"
)

type checkSNSNotifier interface {
	Push(message interface{}) error
}

// CheckNotifier notifies to the provided generic notifier exactly the same
// payload that the endpoint for getting scan status is generating.
type CheckNotifier struct {
	notifier notifier
}

// NewCheckNotifier creates a new scan notifier with the given generic notifier.
func NewCheckNotifier(n notifier) *CheckNotifier {
	return &CheckNotifier{
		notifier: n,
	}
}

// Notify to the injected generic notifier a ScanNotification.
func (s *CheckNotifier) Notify(m *client.CheckPayload) error {
	return s.notifier.Push(m)
}
