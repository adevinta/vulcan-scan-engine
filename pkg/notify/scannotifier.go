/*
Copyright 2021 Adevinta
*/

package notify

import (
	"github.com/adevinta/vulcan-scan-engine/pkg/api"
)

type notifier interface {
	Push(message interface{}) error
}

// ScanNotifier notifies to the provided generic notifier exactly the same
// payload that the endpoint for getting scan status is generating.
type ScanNotifier struct {
	notifier notifier
}

// NewScanNotifier creates a new scan notifier with the given generic notifier.
func NewScanNotifier(n notifier) *ScanNotifier {
	return &ScanNotifier{
		notifier: n,
	}
}

// Notify to the injected generic notifier a ScanNotification.
func (s *ScanNotifier) Notify(m api.ScanNotification) error {
	return s.notifier.Push(m)
}
