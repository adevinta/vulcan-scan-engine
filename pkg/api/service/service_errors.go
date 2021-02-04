/*
Copyright 2021 Adevinta
*/

package service

import (
	ers "errors"
	"fmt"

	"github.com/adevinta/errors"
)

// ErrNotImplemented ...
var ErrNotImplemented = ers.New("NotImplemented")

// ErrNotDefinedCheckState a check update with an unkown state has been received.
var ErrNotDefinedCheckState = ers.New("CheckStateNotDefined")

// ErrAtLeastOneTargetAndChecktype must have al least one checktype and one target.
var ErrAtLeastOneTargetAndChecktype = fmt.Errorf("AtLeastOneTargetAndChecktype")

// ErrNotTargetGroupsDefined a scan must have at least one targetgroup defined.
var ErrNotTargetGroupsDefined = fmt.Errorf("a scan must have a least one target_group defined")

// ErrValidationError returns a pretty error
func ErrValidationError(err error) error {
	return errors.Validation(err, "Validation error")
}

// ErrNotFound returns a pretty error
func ErrNotFound(err error) error {
	return errors.NotFound(err)
}

// ErrUpdateFailed returns a pretty error
func ErrUpdateFailed(err error) error {
	return errors.Update(err)
}

// ErrAbortFailed creates a new ErrorAbortFailed with the given status code returned
// by vulcan-core.
func ErrAbortFailed(statusCode int) error {
	return &errorAbortFailed{statusCode}
}

// errorAbortFailed represents an error that wraps the status code returned by vulcan-core.
type errorAbortFailed struct {
	statusCode int
}

func (e errorAbortFailed) StatusCode() int {
	return e.statusCode
}

func (e *errorAbortFailed) Error() string {
	return ""
}
