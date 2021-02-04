/*
Copyright 2021 Adevinta
*/

package db

import (
	"fmt"

	"github.com/adevinta/errors"
)

var (
	// ErrAnonymousType error returned when a anonymous type is passed to UpdateDocument functions.
	ErrAnonymousType = errors.Default("anonymous types are not supported")
)

// ErrWithQueryAndParams includes information regarding the query that caused the error.
func ErrWithQueryAndParams(err error, q string, p []interface{}) error {
	err = fmt.Errorf("error: %s, query: %s. params: %+v", err, q, p)
	return errors.Database(err)
}

// ErrWithQueryAndParamsP includes information regarding the query that caused the error.
func ErrWithQueryAndParamsP(err error, q string, p ...interface{}) error {
	return fmt.Errorf("error: %s, query: %s. params: %+v", err, q, p)
}
