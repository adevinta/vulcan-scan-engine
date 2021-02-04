/*
Copyright 2021 Adevinta
*/

package api

import (
	uuid "github.com/satori/go.uuid"
)

// Event holds the data that is stored in the database when a Event is processed.
type Event struct {
	ScanID uuid.UUID
	ID     int
	Data   []byte
}

// MalformedEvent holds the data that is stored in the database for a malformed event.
type MalformedEvent struct {
	ID   int
	Data []byte
}
