/*
Copyright 2021 Adevinta
*/

package migrations

import (
	"github.com/adevinta/vulcan-scan-engine/pkg/util"
)

const (
	migrationCmd = "migrate"
)

// Ensure ensure the database exists and is migrated to the last version.
func Ensure(conn, dir string) error {
	// Ensure db is created.
	_, err := util.EnsureDB(conn)
	if err != nil {
		return err
	}
	// Execute migrations
	return util.RunFlywayCmd(conn, dir, migrationCmd)
}
