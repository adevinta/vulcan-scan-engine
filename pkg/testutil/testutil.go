/*
Copyright 2021 Adevinta
*/

package testutil

import (
	"database/sql"
	"fmt"
	"os"
	"path"
	"sync"

	// This package is intended to be used by tests in other packages so they don't have to interact
	// directly with the db so makes sense to import the driver here.
	_ "github.com/lib/pq"
	testfixtures "gopkg.in/testfixtures.v2"

	"github.com/adevinta/errors"
	"github.com/adevinta/vulcan-scan-engine/pkg/util"
)

const (
	TestDBUser            = "vulcan"
	TestDBPassword        = "vulcan"
	dbDialect             = "postgres"
	DBConnString          = "port=5434 user=%s password=%s sslmode=disable dbname=%s"
	DBConnStringWithoutDB = "port=5434 user=%s password=%s sslmode=disable dbname=scan-enginedb"
)

var (
	m sync.Mutex
)

// SetupDB initializes the db to be used in tests.
func SetupDB(dbDirPath string, dbName string) error {
	m.Lock()
	defer m.Unlock()
	return setupDB(dbDirPath, dbName)
}

func setupDB(dbDirPath, dbName string) error {
	_, err := ensureDB(dbName)
	if err != nil {
		return err
	}
	wd, err := os.Getwd()
	if err != nil {
		return err
	}
	dir := path.Join(wd, dbDirPath)
	conn := fmt.Sprintf(DBConnString, TestDBUser, TestDBPassword, dbName)
	err = util.RunFlywayCmd(conn, dir, "clean")
	if err != nil {
		return err
	}
	return util.RunFlywayCmd(conn, dir, "migrate")
}

func ensureDB(dbName string) (bool, error) {
	conn := fmt.Sprintf(DBConnString, TestDBUser, TestDBPassword, dbName)
	return util.EnsureDB(conn)
}

// DropDB well drops an existing DB.
func DropDB(dbName string) error {
	conn := fmt.Sprintf(DBConnStringWithoutDB, TestDBUser, TestDBPassword)
	db, err := sql.Open(dbDialect, conn)
	if err != nil {
		return err
	}
	defer db.Close() // nolint: errcheck
	// The postgres driver doesn't support params in a query that drops a db.
	// We have to use string concatenation to build the statement but we are not vulnerable to a SQL injection because
	// this function should only be executed under a test and, in any case, the db name is defined in a constant.
	_, err = db.Exec("drop database " + dbName)
	return err
}

// LoadFixtures ...
func LoadFixtures(fixturesDir, dbName string) error {
	conn := fmt.Sprintf(DBConnString, TestDBUser, TestDBPassword, dbName)
	db, err := sql.Open(dbDialect, conn)
	if err != nil {
		return err
	}
	defer db.Close() // nolint: errcheck
	fixtures, err := testfixtures.NewFolder(db, &testfixtures.PostgreSQL{}, fixturesDir)
	if err != nil {
		return err
	}
	return fixtures.Load()
}

func ErrToStr(err error) string {
	result := ""
	if err != nil {
		result = err.Error()
	}
	return result
}

// CheckErrors returns trues if the both params are nil
// or both are not nil and are the same kind.
func CheckErrors(err1, err2 error) bool {
	if err1 == nil && err2 == nil {
		return true
	}
	return errors.IsKind(err1, err2)
}

// FloatPointer returns a pointer to a float32 parameter passed in.
// It's just an utility option for initializing inline struct fields.
func FloatPointer(n float32) *float32 {
	return &n
}

// StringPointer returns a pointer to a string parameter passed in.
// It's just an utility option for initializing inline struct fields.
func StringPointer(s string) *string {
	return &s
}

// IntPointer returns a pointer to a int parameter passed in.
// It's just an utility option for initializing inline struct fields.
func IntPointer(i int) *int {
	return &i
}
