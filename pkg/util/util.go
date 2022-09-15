/*
Copyright 2021 Adevinta
*/

package util

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"strconv"
	"strings"
	"time"

	// This package is intended to be used by tests in other packages so they don't have to interact
	// directly with the db so makes sense to import the driver here.
	_ "github.com/lib/pq"
)

const (
	defaultDBName        = "postgres"
	dialect              = "postgres"
	defaultFlywayVersion = "7"
)

type connStr struct {
	Host     string
	User     string
	Password string
	Dbname   string // nolint
	Port     string
	Sslmode  string
}

func (c *connStr) UnmarshalText(text []byte) error {
	var e reflect.Value
	m, err := parseConnStr(string(text))
	if err != nil {
		return err
	}
	e = reflect.ValueOf(c).Elem()
	for k, v := range m {
		name := strings.ToUpper(string([]byte{k[0]})) + k[1:]
		f := e.FieldByName(name)
		// if the field does not exists IsValid returns false.
		if !f.IsValid() {
			continue
		}
		f.SetString(v)
	}
	return nil
}

func (c *connStr) MarshalText() ([]byte, error) {
	e := reflect.ValueOf(c).Elem()
	t := e.Type()
	parts := []string{}
	for i := 0; i < t.NumField(); i++ {
		f := e.Field(i)
		name := strings.ToLower(t.Field(i).Name)
		val := f.Interface()
		strVal, ok := val.(string)
		if !ok {
			return nil, errors.New("field is not a a string")
		}
		if strVal == "" {
			continue
		}
		part := strings.Join([]string{name, strVal}, "=")
		parts = append(parts, part)
	}
	return []byte(strings.Join(parts, " ")), nil
}

func parseConnStr(conn string) (map[string]string, error) {
	parts := strings.Fields(conn)
	res := map[string]string{}
	for _, p := range parts {
		params := strings.Split(p, "=")
		if len(params) != 2 {
			return nil, errors.New("InvalidConnstr")
		}
		res[params[0]] = params[1]
	}
	return res, nil
}

// RunFlywayCmd FlayWay command on by using th current,
func RunFlywayCmd(conn, migrationsDir, flywayCommand string) error {
	c := &connStr{}
	err := c.UnmarshalText([]byte(conn))
	if err != nil {
		return err
	}
	flywayVersion := defaultFlywayVersion
	if value, ok := os.LookupEnv("FLYWAY_VERSION"); ok {
		flywayVersion = value
	}
	addr := fmt.Sprintf("postgresql://%s:%s/%s", c.Host, c.Port, c.Dbname)
	cmdName := "docker"
	cmdArgs := []string{
		"run",
		"--net=host",
		"-v",
		migrationsDir + ":/flyway/sql",
		"flyway/flyway:" + flywayVersion + "-alpine",
		"-user=" + c.User,
		"-password=" + c.Password,
		"-url=jdbc:" + addr,
		"-baselineOnMigrate=true",
		"-cleanDisabled=false",
		flywayCommand}

	cmd := exec.Command(cmdName, cmdArgs...)
	cmd.Env = os.Environ()
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("Error executing flyway command, command output:\n%s.\n Error:\n %s", output, err)
	}
	return nil
}

func EnsureDB(conn string) (bool, error) {
	c := &connStr{}
	err := c.UnmarshalText([]byte(conn))
	if err != nil {
		return false, err
	}
	dbName := c.Dbname
	c.Dbname = defaultDBName
	connDefDB, err := c.MarshalText()
	if err != nil {
		return false, err
	}

	db, err := sql.Open(dialect, string(connDefDB))
	if err != nil {
		return false, err
	}
	defer db.Close() // nolint: errcheck
	r, err := db.Exec("select  * from pg_database where datname = $1", dbName)
	if err != nil {
		return false, err

	}
	affected, err := r.RowsAffected()
	if err != nil {
		return false, err
	}
	if affected != 1 {
		// Create the database.
		// The postgres driver doesn't support params in a query that creates a db.
		// We have to use string concatenation to build the statement but we are not vulnerable to a SQL injection because
		// this function should only be executed under a test and, in any case, the db name is defined in a constant.
		_, err := db.Exec(fmt.Sprintf("CREATE DATABASE \"%s\"", dbName))
		return false, err
	}
	return true, nil
}

func Str2Uint32(str string) (uint32, error) {
	n, err := strconv.ParseUint(str, 10, 32)
	if err != nil {
		return 0, err
	}
	return uint32(n), nil
}

func Ptr2Str(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func Str2Ptr(p string) *string {
	return &p
}

func Int2Ptr(i int) *int {
	return &i
}

// Ptr2Float returns the value passed in if it isn't nil.
// Returns 0 otherwise.
func Ptr2Float(val *float32) float32 {
	if val == nil {
		return 0
	}
	return *val
}

func Ptr2Time(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return *t
}

func Ptr2Int(i *int) int {
	if i == nil {
		return 0
	}
	return *i
}

func Bool2Ptr(b bool) *bool {
	return &b
}
