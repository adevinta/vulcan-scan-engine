/*
Copyright 2021 Adevinta
*/

package persistence

import (
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/adevinta/vulcan-scan-engine/pkg/api"
	"github.com/adevinta/vulcan-scan-engine/pkg/api/persistence/db"

	uuid "github.com/satori/go.uuid"
)

const (
	errNoInitChecksFinishedStr = `pq: null value in column "data" violates not-null constraint`
)

var (
	// ErrChecksFinishedNotInitialized is returned by the AddCheckAsFinished when trying to add
	// a check finished to its scan.
	ErrChecksFinishedNotInitialized = errors.New("field checks_finished is not initialized")
)

type ScansStore interface {
	CreateScan(id uuid.UUID, scan api.Scan) (int64, error)
	UpsertCheck(scanID, id uuid.UUID, check api.Check, updateStates []string) (int64, error)
	GetScans(offset, limit uint32) ([]api.Scan, error)
	GetScanChecks(scanID uuid.UUID) ([]api.Check, error)
	GetScanChecksByStatus(scanID uuid.UUID, status string) ([]api.Check, error)
	GetScanByID(id uuid.UUID) (api.Scan, error)
	GetScanStats(scanID uuid.UUID) (map[string]int, error)
	UpdateScan(id uuid.UUID, scan api.Scan, updateStates []string) (int64, error)
	GetScansByExternalID(ID string, offset, limit uint32) ([]api.Scan, error)
	GetCheckByID(id uuid.UUID) (api.Check, error)
	DeleteScanChecks(scanID uuid.UUID) error
	GetScanIDForCheck(ID uuid.UUID) (uuid.UUID, error)
	AddCheckAsFinished(checkID uuid.UUID) (int64, error)
	GetScanStatus(ID uuid.UUID) (api.Scan, error)
}

// Persistence implements ScansStore interface
// by using the underlying document store.
type Persistence struct {
	store db.DB
}

// NewPersistence creates and initializes a store.
func NewPersistence(s db.DB) Persistence {
	return Persistence{store: s}

}

// Close closes the underlaying connection to the store.
func (db Persistence) Close() error {
	return db.store.Close()
}

// CreateScan creates a new scan in  the database.
func (db Persistence) CreateScan(id uuid.UUID, scan api.Scan) (int64, error) {
	return db.store.UpsertDocument(id, scan, "")
}

// UpdateScan updates a scan in  the database. The data of the current scan in
// the db it is not replaced, but merged using json merge as is defined in the
// concatenate operation here:
// https://www.postgresql.org/docs/9.5/functions-json.html
func (db Persistence) UpdateScan(id uuid.UUID, scan api.Scan, updateStates []string) (int64, error) {
	condition := ""
	if len(updateStates) > 0 {
		condition = `NOT(jsonb_exists(scans.data,'status')) OR (scans.data->>'status') IN (`
		marks := []string{}
		for i := 0; i < len(updateStates); i++ {
			marks = append(marks, "?")
		}
		cond := strings.Join(marks, ",")
		condition = condition + cond + ")"
	}
	// TODO: It would be better to not reference the table name 'scans' in the condition.
	if scan.Progress != nil {
		pcondition := `( NOT(jsonb_exists(scans.data,'progress')) OR ? >= (scans.data->>'progress')::float )`
		if condition != "" {
			condition = pcondition + " AND (" + condition + ")"
		} else {
			condition = pcondition
		}
	}

	args := []interface{}{}
	if scan.Progress != nil {
		args = append(args, scan.Progress)
	}
	for _, v := range updateStates {
		args = append(args, interface{}(v))
	}
	count, err := db.store.UpsertDocument(id, scan, condition, args...)
	return count, err

}

// AddCheckAsFinished mark the given check as finished in the given scan by
// increasing the the number the field ChecksFinished in the giver scan. The
// operation is idempotent That is if for a given scanID and CheckID the
// operation will only increase the field ChecksFinished of the scan one time,
// no matters the number of times it is called.
func (db Persistence) AddCheckAsFinished(checkID uuid.UUID) (int64, error) {
	query := `
	WITH if_check_was_not_added AS(
    SELECT parent_id as scan_id FROM checks WHERE  checks.id=? AND
    data->'check_added' is NULL
    ),
   add_check AS (
   UPDATE scans SET data =  data || ('{"checks_finished": ' || ((data->>'checks_finished')::int + 1) || '}')::jsonb
   FROM if_check_was_not_added as scan_to_add
   WHERE scans.id = scan_to_add.scan_id
   RETURNING scans.id
   )
   UPDATE checks SET data = data || '{"check_added":true}', updated_at=?
   FROM add_check as scan
   WHERE checks.id=?
	`
	now := time.Now()
	n, err := db.store.ExecRaw(query, checkID, now, checkID)
	if err != nil && err.Error() == errNoInitChecksFinishedStr {
		err = ErrChecksFinishedNotInitialized
	}
	return n, err
}

// UpsertCheck adds or updates a check of a given scan.
func (db Persistence) UpsertCheck(scanID, id uuid.UUID, check api.Check, updateStates []string) (int64, error) {
	now := time.Now()
	condition := ""

	if len(updateStates) > 0 {
		condition = `NOT(jsonb_exists(checks.data,'status')) OR (checks.data->>'status') IN (`
		marks := []string{}
		for i := 0; i < len(updateStates); i++ {
			marks = append(marks, "?")
		}
		cond := strings.Join(marks, ",")
		condition = condition + cond + ")"
	}
	// TODO: It would be better to not reference the table name 'checks' in the condition.
	if check.Progress != nil {
		pcondition := ` (? >= (checks.data->>'progress')::float OR NOT(jsonb_exists(checks.data,'progress')))`
		if condition != "" {
			condition = pcondition + " AND (" + condition + ")"
		} else {
			condition = pcondition
		}
	}
	args := []interface{}{}
	if check.Progress != nil {
		args = append(args, check.Progress)
	}
	for _, v := range updateStates {
		args = append(args, interface{}(v))
	}

	check.UpdatedAt = &now
	data, err := json.Marshal(check)
	if err != nil {
		return 0, err
	}
	check.Data = data

	return db.store.UpsertChildDocumentWithData(scanID, id, check, check.Data, condition, args...)
}

// GetScans returns the list of scans.
func (db Persistence) GetScans(offset, limit uint32) ([]api.Scan, error) {
	datas, err := db.store.GetAllDocsFromDocTypeWithLimit(api.Scan{}, offset, limit)
	if err != nil {
		return []api.Scan{}, err
	}
	res := []api.Scan{}
	for _, v := range datas {
		c := api.Scan{}
		err := json.Unmarshal(v, &c)
		if err != nil {
			return []api.Scan{}, err
		}
		res = append(res, c)
	}
	return res, nil
}

// GetScanByID returns a scan given its ID.
func (db Persistence) GetScanByID(id uuid.UUID) (api.Scan, error) {
	s := api.Scan{}
	err := db.store.GetDocByIDFromDocType(&s, id)
	return s, err
}

// GetScanChecks returns all checks of a scan.
func (db Persistence) GetScanChecks(scanID uuid.UUID) ([]api.Check, error) {
	datas, err := db.store.GetChildDocsFromDocType(api.Check{}, scanID)
	if err != nil {
		return []api.Check{}, err
	}
	res := []api.Check{}
	for _, v := range datas {
		c := api.Check{}
		err := json.Unmarshal(v, &c)
		if err != nil {
			return []api.Check{}, err
		}
		c.Data = v
		res = append(res, c)
	}
	return res, nil
}

// GetScanChecksByStatus returns all checks of a scan that have the given status.
func (db Persistence) GetScanChecksByStatus(scanID uuid.UUID, status string) ([]api.Check, error) {
	cond := "checks.data->>'status' = ?"
	datas, err := db.store.GetChildDocsFromDocTypeWithCondition(api.Check{}, scanID, cond, status)
	if err != nil {
		return []api.Check{}, err
	}
	res := []api.Check{}
	for _, v := range datas {
		c := api.Check{}
		err := json.Unmarshal(v, &c)
		if err != nil {
			return []api.Check{}, err
		}
		c.Data = v
		res = append(res, c)
	}
	return res, nil
}

// DeleteScanChecks deletes all the checks of a given scan.
func (db Persistence) DeleteScanChecks(scanID uuid.UUID) error {
	return db.store.DeleteChildDocuments(scanID, api.Check{})
}

// GetCheckByID returns the check for the given ID.
func (db Persistence) GetCheckByID(id uuid.UUID) (api.Check, error) {
	c := api.Check{}
	err := db.store.GetDocByIDFromDocType(&c, id)
	return c, err
}

// GetScanStatus returns a scan struct with only the fields: Status, CheckCount, ChecksFinished
// filled.
func (db Persistence) GetScanStatus(ID uuid.UUID) (api.Scan, error) {
	query := `SELECT data->>'status' as status, 
	data->'checks_finished' as checks_finished,
	data->'check_count', data->>'tag', data->>'external_id' as check_count FROM scans WHERE id=?`
	s := new(api.Scan)
	var (
		count, finished int
		status          string
		tag             string
		externalID      string
	)
	rest := []interface{}{&status, &finished, &count, &tag, &externalID}
	err := db.store.QueryRaw(query, rest, ID)
	if err != nil {
		return api.Scan{}, err
	}
	s.ID = ID
	s.Status = &status
	s.CheckCount = &count
	s.ChecksFinished = &finished
	s.Tag = &tag
	s.ExternalID = &externalID
	return *s, nil
}

// GetScanStats returns the number of checks by status for the given scan.
func (db Persistence) GetScanStats(scanID uuid.UUID) (map[string]int, error) {
	return db.store.GetChildDocsStatsFromDocType(api.Check{}, "status", scanID)
}

// GetScansByExternalID returns scans with a given ExternalID applying the given offset and limit.
func (db Persistence) GetScansByExternalID(ID string, offset, limit uint32) ([]api.Scan, error) {
	var (
		err   error
		datas [][]byte
		scan  api.Scan
	)
	if offset == 0 && limit == 0 {
		datas, err = db.store.GetDocsByFieldFromDocType(&scan, `"`+ID+`"`, `external_id`)
	} else {
		datas, err = db.store.GetDocsByFieldLimitFromDocType(&scan, `"`+ID+`"`, offset, limit, `external_id`)
	}
	if err != nil {
		return []api.Scan{}, err
	}
	res := []api.Scan{}
	for _, v := range datas {
		c := api.Scan{}
		err := json.Unmarshal(v, &c)
		if err != nil {
			return []api.Scan{}, err
		}
		res = append(res, c)
	}
	return res, nil
}

// InsertCheckIfNotExists looks if a check exists in the database with the same
// ScanID and ScanIndex than the passed check. If it exists, the function
// returns the id of the check in the database. If it does not exist the
// function inserts the passed check and returns the id of the inserted check
// id.
func (db Persistence) InsertCheckIfNotExists(c api.Check) (string, error) {
	if c.ScanIndex == nil {
		return "", errors.New("ScanIndex can not be nil")
	}
	index := *c.ScanIndex
	id, err := uuid.FromString(c.ID)
	if err != nil {
		return "", err
	}
	sID, err := uuid.FromString(c.ScanID)
	if err != nil {
		return "", err
	}
	data, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	c.Data = data
	return db.store.InsertChildDocIfNotExistsFromDocType(c, sID, id, index, c.Data)
}

func (db Persistence) GetScanIDForCheck(ID uuid.UUID) (uuid.UUID, error) {
	c := api.Check{}
	return db.store.GetParentID(c, ID)
}

func (db Persistence) GetCreatingScans() ([]string, error) {
	s := api.Scan{}
	condition := `(data->'checks_created' is not null AND data->'check_count' <> data->'checks_created' AND  data->>'status' = 'RUNNING')`
	return db.store.GetDocIDsWithCondFromDocType(s, condition)
}

func (db Persistence) TryLockScan(id string) (*db.Lock, error) {
	return db.store.TryGetLock(id)
}

func (db Persistence) ReleaseScanLock(l *db.Lock) error {
	return db.store.ReleaseLock(l)
}
