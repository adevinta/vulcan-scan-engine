package persistence

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/adevinta/vulcan-scan-engine/pkg/api"
	"github.com/adevinta/vulcan-scan-engine/pkg/api/persistence/db"
	uuid "github.com/satori/go.uuid"
)

// Persistence implements a
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

// UpsertCheck adds or updates a check of a given scan.
func (db Persistence) UpsertCheck(scanID, id uuid.UUID, check api.Check, updateStates []string) (int64, error) {
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

	return db.store.UpsertChildDocumentWithData(scanID, id, check, check.Data, condition, args...)
}

// GetScanByID returns a scan given its ID.
func (db Persistence) GetScanByID(id uuid.UUID) (api.Scan, error) {
	s := api.Scan{}
	err := db.store.GetDocByIDFromDocType(&s, id)
	return s, err
}

// GetScanChecks returns all the checks of a scan.
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

// DeleteScanChecks deletes all the checks of a given scan.
func (db Persistence) DeleteScanChecks(scanID uuid.UUID) error {
	return db.store.DeleteChildDocuments(scanID, api.Check{})
}

// GetChecksStatusStats the number of checks belonging to a scan that are in a
// concrete status.
func (db Persistence) GetChecksStatusStats(scanID uuid.UUID) (map[string]int, error) {
	return db.store.GetChildDocsStatsFromDocType(api.Check{}, "status", scanID)
}

// GetScansByExternalIDWithLimit returns all the scans with a given ExternalID
func (db Persistence) GetScansByExternalIDWithLimit(ID string, limit *uint32) ([]api.Scan, error) {
	var (
		err   error
		datas [][]byte
		scan  api.Scan
	)
	if limit == nil {
		datas, err = db.store.GetDocsByFieldFromDocType(&scan, `"`+ID+`"`, `external_id`)
	} else {
		datas, err = db.store.GetDocsByFieldLimitFromDocType(&scan, `"`+ID+`"`, *limit, `external_id`)
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
