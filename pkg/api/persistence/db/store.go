/*
Copyright 2021 Adevinta
*/

package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"reflect"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"

	// Import postgres dialect
	_ "github.com/lib/pq"
	uuid "github.com/satori/go.uuid"

	"github.com/adevinta/errors"
)

const (
	dialect = "postgres"
)

// DB implements a 'low level' access methos for interacting with postgres as a json document store.
type DB struct {
	db *sqlx.DB
}

// NewDB returns a connection to a Postgres instance
func NewDB(pDialect, connectionString string) (DB, error) {
	store := DB{}
	if pDialect == "" {
		pDialect = dialect
	}

	db, err := sqlx.Connect(pDialect, connectionString)
	if err != nil {
		return store, err
	}
	// Try to fail the early if there is any problem with the connection to the
	// db.
	err = db.Ping()
	if err != nil {
		return store, err
	}
	store.db = db
	return store, nil
}

// Close close Store db connection
func (db DB) Close() error {
	return db.db.Close()
}

// InsertDocWithID Creates a new document.
func (db DB) InsertDocWithID(table string, id uuid.UUID, doc []byte) error {
	strExec := `INSERT INTO %s (id,data,created_at,updated_at) VALUES (?,?,?,?)`
	st := fmt.Sprintf(strExec, table)
	st = db.db.Rebind(st)
	d := time.Now()
	_, err := db.db.Exec(st, id, doc, d, d)
	return err
}

// InsertDoc Creates a new document returning the assigned id.
func (db DB) InsertDoc(table string, doc []byte) (int64, error) {
	strExec := `INSERT INTO %s (data) VALUES (?) RETURNING id`
	st := fmt.Sprintf(strExec, table)
	st = db.db.Rebind(st)
	res, err := db.db.Query(st, doc)
	if err != nil {
		return 0, ErrWithQueryAndParams(err, st, []interface{}{doc})
	}
	var id int64
	defer res.Close() //nolint
	if !res.Next() {
		err := fmt.Errorf("IDNotReturned") // nolint
		return 0, ErrWithQueryAndParams(err, st, []interface{}{doc})
	}
	err = res.Scan(&id)
	return id, err
}

// UpsertDocWithCondition Merges a document with the existing one depending on a condition.
// If the document does not exists returns and error. If it exists but does not meet the condition returns 0 rows affected.
// If exists and the condition is meet returns the number of rows affected.
func (db DB) UpsertDocWithCondition(table string, id uuid.UUID, doc []byte, condition string, params ...interface{}) (int64, error) {
	d := time.Now()
	st := `INSERT INTO %s VALUES (?,?,?,?)
		ON CONFLICT ON CONSTRAINT %s_pkey
		DO UPDATE SET
		data = %s.data || ?, updated_at = ?`
	if condition != "" {
		st = st + " WHERE %s "
		st = fmt.Sprintf(st, table, table, table, condition)
	} else {
		st = fmt.Sprintf(st, table, table, table)
	}

	st = db.db.Rebind(st)
	args := []interface{}{id, doc, d, d, doc, d}
	args = append(args, params...)

	res, err := db.db.Exec(st, args...)
	if err != nil {
		return 0, ErrWithQueryAndParams(err, st, args)
	}
	return res.RowsAffected()
}

// UpsertChildDocWithCondition adds or updates new document as child of an existing one
// protecting the update with a condition.
func (db DB) UpsertChildDocWithCondition(table string, parentID, id uuid.UUID, doc []byte, condition string, params ...interface{}) (int64, error) {
	d := time.Now()
	strExec := `INSERT INTO %s VALUES (?,?,?,?,?)
		ON CONFLICT ON CONSTRAINT %s_pkey
		DO UPDATE SET
		data = %s.data || ?, updated_at = ?
		WHERE %s`
	st := fmt.Sprintf(strExec, table, table, table, condition)
	st = db.db.Rebind(st)
	args := []interface{}{id, parentID, doc, d, d, doc, d}
	args = append(args, params...)
	res, err := db.db.Exec(st, args...)
	if err != nil {
		return 0, ErrWithQueryAndParams(err, st, args)
	}

	count, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	return count, nil
}

// CreateChildDoc inserts a new weak entity in a given table.
func (db DB) CreateChildDoc(table string, parentID uuid.UUID, doc []byte) (int64, error) {
	d := time.Now()
	strExec := `INSERT INTO %s(parent_id,data) VALUES (?,?) RETURNING id`
	st := fmt.Sprintf(strExec, table)
	st = db.db.Rebind(st)
	res, err := db.db.Query(st, parentID, doc)
	if err != nil {
		return 0, ErrWithQueryAndParams(err, st, []interface{}{parentID, d})
	}
	var id int64
	defer res.Close() //nolint
	if !res.Next() {
		err := fmt.Errorf("IDNotReturned") //nolint
		return 0, ErrWithQueryAndParams(err, st, []interface{}{parentID, d})
	}
	err = res.Scan(&id)
	return id, err
}

// DeleteChildDocs deletes all the docs with the given parent id.
func (db DB) DeleteChildDocs(table string, parentID uuid.UUID) error {
	strExec := `DELETE FROM %s WHERE parent_id = ?`
	st := fmt.Sprintf(strExec, table)
	st = db.db.Rebind(st)
	_, err := db.db.Exec(st, parentID)
	return err
}

// IncrFieldDoc updates a document that belongs to a parent document.
func (db DB) IncrFieldDoc(table string, id uuid.UUID, field string) (int64, error) {
	strExec := `UPDATE %s SET data =  data || ('{"%s": ' || ((data->>'%s')::int + 1) || '}')::jsonb  WHERE id = ?`
	st := fmt.Sprintf(strExec, table, field, field)
	st = db.db.Rebind(st)
	res, err := db.db.Exec(st, id)
	if err != nil {
		return 0, err
	}
	count, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	return count, nil
}

// UpdateDoc updates a document with a given id, using the given expression
func (db DB) UpdateDoc(table string, parentID, id uuid.UUID, path []byte, partialDoc []byte) (int64, error) {
	strExec := `UPDATE %s SET data = jsonb_set(data, ?,?, true) WHERE id = ? AND parent_id = ?`
	st := fmt.Sprintf(strExec, table)
	st = db.db.Rebind(st)
	res, err := db.db.Exec(st, path, partialDoc, id)
	if err != nil {
		return 0, err
	}
	count, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	return count, nil
}

// UpsertChildDoc adds or updates new document as a child of an existing one.
func (db DB) UpsertChildDoc(table string, parentID, id uuid.UUID, doc []byte) error {
	d := time.Now()
	strExec := `INSERT INTO %s VALUES (?,?,?,?,?)
		ON CONFLICT ON CONSTRAINT %s_pkey
		DO UPDATE SET
		data = ?, updated_at = ?`
	st := fmt.Sprintf(strExec, table, table)
	st = db.db.Rebind(st)
	_, err := db.db.Exec(st, parentID, id, doc, d, d, doc, d)
	return err
}

// GetChildDoc gets an existing child document from database
func (db DB) GetChildDoc(table string, parentID, id uuid.UUID) ([]byte, error) {
	strExec := `SELECT data FROM %s WHERE parent_id = ? and id = ?`
	st := fmt.Sprintf(strExec, table)
	st = db.db.Rebind(st)
	res, err := db.db.Query(st, parentID, id)
	if err != nil {
		return nil, err
	}
	defer res.Close() // nolint
	data := []byte{}
	if !res.Next() {
		return data, errors.NotFound(nil)
	}
	err = res.Scan(&data)
	return data, err
}

// CountDocsWithCondition returns the number of documents that meet the given
// where condition.
func (db DB) CountDocsWithCondition(table, condition string, params ...interface{}) (int64, error) {
	strExec := `SELECT COUNT(*) FROM %s WHERE %s`
	st := fmt.Sprintf(strExec, table, condition)
	st = db.db.Rebind(st)
	res, err := db.db.Query(st, params...)
	if err != nil {
		return 0, ErrWithQueryAndParams(err, st, params)
	}
	defer res.Close() // nolint
	if !res.Next() {
		return 0, errors.NotFound(nil)
	}
	var count int64
	err = res.Scan(&count)
	if err != nil {
		return 0, err
	}
	return count, nil
}

// GetParentIDDoc gets the parent id from a given ChildID
func (db DB) GetParentIDDoc(table string, childID uuid.UUID) (uuid.UUID, error) {
	strExec := `SELECT parent_id FROM %s WHERE id = ?`
	st := fmt.Sprintf(strExec, table)
	st = db.db.Rebind(st)
	res, err := db.db.Query(st, childID)
	if err != nil {
		return uuid.Nil, err
	}
	defer res.Close() // nolint
	if !res.Next() {
		return uuid.Nil, errors.NotFound(nil)
	}
	var id uuid.UUID
	err = res.Scan(&id)
	return id, err
}

// GetChildDocsStatsForField gets the stats of all the child documents belonging
// to a given parentID. The type of the field must be marshalable into a string
// by the scan method of the postgres driver.
func (db DB) GetChildDocsStatsForField(table, field string, parentID uuid.UUID) (map[string]int, error) {
	strExec := `SELECT count(*) as count, data ->> '%s' as %s FROM %s WHERE parent_id = ? GROUP BY data ->> '%s'`
	st := fmt.Sprintf(strExec, field, field, table, field)
	st = db.db.Rebind(st)
	res, err := db.db.Query(st, parentID)
	if err != nil {
		sErr := ErrWithQueryAndParamsP(err, st, field, parentID, field)
		return nil, sErr
	}
	stats := make(map[string]int)
	defer res.Close() // nolint
	for res.Next() {
		var (
			count int
			val   *string
		)
		err = res.Scan(&count, &val)
		if err != nil {
			return nil, err
		}
		var vstat string
		if val != nil {
			vstat = *val
		} else {
			vstat = ""
		}
		stats[vstat] = count
	}
	return stats, nil
}

// GetAllDocs gets all documents for a given table.
func (db DB) GetAllDocs(table string) ([][]byte, error) {
	return db.GetAllDocsWithLimit(table, 0, 0)
}

// GetAllDocsWithLimit returns all documents for a given table applying the given offset and limit.
func (db DB) GetAllDocsWithLimit(table string, offset, limit uint32) ([][]byte, error) {
	args := []interface{}{}
	strExec := "SELECT data FROM %s ORDER BY created_at DESC"
	if offset != 0 {
		strExec += " OFFSET ?"
		args = append(args, offset)
	}
	if limit != 0 {
		strExec += " LIMIT ?"
		args = append(args, limit)
	}
	st := fmt.Sprintf(strExec, table)
	st = db.db.Rebind(st)
	res, err := db.db.Query(st, args...)
	if err != nil {
		return nil, err
	}
	defer res.Close() // nolint
	datas := [][]byte{}
	for res.Next() {
		data := []byte{}
		err = res.Scan(&data)
		if err != nil {
			return [][]byte{}, err
		}
		datas = append(datas, data)
	}
	return datas, err
}

// GetChildDocs gets all the child documents of a given parent.
func (db DB) GetChildDocs(table string, parentID uuid.UUID) ([][]byte, error) {
	strExec := `SELECT data FROM %s WHERE parent_id = ?`
	st := fmt.Sprintf(strExec, table)
	st = db.db.Rebind(st)
	res, err := db.db.Query(st, parentID)
	if err != nil {
		return nil, err
	}
	defer res.Close() // nolint
	datas := [][]byte{}
	for res.Next() {
		data := []byte{}
		err = res.Scan(&data)
		if err != nil {
			return [][]byte{}, err
		}
		datas = append(datas, data)
	}
	return datas, err
}

// GetChildDocsWithCondition gets all the child documents for a given parent and condition.
func (db DB) GetChildDocsWithCondition(table string, parentID uuid.UUID, cond string, params ...interface{}) ([][]byte, error) {
	strExec := `SELECT data FROM %s WHERE parent_id = ? AND %s`
	st := fmt.Sprintf(strExec, table, cond)
	st = db.db.Rebind(st)
	queryParams := []interface{}{parentID}
	queryParams = append(queryParams, params...)
	res, err := db.db.Query(st, queryParams...)
	if err != nil {
		return nil, err
	}
	defer res.Close() // nolint
	datas := [][]byte{}
	for res.Next() {
		data := []byte{}
		err = res.Scan(&data)
		if err != nil {
			return [][]byte{}, err
		}
		datas = append(datas, data)
	}
	return datas, err
}

// GetDocByID gets a document given its id.
func (db DB) GetDocByID(table string, id uuid.UUID) ([]byte, error) {
	st := `SELECT data FROM %s where id = ?`
	st = fmt.Sprintf(st, table)
	st = db.db.Rebind(st)

	res, err := db.db.Query(st, id)
	if err != nil {
		return nil, err
	}
	defer res.Close() // nolint
	data := []byte{}
	if !res.Next() {
		return data, errors.NotFound(nil)
	}
	err = res.Scan(&data)
	return data, err
}

func (db DB) InsertChildDocIfNotExists(table string, parentID uuid.UUID, childID uuid.UUID, index string, data []byte) (string, error) {
	var err error
	d := time.Now()
	q := `
	WITH  q as (
    SELECT * FROM %s
	WHERE parent_id = ? and parent_index = ?
	),
	c AS (
      INSERT INTO %s (id, parent_id, parent_index, data, created_at, updated_at)
      SELECT ?, ?, ?, ?, ?, ?
      WHERE NOT EXISTS (SELECT 1 FROM q)
      RETURNING *
    )
    SELECT id::text FROM c
    UNION ALL
	SELECT id::text FROM q`

	st := fmt.Sprintf(q, table, table)
	st = db.db.Rebind(st)
	res, err := db.db.Query(st, parentID, index, childID, parentID, index, data, d, d)
	if err != nil {
		return "", err
	}
	defer res.Close() // nolint
	if !res.Next() {
		return "", errors.Database(fmt.Errorf("unexpected no result running creating child doc"))
	}
	var id string
	err = res.Scan(&id)
	if err != nil {
		return "", err
	}
	return id, err
}

// GetDocsByField gets all documents that have a field in the specified path
// with a given value. The results are sorted by creation time.
func (db DB) GetDocsByField(table string, value string, path ...interface{}) ([][]byte, error) {
	return db.GetDocsByFieldLimit(table, value, 0, 0, path...)
}

// GetDocsByFieldLimit gets all documents that have a field in the specified
// path with a given value. The results are sorted by the specified field and
// limited to the specified number of results. if limit the numbers of results
// is outbounded. The functions always returns the results sorted by creation
// time.
func (db DB) GetDocsByFieldLimit(table string, value string, offset, limit uint32, path ...interface{}) ([][]byte, error) {
	var params, st string
	// TODO if an index is created in the table for a top level field in json
	// column data we need to use the -> operator to allow postgres to use that
	// index. As this operator, and the index, only works with a top level field
	// in the json, we use it when the path param is of length 1, otherwise we use
	// the function jsonb_extract_path which will not use any index.
	if len(path) > 1 {
		strExec := `SELECT data FROM %s WHERE jsonb_extract_path(data,%s) = ?`
		var parts = []string{}
		for i := 0; i < len(path); i++ {
			parts = append(parts, "?")
		}
		params = strings.Join(parts, ",")
		st = fmt.Sprintf(strExec, table, params)
	} else if len(path) == 1 {
		st = fmt.Sprintf(`SELECT data FROM %s WHERE data -> ? = ?`, table)
	}

	args := []interface{}{}
	args = append(args, path...)
	args = append(args, value)
	st = st + " ORDER BY created_at DESC"
	if offset != 0 {
		st += " OFFSET ?"
		args = append(args, offset)
	}
	if limit != 0 {
		st += " LIMIT ?"
		args = append(args, limit)
	}
	st = db.db.Rebind(st)
	res, err := db.db.Query(st, args...)
	if err != nil {
		sErr := ErrWithQueryAndParams(err, st, args)
		fmt.Print(sErr)
		return nil, sErr
	}
	defer res.Close() // nolint
	datas := [][]byte{}
	for res.Next() {
		data := []byte{}
		err = res.Scan(&data)
		if err != nil {
			return [][]byte{}, err
		}
		datas = append(datas, data)
	}
	return datas, err
}

// GetDocIDsWithCondition returns the ID's of the documents that maches the given condition.
func (db DB) GetDocIDsWithCondition(table, condition string, params ...interface{}) ([]string, error) {
	st := `SELECT ID::text FROM %s where %s`
	st = fmt.Sprintf(st, table, condition)
	st = db.db.Rebind(st)
	res, err := db.db.Query(st, params...)
	if err != nil {
		return nil, err
	}
	defer res.Close() // nolint
	var ids []string
	for res.Next() {
		var id string
		err = res.Scan(&id)
		if err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, err

}

// CreateDocumentWithID creates a document in the underlaying store
func (db DB) CreateDocumentWithID(id uuid.UUID, doc interface{}) error {
	tableName := reflect.TypeOf(doc).Name()
	if tableName == "" {
		return ErrAnonymousType
	}
	// By convention the name of the type is the singular form of table's name.
	tableName = tableName + "s"
	tableName = strings.ToLower(tableName)
	data, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	return db.InsertDocWithID(tableName, id, data)
}

// IncrDocumentField increases by 1 a field in the json data of the given document.
// The document and the field must already exist
func (db DB) IncrDocumentField(id uuid.UUID, doc interface{}, field string) error {
	tableName := reflect.TypeOf(doc).Name()
	if tableName == "" {
		return ErrAnonymousType
	}
	// By convention the name of the type is the singular form of table's name.
	tableName = tableName + "s"
	tableName = strings.ToLower(tableName)
	_, err := db.IncrFieldDoc(tableName, id, field)
	return err
}

// CreateDocument creates a document in the underlaying store.
// The doc parameter is only use the derive the name of the table to store the data.
func (db DB) CreateDocument(doc interface{}, data []byte) (int64, error) {
	tableName := reflect.TypeOf(doc).Name()
	if tableName == "" {
		return 0, ErrAnonymousType
	}
	// By convention the name of the type is the singular form of table's name.
	tableName = tableName + "s"
	tableName = strings.ToLower(tableName)
	return db.InsertDoc(tableName, data)
}

// DeleteChildDocuments deletes all the documents related to a given parent id.
func (db DB) DeleteChildDocuments(id uuid.UUID, doc interface{}) error {
	tableName := reflect.TypeOf(doc).Name()
	if tableName == "" {
		return ErrAnonymousType
	}
	// By convention the name of the type is the singular form of table's name.
	tableName = tableName + "s"
	tableName = strings.ToLower(tableName)
	return db.DeleteChildDocs(tableName, id)
}

// CreateChildDocument creates a child document in the underlaying store.
func (db DB) CreateChildDocument(id uuid.UUID, doc interface{}, data []byte) (int64, error) {
	tableName := reflect.TypeOf(doc).Name()
	if tableName == "" {
		return 0, ErrAnonymousType
	}
	// By convention the name of the type is the singular form of table's name.
	tableName = tableName + "s"
	tableName = strings.ToLower(tableName)
	return db.CreateChildDoc(tableName, id, data)
}

// UpsertDocument upserts a document in the underlaying store if a condition is meet.
func (db DB) UpsertDocument(id uuid.UUID, doc interface{}, condition string, args ...interface{}) (int64, error) {
	tableName := reflect.TypeOf(doc).Name()
	if tableName == "" {
		return 0, ErrAnonymousType
	}
	// By convention the name of the type is the singular form of table's name.
	tableName = tableName + "s"
	tableName = strings.ToLower(tableName)
	data, err := json.Marshal(doc)
	if err != nil {
		return 0, err
	}
	return db.UpsertDocWithCondition(tableName, id, data, condition, args...)
}

// UpsertChildDocumentWithData upserts a child document in the underlaying store if a condition is meet.
func (db DB) UpsertChildDocumentWithData(parentID, id uuid.UUID, doc interface{}, data []byte, condition string, args ...interface{}) (int64, error) {
	tableName := reflect.TypeOf(doc).Name()
	if tableName == "" {
		return 0, ErrAnonymousType
	}
	// By convention the name of the type is the singular form of table's name.
	tableName = tableName + "s"
	tableName = strings.ToLower(tableName)
	return db.UpsertChildDocWithCondition(tableName, parentID, id, data, condition, args...)
}

// CountDocumentsWithCondition retruns the number of documents that meet a given condition.
func (db DB) CountDocumentsWithCondition(doc interface{}, condition string, args ...interface{}) (int64, error) {
	tableName := reflect.TypeOf(doc).Name()
	if tableName == "" {
		return 0, ErrAnonymousType
	}
	// By convention the name of the type is the singular form of table's name.
	tableName = tableName + "s"
	tableName = strings.ToLower(tableName)
	return db.CountDocsWithCondition(tableName, condition, args...)
}

// GetAllDocsFromDocType returns the list of docs for the given doc type.
func (db DB) GetAllDocsFromDocType(doc interface{}) ([][]byte, error) {
	return db.GetAllDocsFromDocTypeWithLimit(doc, 0, 0)
}

// GetAllDocsFromDocTypeWithLimit returns the list of docs for the given doc type applying the given
// offset and limit parameters.
func (db DB) GetAllDocsFromDocTypeWithLimit(doc interface{}, offset, limit uint32) ([][]byte, error) {
	val := reflect.ValueOf(doc)
	tableName := reflect.Indirect(val).Type().Name()
	// By convention the name of the type is the singular form of the table's name in lower case.
	tableName = tableName + "s"
	tableName = strings.ToLower(tableName)
	return db.GetAllDocsWithLimit(tableName, offset, limit)
}

// GetDocByIDFromDocType returns a document given its id.
// the doc param must always be a pointer to a struct.
func (db DB) GetDocByIDFromDocType(doc interface{}, id uuid.UUID) error {
	val := reflect.ValueOf(doc)
	tableName := reflect.Indirect(val).Type().Name()
	// By convention the name of the type is the singular form of the table's name in lower case.
	tableName = tableName + "s"
	tableName = strings.ToLower(tableName)
	data, err := db.GetDocByID(tableName, id)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, doc)
}

// GetChildDocsFromDocType returns all child documents for a given parent ID
func (db DB) GetChildDocsFromDocType(doc interface{}, parentID uuid.UUID) ([][]byte, error) {
	val := reflect.ValueOf(doc)
	tableName := reflect.Indirect(val).Type().Name()
	// By convention the name of the type is the singular form of the table's name in lower case.
	tableName = tableName + "s"
	tableName = strings.ToLower(tableName)
	return db.GetChildDocs(tableName, parentID)

}

// GetChildDocsFromDocTypeWithCondition returns child documents for a given parent ID
// complying with a specific condition.
func (db DB) GetChildDocsFromDocTypeWithCondition(doc interface{}, parentID uuid.UUID, cond string, params ...interface{}) ([][]byte, error) {
	val := reflect.ValueOf(doc)
	tableName := reflect.Indirect(val).Type().Name()
	// By convention the name of the type is the singular form of the table's name in lower case.
	tableName = tableName + "s"
	tableName = strings.ToLower(tableName)
	return db.GetChildDocsWithCondition(tableName, parentID, cond, params...)
}

// GetChildDocsStatsFromDocType returns a document given its id.
// the doc param must always be a pointer to a struct.
func (db DB) GetChildDocsStatsFromDocType(doc interface{}, field string, parentID uuid.UUID) (map[string]int, error) {
	val := reflect.ValueOf(doc)
	tableName := reflect.Indirect(val).Type().Name()
	// By convention the name of the type is the singular form of the table's name in lower case.
	tableName = tableName + "s"
	tableName = strings.ToLower(tableName)
	return db.GetChildDocsStatsForField(tableName, field, parentID)
}

// GetDocsByFieldFromDocType returns an slice of documents with a given a value for a given field in data.
// the doc param must always be a pointer to a struct.
func (db DB) GetDocsByFieldFromDocType(doc interface{}, value string, path ...interface{}) ([][]byte, error) {
	val := reflect.ValueOf(doc)
	tableName := reflect.Indirect(val).Type().Name()
	// By convention the name of the type is the singular form of the table's name in lower case.
	tableName = tableName + "s"
	tableName = strings.ToLower(tableName)
	return db.GetDocsByField(tableName, value, path...)

}

// GetDocIDsWithCondFromDocType returns all the id's of the documents that
// satisfy a given condition.
func (db DB) GetDocIDsWithCondFromDocType(doc interface{}, condition string, params ...interface{}) ([]string, error) {
	val := reflect.ValueOf(doc)
	tableName := reflect.Indirect(val).Type().Name()
	// By convention the name of the type is the singular form of the table's name in lower case.
	tableName = tableName + "s"
	tableName = strings.ToLower(tableName)
	return db.GetDocIDsWithCondition(tableName, condition, params...)
}

// GetDocsByFieldLimitFromDocType returns an slice of documents with a given a value for a given field in data.
// The results are sorted by creation time and limited to the number of results specified by the limit param.
// The doc param must always be a pointer to a struct.
func (db DB) GetDocsByFieldLimitFromDocType(doc interface{}, value string, offset, limit uint32, path ...interface{}) ([][]byte, error) {
	val := reflect.ValueOf(doc)
	tableName := reflect.Indirect(val).Type().Name()
	// By convention the name of the type is the singular form of the table's name in lower case.
	tableName = tableName + "s"
	tableName = strings.ToLower(tableName)
	return db.GetDocsByFieldLimit(tableName, value, offset, limit, path...)
}

// InsertChildDocIfNotExistsFromDocType this function inserts a new child doc,
// or updates a current one if it has the same parent id and index than the
// given ones.
func (db DB) InsertChildDocIfNotExistsFromDocType(doc interface{}, parentID, id uuid.UUID, index string, data []byte) (string, error) {
	val := reflect.ValueOf(doc)
	tableName := reflect.Indirect(val).Type().Name()
	// By convention the name of the type is the singular form of the table's name in lower case.
	tableName = tableName + "s"
	tableName = strings.ToLower(tableName)
	return db.InsertChildDocIfNotExists(tableName, parentID, id, index, data)
}

// GetParentID returns the parent ID of the first row with the given childID.
func (db DB) GetParentID(childDoc interface{}, childID uuid.UUID) (uuid.UUID, error) {
	tableName := reflect.TypeOf(childDoc).Name()
	if tableName == "" {
		return uuid.Nil, ErrAnonymousType
	}
	// By convention the name of the type is the singular form of table's name.
	tableName = tableName + "s"
	tableName = strings.ToLower(tableName)
	return db.GetParentIDDoc(tableName, childID)
}

// Ping pings the underlaying db to check its connected and prepared to receive commands.
func (db DB) Ping() error {
	return db.db.Ping()
}

func (db DB) TryGetLock(id string) (*Lock, error) {
	h := fnv.New32()
	_, err := h.Write([]byte(id))
	if err != nil {
		return nil, err
	}
	n := h.Sum32()
	tx, err := db.db.DB.Begin()
	if err != nil {
		return nil, err
	}
	st := `SELECT pg_try_advisory_xact_lock(?)`
	st = db.db.Rebind(st)
	res, err := tx.Query(st, n)
	if err != nil {
		return nil, err
	}
	defer res.Close() // nolint
	var ret bool
	res.Next()
	err = res.Scan(&ret)
	return &Lock{Acquired: ret, ID: id, tx: tx}, err

}

func (db DB) ReleaseLock(l *Lock) error {
	if l == nil {
		return errors.Default("lock can not be nil")
	}
	return l.tx.Commit()
}

// Lock represents the result of trying to acquire an advisory lock.
type Lock struct {
	Acquired bool
	ID       string
	tx       *sql.Tx
}
