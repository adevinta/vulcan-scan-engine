/*
Copyright 2021 Adevinta
*/

package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/adevinta/errors"
	"github.com/google/go-cmp/cmp"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	_ "github.com/lib/pq"
	uuid "github.com/satori/go.uuid"

	"github.com/adevinta/vulcan-scan-engine/pkg/api"
	"github.com/adevinta/vulcan-scan-engine/pkg/testutil"
)

const (
	fixtures  = "testdata/store_test_fixtures"
	dbDirPath = "../../../../db/" // nolint
	dbName    = "storetestdb"
)

type fixtureScan struct {
	ID     string
	Checks map[string]string
}

var (
	connStr      = fmt.Sprintf(testutil.DBConnString, testutil.TestDBUser, testutil.TestDBPassword, dbName)
	fixtureScans = map[string]fixtureScan{
		"Scan1": {
			ID: "c3b5af18-4e1d-11e8-9c2d-fa7ae01bbebc",
			Checks: map[string]string{
				"Check1": "c3b5af18-4e1d-11e8-9c2d-fa7ae01bbeaa",
				"Check2": "c3b5afd8-4e1d-11d8-9c2d-fa7ae01bbeaa",
			},
		},
		"Scan2": {
			ID: "a3b5af18-4e1d-11e8-9c2d-fa7ae01bbebc",
			Checks: map[string]string{
				"Check3": "c3b5bfe8-4e1d-11d8-9c2d-fa7ae01bbeaa",
			},
		},
		"Scan3": {
			ID:     "a3b5af18-4e1d-11e8-9c2d-fa7ae01bbeba",
			Checks: map[string]string{},
		},
		"Scan4": {
			ID:     "a3b5af18-4e2d-22e8-9c2d-fa7ad01bbeba",
			Checks: map[string]string{},
		},
		"Scan5": {
			ID: "a3b5ca18-4e2d-22e8-9c2d-fa7ad01bbeba",
			Checks: map[string]string{
				"Check4": "b3b5ca18-4e2d-22e8-9c2d-fa7ad01bbeba",
				"Check5": "a3b5ca18-4e2d-22e8-9c2d-fa7ad03bbfaa",
			},
		},
		"Scan2Delete": {
			ID: "e5699669-b212-44b2-8b30-32e1d6d14f5c",
			Checks: map[string]string{
				"Check1Scan2Delete": "e750dfb0-c5ab-4133-941f-cfd26ec4db6c",
				"Check2Scan2Delete": "f4cae742-01e8-44f3-83b9-e5d5d7934f28",
			},
		},
	}
	nonExistentScanID = "a3c6bf18-4e1d-11e8-9c2a-fa7ae01bbeba"
)

func TestMain(m *testing.M) {
	var res int
	defer func() {
		os.Exit(res)
	}()
	err := testutil.SetupDB(dbDirPath, dbName)
	if err != nil {
		fmt.Printf("error setting up tests: %s", err.Error())
		res = 1
		return
	}
	err = testutil.LoadFixtures(fixtures, dbName)
	if err != nil {
		fmt.Printf("error setting up tests: %s", err.Error())
		res = 1
		return
	}
	res = m.Run()
}

func TestVulcanitoStore_InsertDoc(t *testing.T) {
	type args struct {
		table string
		doc   sql.RawBytes
		id    uuid.UUID
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "HappyPath",
			args: args{
				table: "scans",
				doc:   []byte(`{"name":"works"}`),
				id:    uuid.FromStringOrNil("c3b5af18-4e1d-11e8-9c2d-fa7ae02bbebc"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, err := NewDB(dialect, connStr)
			if err != nil {
				t.Fatal(err)
			}
			err = db.InsertDocWithID(tt.args.table, tt.args.id, tt.args.doc)
			if (err != nil) != tt.wantErr {
				t.Errorf("VulcanitoStore.InsertDoc() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func UUIDFromString(v string) uuid.UUID {
	ret, _ := uuid.FromString(v)
	return ret
}

func TestStore_UpsertDocWithCondition(t *testing.T) {
	type args struct {
		table     string
		doc       []byte
		condition string
		params    []interface{}
		id        uuid.UUID
	}
	tests := []struct {
		name      string
		args      args
		wantErr   error
		wantDoc   []byte
		wantCount int64
	}{
		{
			name: "UpdatesDocWhenConditionIsMeet",
			args: args{
				table:     "scans",
				id:        UUIDFromString(fixtureScans["Scan2"].ID),
				condition: `(scans.data->>'status') = ?`,
				params:    []interface{}{"RUNNING"},
				doc:       []byte(`{"progress":1, "status":"FINISHED"}`),
			},
			wantDoc:   []byte(`{"status": "FINISHED", "trigger": "a trigger", "progress": 1}`),
			wantCount: 1,
		},
		{
			name: "DoesNotUpdateDocWhenConditionIsNotMeet",
			args: args{
				table:     "scans",
				id:        UUIDFromString(fixtureScans["Scan3"].ID),
				condition: `(scans.data->>'status') = ?`,
				params:    []interface{}{"RUNNING"},
				doc:       []byte(`{"progress":0.5, "status":"RUNNING"}`),
			},
			wantDoc:   []byte(`{"status": "FINISHED", "trigger": "a trigger", "progress": 1.0}`),
			wantCount: 0,
		},
		{
			name: "CreatesADocThatDoesNotExist",
			args: args{
				table: "scans",
				id:    UUIDFromString(nonExistentScanID),
				doc:   []byte(`{"progress":0.5, "status":"RUNNING"}`),
			},
			wantDoc:   []byte(`{"progress":0.5, "status":"RUNNING"}`),
			wantCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, err := NewDB(dialect, connStr)
			if err != nil {
				t.Fatal(err)
			}
			count, err := db.UpsertDocWithCondition(tt.args.table, tt.args.id, tt.args.doc, tt.args.condition, tt.args.params...)
			if testutil.ErrToStr(err) != testutil.ErrToStr(tt.wantErr) {
				t.Errorf("Store.UpdateDoc() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if count != tt.wantCount {
				t.Errorf("got count != want count. got %d, want %d", count, tt.wantCount)
				return
			}
			if tt.wantDoc != nil {
				got, err := db.GetDocByID(tt.args.table, tt.args.id)
				if err != nil {
					t.Errorf("Error checking updated document. Err : %v", err)
					return
				}
				gotDoc := mustDecodeToMap(got)
				wantDoc := mustDecodeToMap(tt.wantDoc)
				diff := cmp.Diff(gotDoc, wantDoc)
				if diff != "" {
					t.Fatalf("got != want. Diff:\n %s. Got: %+v", diff, gotDoc)
				}

			}
		})
	}
}

type Scan struct {
	ID              string          `json:"id,omitempty"`
	Status          string          `json:"status"`
	StartTime       time.Time       `json:"start_time"`
	EndTime         time.Time       `json:"endtime_time"`
	Progress        float32         `json:"progress"`
	Trigger         string          `json:"trigger"`
	TargetGroup     TargetGroup     `json:"target_group"`
	ChecktypesGroup ChecktypesGroup `json:"check_types_groups"`
}
type TargetGroup struct {
	Name    string   `json:"name"`
	Options string   `json:"options"`
	Targets []Target `json:"targets"`
}

// Target represents a target of a scan.
type Target struct {
	Identifier string `json:"identifier"`
	Options    string `json:"options"`
}

// ChecktypesGroup represents a group of checktypes that are used to generated the checks
// of a scan.
type ChecktypesGroup struct {
	Name       string      `json:"name"`
	Checktypes []Checktype `json:"checktypes"`
}

// Checktype defines one kind of check that belongs to a ChecktypesGroup.
type Checktype struct {
	Name    string `json:"identifier"`
	Options string `json:"options"`
}

func TestStore_CreateDocument(t *testing.T) {
	type args struct {
		doc interface{}
		id  uuid.UUID
	}
	tests := []struct {
		name    string
		args    args
		wantErr error
	}{
		{
			name: "HappyPath",
			args: args{
				id: UUIDFromString("c3b5af18-4e1d-11e8-9c2d-fa7ae01bbabc"),
				doc: Scan{
					Trigger: "Daily Pre Scan",
					ChecktypesGroup: ChecktypesGroup{
						Name: "OneGroup",
						Checktypes: []Checktype{
							{
								Name:    "onecheck",
								Options: `{"port":8080}`,
							},
						},
					},
					TargetGroup: TargetGroup{
						Name:    "OneGroup",
						Options: `{"port:"8080"}`,
						Targets: []Target{
							{Identifier: "localhost", Options: `{"port":"8180"}`},
						},
					},
				},
			},
		},

		{
			name: "DoesNotCreateDocumentWithSameID",
			args: args{
				id: UUIDFromString("c3b5af18-4e1d-11e8-9c2d-fa7ae01bbabc"),
				doc: Scan{
					ChecktypesGroup: ChecktypesGroup{
						Name: "OneGroup",
						Checktypes: []Checktype{
							{
								Name:    "onecheck",
								Options: `{"port":8080}`,
							},
						},
					},
					Status: "",
					TargetGroup: TargetGroup{
						Name: "OneGroup",
						Targets: []Target{
							{Identifier: "localhost"},
						},
					},
				},
			},
			wantErr: errors.Default(`pq: duplicate key value violates unique constraint "scans_pkey"`),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, err := NewDB(dialect, connStr)
			defer db.Close() //nolint
			if err != nil {
				t.Fatal(err)
			}
			err = db.CreateDocumentWithID(tt.args.id, tt.args.doc)
			if testutil.ErrToStr(err) != testutil.ErrToStr(tt.wantErr) {
				t.Errorf("Store.CreateDocument() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestStore_GetDocumentByID(t *testing.T) {
	type args struct {
		doc Scan
		id  uuid.UUID
	}
	tests := []struct {
		name    string
		args    args
		want    interface{}
		wantErr error
	}{
		{
			name: "HappyPath",
			args: args{
				doc: Scan{},
				id:  UUIDFromString(fixtureScans["Scan3"].ID),
			},
			want: Scan{
				Status:   "FINISHED",
				Trigger:  "a trigger",
				Progress: 1,
			},
		},
		{
			name: "DocDoesNotExist",
			args: args{
				doc: Scan{},
				id:  UUIDFromString("a3b5af28-3e1d-12e8-9c2d-fa7ae01bbebc"),
			},
			wantErr: errors.ErrNotFound,
			want:    Scan{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, err := NewDB(dialect, connStr)
			defer db.Close() //nolint
			if err != nil {
				t.Fatal(err)
			}
			err = db.GetDocByIDFromDocType(&tt.args.doc, tt.args.id)
			if !testutil.CheckErrors(err, tt.wantErr) {
				t.Errorf("Store.GetDocumentByID() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			diff := cmp.Diff(tt.want, tt.args.doc)
			if diff != "" {
				t.Errorf("want != got. Diff %s", diff)
			}
		})
	}
}

func TestStore_GetChildDocuments(t *testing.T) {
	type args struct {
		doc      interface{}
		parentID uuid.UUID
	}
	tests := []struct {
		name    string
		args    args
		wantErr error
		wantDoc []map[string]interface{}
	}{
		{
			name: "HappyPath",
			args: args{
				doc:      api.Check{},
				parentID: UUIDFromString(fixtureScans["Scan2"].ID),
			},
			wantDoc: []map[string]interface{}{
				{
					"status": "FINISHED",
					"target": "localhost",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, err := NewDB(dialect, connStr)
			defer db.Close() //nolint
			if err != nil {
				t.Fatal(err)
			}
			datas, err := db.GetChildDocsFromDocType(tt.args.doc, tt.args.parentID)
			if testutil.ErrToStr(err) != testutil.ErrToStr(tt.wantErr) {
				t.Errorf("Store.GetChildDocuments() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			got := []map[string]interface{}{}
			for _, v := range datas {
				got = append(got, mustDecodeToMap(v))
			}

			diff := cmp.Diff(got, tt.wantDoc)
			if diff != "" {
				t.Errorf("Error got != want. Diff:%s", diff)
			}
		})
	}
}

func TestStore_GetChildDocsStatsForField(t *testing.T) {
	type args struct {
		doc      interface{}
		parentID uuid.UUID
		field    string
	}
	tests := []struct {
		name    string
		args    args
		wantErr error
		wantDoc map[string]int
	}{
		{
			name: "HappyPath",
			args: args{
				doc:      api.Check{},
				parentID: UUIDFromString(fixtureScans["Scan2"].ID),
				field:    "status",
			},
			wantDoc: map[string]int{
				"FINISHED": 1,
			},
		},
		{
			name: "HappyPathNoRows",
			args: args{
				doc:      api.Check{},
				parentID: UUIDFromString("a3b5af18-4e1d-11e8-9c2d-fa7ae01bbeba"),
				field:    "status",
			},
			wantDoc: map[string]int{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, err := NewDB(dialect, connStr)
			defer db.Close() //nolint
			if err != nil {
				t.Fatal(err)
			}
			got, err := db.GetChildDocsStatsFromDocType(tt.args.doc, tt.args.field, tt.args.parentID)
			if testutil.ErrToStr(err) != testutil.ErrToStr(tt.wantErr) {
				t.Errorf("Store.GetChildDocumentsStats() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			diff := cmp.Diff(got, tt.wantDoc)
			if diff != "" {
				t.Errorf("Error got != want. Diff:%s", diff)
			}
		})
	}
}

func mustDecodeToMap(doc []byte) map[string]interface{} {
	res := map[string]interface{}{}
	err := json.Unmarshal(doc, &res)
	if err != nil {
		panic(err)
	}
	return res
}

func TestDB_GetDocsByField(t *testing.T) {
	type args struct {
		table string
		path  []interface{}
		value string
	}
	tests := []struct {
		name    string
		args    args
		want    []map[string]interface{}
		wantErr bool
	}{
		{
			name: "GetsDocumentsHavingFieldAtPathAndValue",
			args: args{
				table: "scans",
				path:  []interface{}{`targets`, `name`},
				value: `"test"`,
			},
			want: []map[string]interface{}{
				{
					"targets": map[string]interface{}{
						"name": "test",
					},
					"start_time": "2020-04-04T07:53:19.572375+01:00",
				},
				{
					"start_time": "2019-03-19T13:53:19.572375+01:00",
					"targets":    map[string]interface{}{"name": "test"},
				},
			},
		},
		{
			name: "GetsDocumentsHavingFieldAtTopLevelPathAndValue",
			args: args{
				table: "scans",
				path:  []interface{}{`extid`},
				value: `"id"`,
			},
			want: []map[string]interface{}{
				{"extid": "id", "name": "scan"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, err := NewDB(dialect, connStr)
			defer db.Close() //nolint
			if err != nil {
				t.Fatal(err)
			}
			datas, err := db.GetDocsByField(tt.args.table, tt.args.value, tt.args.path...)
			if (err != nil) != tt.wantErr {
				t.Errorf("DB.GetDocByField() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			got := []map[string]interface{}{}
			for _, v := range datas {
				got = append(got, mustDecodeToMap(v))
			}
			fmt.Printf("%+v\n", got)
			diff := cmp.Diff(got, tt.want)
			if diff != "" {
				t.Errorf("Error got != want. Diff:%s", diff)
			}
		})
	}
}

func TestDB_GetDocsByFieldOrderByLimit(t *testing.T) {
	type args struct {
		table  string
		offset uint32
		limit  uint32
		path   []interface{}
		value  string
	}
	tests := []struct {
		name    string
		args    args
		want    []map[string]interface{}
		wantErr bool
	}{
		{
			name: "GetsDocumentsComplexPathOrderByLimit",
			args: args{
				table: "scans",
				path:  []interface{}{`targets`, `name`},
				value: `"test"`,
				limit: 2,
			},
			want: []map[string]interface{}{
				{
					"targets": map[string]interface{}{
						"name": "test",
					},
					"start_time": "2020-04-04T07:53:19.572375+01:00",
				},
				{
					"start_time": "2019-03-19T13:53:19.572375+01:00",
					"targets":    map[string]interface{}{"name": "test"},
				},
			},
		},
		{
			name: "GetsDocumentsHavingFieldAtTopLevelPathAndValue",
			args: args{
				table: "scans",
				path:  []interface{}{`extid`},
				value: `"id"`,
			},
			want: []map[string]interface{}{
				{"extid": "id", "name": "scan"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, err := NewDB(dialect, connStr)
			defer db.Close() //nolint
			if err != nil {
				t.Fatal(err)
			}
			datas, err := db.GetDocsByFieldLimit(tt.args.table, tt.args.value, tt.args.offset, tt.args.limit, tt.args.path...)
			if (err != nil) != tt.wantErr {
				t.Errorf("DB.GetDocByField() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			got := []map[string]interface{}{}
			for _, v := range datas {
				got = append(got, mustDecodeToMap(v))
			}
			fmt.Printf("%+v\n", got)
			diff := cmp.Diff(got, tt.want)
			if diff != "" {
				t.Errorf("Error got != want. Diff:%s", diff)
			}
		})
	}
}

func TestDB_DeleteChildDocs(t *testing.T) {
	type args struct {
		table    string
		parentID uuid.UUID
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "HappyPath",
			args: args{
				parentID: UUIDFromString("e5699669-b212-44b2-8b30-32e1d6d14f5c"),
				table:    "checks",
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			db, err := NewDB(dialect, connStr)
			defer db.Close() //nolint
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.DeleteChildDocs(tt.args.table, tt.args.parentID); (err != nil) != tt.wantErr {
				t.Errorf("DB.DeleteChildDocs() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
