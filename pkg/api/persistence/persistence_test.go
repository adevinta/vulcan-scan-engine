/*
Copyright 2021 Adevinta
*/

package persistence

import (
	"fmt"
	"os"
	"reflect"
	"testing"

	"github.com/adevinta/vulcan-scan-engine/pkg/api"
	"github.com/adevinta/vulcan-scan-engine/pkg/api/persistence/db"
	"github.com/adevinta/vulcan-scan-engine/pkg/testutil"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	_ "github.com/lib/pq"
	uuid "github.com/satori/go.uuid"
)

const (
	fixtures  = "testdata/store_test_fixtures"
	dbDirPath = "../../../db/" // nolint
	dbName    = "persistencetestdb"
	// Use the default dialect for the underlying store.
	dialect = ""
)

type fixtureScan struct {
	ID     string
	Checks map[string]string
}

var (
	connStr       = fmt.Sprintf(testutil.DBConnString, testutil.TestDBUser, testutil.TestDBPassword, dbName)
	runningState  = "RUNNING"
	finishedState = "FINISHED"
	fixtureScans  = map[string]fixtureScan{
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
	}
	nonExistentScanID   = "a3c6bf18-4e1d-11e8-9c2a-fa7ae01bbeba"
	nonExistentScanID2  = "a3b5ca18-4e2d-22e8-9c2d-fa7dd02cdddd"
	nonExistentCheckID  = "c3f3bf38-4e1d-11e8-9c2a-fa7ae01bbeba"
	nonExistentCheckID2 = "fab61b5e-e4e0-490d-b86b-ad38ca87291e"
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
	res = m.Run()
}

func loadFixtures(t *testing.T) {
	t.Helper()
	err := testutil.LoadFixtures(fixtures, dbName)
	if err != nil {
		t.Fatalf("error setting up tests: %s", err.Error())
	}
}

func TestStore_UpdateScan(t *testing.T) {
	loadFixtures(t)

	type args struct {
		id           uuid.UUID
		scan         api.Scan
		updateStates []string
	}
	tests := []struct {
		name      string
		args      args
		wantErr   error
		wantCount int64
		wantScan  api.Scan
	}{
		{
			name: "DontUpdateScanWhenLessProgress",
			args: args{
				id: UUIDFromString(fixtureScans["Scan4"].ID),
				scan: api.Scan{
					ID:       UUIDFromString(fixtureScans["Scan4"].ID),
					Status:   &runningState,
					Progress: new(float32),
				},
				updateStates: []string{"RUNNING", "CREATED"},
			},
			wantScan: api.Scan{
				ID:       UUIDFromString(fixtureScans["Scan4"].ID),
				Status:   &runningState,
				Progress: testutil.FloatPointer(0.3),
			},
		},
		{
			name: "UpdateScanWithGreaterProcess",
			args: args{
				id: UUIDFromString(fixtureScans["Scan5"].ID),
				scan: api.Scan{
					ID:       UUIDFromString(fixtureScans["Scan5"].ID),
					Status:   &finishedState,
					Progress: testutil.FloatPointer(1),
				},
				updateStates: []string{"RUNNING", "CREATED"},
			},
			wantScan: api.Scan{
				ID:       UUIDFromString(fixtureScans["Scan5"].ID),
				Status:   &finishedState,
				Progress: testutil.FloatPointer(1),
			},
			wantCount: 1,
		},
		{
			name: "InsertsScan",
			args: args{
				id: UUIDFromString(nonExistentScanID2),
				scan: api.Scan{
					ID:       UUIDFromString(nonExistentScanID2),
					Status:   &finishedState,
					Progress: testutil.FloatPointer(1),
				},
				updateStates: []string{"RUNNING", "CREATED"},
			},
			wantScan: api.Scan{
				ID:       UUIDFromString(nonExistentScanID2),
				Status:   &finishedState,
				Progress: testutil.FloatPointer(1),
			},
			wantCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, err := db.NewDB(dialect, connStr)
			defer db.Close() //nolint
			if err != nil {
				t.Fatal(err)
			}
			s := NewPersistence(db)
			gotCount, err := s.UpdateScan(tt.args.id, tt.args.scan, tt.args.updateStates)
			if testutil.ErrToStr(err) != testutil.ErrToStr(tt.wantErr) {
				t.Errorf("Store.UpdateScan() error = %v, wantErr %v", err, tt.wantErr)
			}
			if gotCount != tt.wantCount {
				t.Errorf("got count != wantCount. %d != %d", gotCount, tt.wantCount)
			}
			got := api.Scan{}
			err = db.GetDocByIDFromDocType(&got, tt.args.id)
			if err != nil {
				t.Fatal(err)
			}
			diff := cmp.Diff(tt.wantScan, got)
			if diff != "" {
				t.Errorf("want Scan != got Scan. Diff: %s\n", diff)
			}
		})
	}
}

func TestStore_UpsertCheck(t *testing.T) {
	loadFixtures(t)

	type args struct {
		scanID       uuid.UUID
		id           uuid.UUID
		check        api.Check
		updateStates []string
	}
	tests := []struct {
		name    string
		args    args
		want    int64
		wantErr error
	}{
		{
			name: "InsertsACheck",
			args: args{
				scanID: UUIDFromString(nonExistentScanID),
				id:     UUIDFromString(nonExistentCheckID),
				check: api.Check{
					ID:       nonExistentCheckID,
					Progress: testutil.FloatPointer(0.3),
					ScanID:   nonExistentScanID,
					Data:     []byte(`{"target":"localhost","options":""}`),
				},
				updateStates: []string{"RUNNING", "CREATED"},
			},
			want: 1,
		},
		{
			name: "UpdatesACheck",
			args: args{
				scanID: UUIDFromString(fixtureScans["Scan2"].ID),
				id:     UUIDFromString(fixtureScans["Scan2"].Checks["Check2"]),
				check: api.Check{
					ID:       nonExistentCheckID,
					Progress: testutil.FloatPointer(0.3),
					ScanID:   nonExistentScanID,
					Data:     []byte(`{"target":"localhost","options":""}`),
				},
				updateStates: []string{"RUNNING", "CREATED"},
			},
			want: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, err := db.NewDB(dialect, connStr)
			defer db.Close() //nolint
			if err != nil {
				t.Fatal(err)
			}
			s := NewPersistence(db)
			got, err := s.UpsertCheck(tt.args.scanID, tt.args.id, tt.args.check, tt.args.updateStates)
			if testutil.ErrToStr(err) != testutil.ErrToStr(tt.wantErr) {
				t.Errorf("Store.UpsertCheck() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Store.UpsertCheck() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPersistence_InsertCheckIfNotExists(t *testing.T) {
	loadFixtures(t)

	tests := []struct {
		name    string
		check   api.Check
		want    string
		wantErr error
	}{
		{
			name: "InsertCheck",
			check: api.Check{
				ID:        nonExistentCheckID,
				Progress:  testutil.FloatPointer(0.3),
				ScanID:    fixtureScans["Scan2"].ID,
				ScanIndex: testutil.StringPointer("1"),
				Data:      []byte(`{"target":"localhost","options":""}`),
			},
			want: nonExistentCheckID,
		},
		{
			name: "DotNotInsertCheck",
			check: api.Check{
				ID:        nonExistentCheckID2,
				Progress:  testutil.FloatPointer(0.3),
				ScanID:    fixtureScans["Scan1"].ID,
				ScanIndex: testutil.StringPointer("1"),
				Data:      []byte(`{"target":"localhost","options":""}`),
			},
			want: fixtureScans["Scan1"].Checks["Check1"],
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, err := db.NewDB(dialect, connStr)
			defer db.Close() //nolint
			if err != nil {
				t.Fatal(err)
			}
			s := NewPersistence(db)
			got, err := s.InsertCheckIfNotExists(tt.check)
			if testutil.ErrToStr(err) != testutil.ErrToStr(tt.wantErr) {
				t.Errorf("persistence.InsertCheckIfNotExists() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("persistence.InsertCheckIfNotExists() = %v, want %v", got, tt.want)
			}
		})
	}
}

func UUIDFromString(v string) uuid.UUID {
	ret, _ := uuid.FromString(v)
	return ret
}

func TestPersistence_GetScans(t *testing.T) {
	loadFixtures(t)

	tests := []struct {
		name    string
		Offset  uint32
		Limit   uint32
		want    []api.Scan
		wantErr bool
	}{
		{
			name: "ReturnsScansHappyPath",
			want: []api.Scan{
				{
					ID:       UUIDFromString("c3b5af18-4e1d-11e8-9c2d-fa7ae01bbebc"),
					Status:   &runningState,
					Progress: testutil.FloatPointer(0.5),
				},
				{
					ID:       UUIDFromString("a3b5af18-4e1d-11e8-9c2d-fa7ae01bbebc"),
					Status:   &runningState,
					Progress: testutil.FloatPointer(0),
				},
				{
					ID:       UUIDFromString("a3b5af18-4e1d-11e8-9c2d-fa7ae01bbeba"),
					Status:   &finishedState,
					Progress: testutil.FloatPointer(1),
				},
				{
					ID:       UUIDFromString("a3b5af18-4e2d-22e8-9c2d-fa7ad01bbeba"),
					Status:   &runningState,
					Progress: testutil.FloatPointer(0.3),
				},
				{
					ID:       UUIDFromString("a3b5ca18-4e2d-22e8-9c2d-fa7ad01bbeba"),
					Status:   &runningState,
					Progress: testutil.FloatPointer(0.1),
				},
				{
					ID:         UUIDFromString("a3b5ca18-5f3f-22e8-9c2d-fa7ad01bbeba"),
					ExternalID: testutil.StringPointer("extid1"),
					Status:     &finishedState,
					Progress:   testutil.FloatPointer(1),
				},
				{
					ID:         UUIDFromString("a4b6ba18-5f3f-22e8-9c2d-fa7ad01bbeba"),
					ExternalID: testutil.StringPointer("extid1"),
					Status:     &runningState,
					Progress:   testutil.FloatPointer(0.1),
				},
				{
					ID:         UUIDFromString("a4b6ba18-5f3f-22e8-9c2d-fa7ad01bbeb1"),
					ExternalID: testutil.StringPointer("extid1"),
					Status:     &runningState,
					Progress:   testutil.FloatPointer(0.1),
				},
			},
		},
		{
			name:  "ReturnsScansLimit2",
			Limit: 2,
			want: []api.Scan{
				{
					ID:       UUIDFromString("c3b5af18-4e1d-11e8-9c2d-fa7ae01bbebc"),
					Status:   &runningState,
					Progress: testutil.FloatPointer(0.5),
				},
				{
					ID:       UUIDFromString("a3b5af18-4e1d-11e8-9c2d-fa7ae01bbebc"),
					Status:   &runningState,
					Progress: testutil.FloatPointer(0),
				},
			},
		},
		{
			name:   "ReturnsScansOffset5",
			Offset: 5,
			want: []api.Scan{
				{
					ID:         UUIDFromString("a3b5ca18-5f3f-22e8-9c2d-fa7ad01bbeba"),
					ExternalID: testutil.StringPointer("extid1"),
					Status:     &finishedState,
					Progress:   testutil.FloatPointer(1),
				},
				{
					ID:         UUIDFromString("a4b6ba18-5f3f-22e8-9c2d-fa7ad01bbeba"),
					ExternalID: testutil.StringPointer("extid1"),
					Status:     &runningState,
					Progress:   testutil.FloatPointer(0.1),
				},
				{
					ID:         UUIDFromString("a4b6ba18-5f3f-22e8-9c2d-fa7ad01bbeb1"),
					ExternalID: testutil.StringPointer("extid1"),
					Status:     &runningState,
					Progress:   testutil.FloatPointer(0.1),
				},
			},
		},
		{
			name:   "ReturnsScansOffset2Limit2",
			Offset: 2,
			Limit:  2,
			want: []api.Scan{
				{
					ID:       UUIDFromString("a3b5af18-4e1d-11e8-9c2d-fa7ae01bbeba"),
					Status:   &finishedState,
					Progress: testutil.FloatPointer(1),
				},
				{
					ID:       UUIDFromString("a3b5af18-4e2d-22e8-9c2d-fa7ad01bbeba"),
					Status:   &runningState,
					Progress: testutil.FloatPointer(0.3),
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, err := db.NewDB(dialect, connStr)
			defer db.Close() //nolint
			if err != nil {
				t.Fatal(err)
			}
			s := NewPersistence(db)
			got, err := s.GetScans(tt.Offset, tt.Limit)
			if (err != nil) != tt.wantErr {
				t.Errorf("Persistence.GetScans() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			diff := cmp.Diff(tt.want, got, cmpopts.IgnoreFields(api.Scan{}, "CheckCount", "ChecksCreated"))
			if diff != "" {
				t.Errorf("want Scans != got Scans. Diff: %s\n", diff)
			}
		})
	}
}

func TestPersistence_GetScansByExternalID(t *testing.T) {
	loadFixtures(t)

	tests := []struct {
		name    string
		ID      string
		Offset  uint32
		Limit   uint32
		want    []api.Scan
		wantErr bool
	}{
		{
			name:  "ReturnsScansWithExternalIDLimit2",
			ID:    `extid1`,
			Limit: 2,
			want: []api.Scan{
				{
					ID:         UUIDFromString("a3b5ca18-5f3f-22e8-9c2d-fa7ad01bbeba"),
					ExternalID: testutil.StringPointer("extid1"),
					Status:     &finishedState,
					Progress:   testutil.FloatPointer(1),
				},
				{
					ID:         UUIDFromString("a4b6ba18-5f3f-22e8-9c2d-fa7ad01bbeba"),
					ExternalID: testutil.StringPointer("extid1"),
					Status:     &runningState,
					Progress:   testutil.FloatPointer(0.1),
				},
			},
		},
		{
			name: "ReturnsScansWithExternalIDNoLimit",
			ID:   `extid1`,
			want: []api.Scan{
				{
					ID:         UUIDFromString("a3b5ca18-5f3f-22e8-9c2d-fa7ad01bbeba"),
					ExternalID: testutil.StringPointer("extid1"),
					Status:     &finishedState,
					Progress:   testutil.FloatPointer(1),
				},
				{
					ID:         UUIDFromString("a4b6ba18-5f3f-22e8-9c2d-fa7ad01bbeba"),
					ExternalID: testutil.StringPointer("extid1"),
					Status:     &runningState,
					Progress:   testutil.FloatPointer(0.1),
				},
				{
					ID:         UUIDFromString("a4b6ba18-5f3f-22e8-9c2d-fa7ad01bbeb1"),
					ExternalID: testutil.StringPointer("extid1"),
					Status:     &runningState,
					Progress:   testutil.FloatPointer(0.1),
				},
			},
		},
		{
			name:   "ReturnsScansWithExternalIDOffset1",
			ID:     `extid1`,
			Offset: 1,
			want: []api.Scan{
				{
					ID:         UUIDFromString("a4b6ba18-5f3f-22e8-9c2d-fa7ad01bbeba"),
					ExternalID: testutil.StringPointer("extid1"),
					Status:     &runningState,
					Progress:   testutil.FloatPointer(0.1),
				},
				{
					ID:         UUIDFromString("a4b6ba18-5f3f-22e8-9c2d-fa7ad01bbeb1"),
					ExternalID: testutil.StringPointer("extid1"),
					Status:     &runningState,
					Progress:   testutil.FloatPointer(0.1),
				},
			},
		},
		{
			name:   "ReturnsScansWithExternalIDOffset1Limit1",
			ID:     `extid1`,
			Offset: 1,
			Limit:  1,
			want: []api.Scan{
				{
					ID:         UUIDFromString("a4b6ba18-5f3f-22e8-9c2d-fa7ad01bbeba"),
					ExternalID: testutil.StringPointer("extid1"),
					Status:     &runningState,
					Progress:   testutil.FloatPointer(0.1),
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, err := db.NewDB(dialect, connStr)
			defer db.Close() //nolint
			if err != nil {
				t.Fatal(err)
			}
			s := NewPersistence(db)
			got, err := s.GetScansByExternalID(tt.ID, tt.Offset, tt.Limit)
			if (err != nil) != tt.wantErr {
				t.Errorf("Persistence.GetScansByExternalID() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			diff := cmp.Diff(tt.want, got)
			if diff != "" {
				t.Errorf("want Scans != got Scans. Diff: %s\n", diff)
			}
		})
	}
}

func TestPersistence_GetScanChecks(t *testing.T) {
	loadFixtures(t)

	tests := []struct {
		name    string
		scanID  uuid.UUID
		want    []api.Check
		wantErr bool
	}{
		{
			name:   "ReturnsChecksHappyPath",
			scanID: UUIDFromString("c3b5af18-4e1d-11e8-9c2d-fa7ae01bbebc"),
			want: []api.Check{
				{
					ID:     "c3b5af18-4e1d-11e8-9c2d-fa7ae01bbeaa",
					Status: "CREATED",
					Target: "localhost",
				},
				{
					ID:     "c3b5afd8-4e1d-11d8-9c2d-fa7ae01bbeaa",
					Status: "FINISHED",
					Target: "localhost",
				},
			},
		},
		{
			name:   "ReturnsChecksInnexistentScan",
			scanID: UUIDFromString("a3c6bf18-4e1d-11e8-9c2a-fa7ae01bbeba"),
			want:   []api.Check{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, err := db.NewDB(dialect, connStr)
			defer db.Close() //nolint
			if err != nil {
				t.Fatal(err)
			}
			s := NewPersistence(db)
			got, err := s.GetScanChecks(tt.scanID)
			if (err != nil) != tt.wantErr {
				t.Errorf("Persistence.GetScanChecks() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			diff := cmp.Diff(tt.want, got, cmpopts.IgnoreFields(api.Check{},
				"Options", "ScanID", "WebHook", "Progress", "QueueName", "ChecktypeID", "Data",
			))
			if diff != "" {
				t.Errorf("want checks != got checks. Diff: %s\n", diff)
			}
		})
	}
}

func TestPersistence_GetScanStats(t *testing.T) {
	loadFixtures(t)

	tests := []struct {
		name    string
		scanID  uuid.UUID
		want    map[string]int
		wantErr bool
	}{
		{
			name:   "ReturnsStatsHappyPath",
			scanID: UUIDFromString("c3b5af18-4e1d-11e8-9c2d-fa7ae01bbebc"),
			want: map[string]int{
				"CREATED":  1,
				"FINISHED": 1,
			},
		},
		{
			name:   "ReturnsStatsSingleCheck",
			scanID: UUIDFromString("a3b5af18-4e1d-11e8-9c2d-fa7ae01bbebc"),
			want: map[string]int{
				"FINISHED": 1,
			},
		},
		{
			name:   "ReturnsStatsInnexistentScanID",
			scanID: UUIDFromString("a3c6bf18-4e1d-11e8-9c2a-fa7ae01bbeba"),
			want:   map[string]int{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, err := db.NewDB(dialect, connStr)
			defer db.Close() //nolint
			if err != nil {
				t.Fatal(err)
			}
			s := NewPersistence(db)
			got, err := s.GetScanStats(tt.scanID)
			if (err != nil) != tt.wantErr {
				t.Errorf("Persistence.GetScanStats() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			diff := cmp.Diff(tt.want, got)
			if diff != "" {
				t.Errorf("want stats != got stats. Diff: %s\n", diff)
			}
		})
	}
}

func TestPersistence_GetCreatingScans(t *testing.T) {
	tests := []struct {
		name    string
		want    []string
		wantErr bool
	}{
		{
			name: "ReturnsScansRunningWithChecksToCreate",
			want: []string{
				"c3b5af18-4e1d-11e8-9c2d-fa7ae01bbebc",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, err := db.NewDB(dialect, connStr)
			defer db.Close() //nolint
			if err != nil {
				t.Fatal(err)
			}
			s := NewPersistence(db)
			got, err := s.GetCreatingScans()
			if (err != nil) != tt.wantErr {
				t.Errorf("Persistence.GetScansByExternalID() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			diff := cmp.Diff(tt.want, got)
			if diff != "" {
				t.Errorf("want Scans != got Scans. Diff: %s\n", diff)
			}

		})
	}
}

func uint32ToPtr(n uint32) *uint32 {
	return &n
}

func TestPersistence_TryLockScan(t *testing.T) {
	db, err := db.NewDB(dialect, connStr)
	defer db.Close() //nolint
	if err != nil {
		t.Fatal(err)
	}
	s := NewPersistence(db)
	id := "id1"
	lock, err := s.TryLockScan(id)
	if err != nil {
		t.Error(err)
	}
	if !lock.Acquired {
		t.Error("lock not acquired")
	}
	err = s.ReleaseScanLock(lock)
	if err != nil {
		t.Error("error realeasing lock")
	}
}

func TestPersistence_GetScanIDForCheck(t *testing.T) {
	loadFixtures(t)

	tests := []struct {
		name    string
		ID      uuid.UUID
		want    uuid.UUID
		wantErr bool
	}{
		{
			name: "ReturnsScanIDForACheck",
			ID:   UUIDFromString(fixtureScans["Scan1"].Checks["Check1"]),
			want: UUIDFromString(fixtureScans["Scan1"].ID),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, err := db.NewDB(dialect, connStr)
			defer db.Close() //nolint
			if err != nil {
				t.Fatal(err)
			}
			s := NewPersistence(db)
			got, err := s.GetScanIDForCheck(tt.ID)
			if (err != nil) != tt.wantErr {
				t.Errorf("Persistence.GetScanIDForCheck() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Persistence.GetScanIDForCheck() = %v, want %v", got, tt.want)
			}
		})
	}
}
