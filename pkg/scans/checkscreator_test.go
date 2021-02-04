/*
Copyright 2021 Adevinta
*/

package scans

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/adevinta/vulcan-core-cli/vulcan-core/client"
	"github.com/go-kit/kit/log"
	uuid2 "github.com/goadesign/goa/uuid"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	uuid "github.com/satori/go.uuid"

	"github.com/adevinta/vulcan-scan-engine/pkg/api"
	"github.com/adevinta/vulcan-scan-engine/pkg/api/persistence/db"
	"github.com/adevinta/vulcan-scan-engine/pkg/api/service"
)

type inMemoryAssettypeInformer struct {
	assetypes client.AssettypeCollection
}

func (i *inMemoryAssettypeInformer) IndexAssettypes(ctx context.Context, path string) (*http.Response, error) {
	return nil, nil
}

func (i *inMemoryAssettypeInformer) DecodeAssettypeCollection(resp *http.Response) (client.AssettypeCollection, error) {
	return i.assetypes, nil
}

type inMemoryStore struct {
	scans  map[string]api.Scan
	checks map[string]api.Check
	locks  sync.Map
}

func (s *inMemoryStore) GetCreatingScans() ([]string, error) {
	var scans []string
	for _, s := range s.scans {
		if s.CheckCount == s.ChecksCreated || s.CheckCount == nil || s.ChecksCreated == nil ||
			*s.Status != service.ScanStatusRunning {
			continue
		}
		scans = append(scans, s.ID.String())
	}
	return scans, nil
}

func (s *inMemoryStore) TryLockScan(id string) (*db.Lock, error) {
	_, ok := s.locks.LoadOrStore(id, struct{}{})
	if ok {
		return &db.Lock{Acquired: false, ID: id}, nil
	}
	return &db.Lock{Acquired: true, ID: id}, nil
}

func (s *inMemoryStore) ReleaseScanLock(l *db.Lock) error {
	s.locks.Delete(l.ID)
	return nil
}

func (s *inMemoryStore) GetScanByID(id uuid.UUID) (api.Scan, error) {
	scan, ok := s.scans[id.String()]
	if !ok {
		return api.Scan{}, errors.New("Not found")
	}
	return scan, nil
}

func (s *inMemoryStore) UpdateScan(id uuid.UUID, scan api.Scan, updateStates []string) (int64, error) {
	// We don't need to take into account the states in this case.
	var newscan api.Scan
	if cscan, ok := s.scans[id.String()]; ok {
		newscan = mergeScans(cscan, scan)
	} else {
		newscan = scan
	}
	s.scans[id.String()] = newscan
	return 1, nil
}

func (s *inMemoryStore) InsertCheckIfNotExists(c api.Check) (string, error) {
	found := c
	for _, cc := range s.checks {
		if *cc.ScanIndex == *c.ScanIndex && cc.ScanID == c.ScanID {
			found = cc
			break
		}
	}
	s.checks[found.ID] = found
	return found.ID, nil
}

type inMemCheckSender struct {
	msgs []client.CheckPayload
}

func (in *inMemCheckSender) Notify(m *client.CheckPayload) error {
	msgs := in.msgs
	msgs = append(msgs, *m)
	in.msgs = msgs
	return nil
}

var (
	checksTypesInfoTest = map[string]map[string]struct{}{
		"Hostname": {
			"vulcan-http-headers": {},
			"vulcan-vulners":      {},
		},
	}

	scan1 = api.Scan{
		ID:            mustUUIDFromString("234da2ca-0da9-4ad8-b69a-c7714e9434cc"),
		CheckCount:    intToPtr(2),
		ChecksCreated: intToPtr(0),
		StartTime:     timeToPtr(time.Now()),
		Status:        strToPtr(service.ScanStatusRunning),
		TargetGroups: &[]api.TargetsChecktypesGroup{
			{
				TargetGroup: api.TargetGroup{
					Name: "TG1",
					Targets: []api.Target{
						{
							Identifier: "host1.example.com",
							Type:       "Hostname",
						},
						{
							Identifier: "host2.example.com",
							Type:       "Hostname",
						},
					},
				},
				ChecktypesGroup: api.ChecktypesGroup{
					Name: "CTG1",
					Checktypes: []api.Checktype{
						{Name: "vulcan-http-headers"},
						{Name: "vulcan-vulners"},
					},
				},
			},
		},

		ChecktypesInfo: checksTypesInfoTest,
	}

	scan1ClientChecks = []client.CheckPayload{
		{
			Check: &client.CheckData{
				Assettype:     strToPtr("Hostname"),
				ChecktypeName: strToPtr("vulcan-http-headers"),
				ID:            mustPtrUUIDFromString("ad11932b-e68f-48a9-bfab-5789a8aa20e8"),
				Options:       strToPtr("{}"),
				ScanID:        mustPtrUUIDFromString("234da2ca-0da9-4ad8-b69a-c7714e9434cc"),
				Target:        "host1.example.com",
			},
		},
		{
			Check: &client.CheckData{
				Assettype:     strToPtr("Hostname"),
				ChecktypeName: strToPtr("vulcan-vulners"),
				ID:            mustPtrUUIDFromString("f186e6f3-e187-4cbb-87bc-0d615d8080d0"),
				Options:       strToPtr("{}"),
				ScanID:        mustPtrUUIDFromString("234da2ca-0da9-4ad8-b69a-c7714e9434cc"),
				Target:        "host1.example.com",
			},
		},
		{
			Check: &client.CheckData{
				Assettype:     strToPtr("Hostname"),
				ChecktypeName: strToPtr("vulcan-http-headers"),
				ID:            mustPtrUUIDFromString("2edaea82-77c6-491b-8937-8678fd4d95a7"),
				Options:       strToPtr("{}"),
				ScanID:        mustPtrUUIDFromString("234da2ca-0da9-4ad8-b69a-c7714e9434cc"),
				Target:        "host2.example.com",
			},
		},
		{
			Check: &client.CheckData{
				Assettype:     strToPtr("Hostname"),
				ChecktypeName: strToPtr("vulcan-vulners"),
				ID:            mustPtrUUIDFromString("5142079c-6b4a-4969-ae57-5468caf6c79c"),
				Options:       strToPtr("{}"),
				ScanID:        mustPtrUUIDFromString("234da2ca-0da9-4ad8-b69a-c7714e9434cc"),
				Target:        "host2.example.com",
			},
		},
	}

	scan2 = api.Scan{
		ID:            mustUUIDFromString("8a2caddf-7f9e-40fc-88ca-1f64715cd4ac"),
		CheckCount:    intToPtr(4),
		ChecksCreated: intToPtr(0),
		Status:        strToPtr(service.ScanStatusRunning),
		StartTime:     timeToPtr(time.Now()),
		TargetGroups: &[]api.TargetsChecktypesGroup{
			{
				TargetGroup: api.TargetGroup{
					Name: "TG1",
					Targets: []api.Target{
						{
							Identifier: "host1.example.com",
							Type:       "Hostname",
						},
						{
							Identifier: "host2.example.com",
							Type:       "Hostname",
						},
					},
				},
				ChecktypesGroup: api.ChecktypesGroup{
					Name: "CTG1",
					Checktypes: []api.Checktype{
						{Name: "vulcan-http-headers"},
						{Name: "vulcan-vulners"},
					},
				},
			},
		},

		ChecktypesInfo: checksTypesInfoTest,
	}

	scan2Check = api.Check{
		ID:        "f186e6f3-e187-4cbb-87bc-0d615d8080d0",
		Progress:  floatToPtr(0),
		ScanID:    scan2.ID.String(),
		ScanIndex: strToPtr("0_0"),
	}

	scan2ClientChecks = []client.CheckPayload{
		{
			Check: &client.CheckData{
				Assettype:     strToPtr("Hostname"),
				ChecktypeName: strToPtr("vulcan-http-headers"),
				ID:            mustPtrUUIDFromString(scan2Check.ID),
				Options:       strToPtr("{}"),
				ScanID:        mustPtrUUIDFromString(scan2.ID.String()),
				Target:        "host1.example.com",
			},
		},
		{
			Check: &client.CheckData{
				Assettype:     strToPtr("Hostname"),
				ChecktypeName: strToPtr("vulcan-vulners"),
				ID:            mustPtrUUIDFromString("f186e6f3-e187-4cbb-87bc-0d615d8080d0"),
				Options:       strToPtr("{}"),
				ScanID:        mustPtrUUIDFromString(scan2.ID.String()),
				Target:        "host1.example.com",
			},
		},
		{
			Check: &client.CheckData{
				Assettype:     strToPtr("Hostname"),
				ChecktypeName: strToPtr("vulcan-http-headers"),
				ID:            mustPtrUUIDFromString("2edaea82-77c6-491b-8937-8678fd4d95a7"),
				Options:       strToPtr("{}"),
				ScanID:        mustPtrUUIDFromString(scan2.ID.String()),
				Target:        "host2.example.com",
			},
		},
		{
			Check: &client.CheckData{
				Assettype:     strToPtr("Hostname"),
				ChecktypeName: strToPtr("vulcan-vulners"),
				ID:            mustPtrUUIDFromString("5142079c-6b4a-4969-ae57-5468caf6c79c"),
				Options:       strToPtr("{}"),
				ScanID:        mustPtrUUIDFromString(scan2.ID.String()),
				Target:        "host2.example.com",
			},
		},
	}

	scan3 = api.Scan{
		ID:            mustUUIDFromString("1cdd13ab-d69f-45b5-a861-08994c16399d"),
		CheckCount:    intToPtr(4),
		ChecksCreated: intToPtr(0),
		Status:        strToPtr(service.ScanStatusRunning),
		StartTime:     timeToPtr(time.Now().AddDate(0, 0, -1*(MaxScanAge+1))),
		TargetGroups: &[]api.TargetsChecktypesGroup{
			{
				TargetGroup: api.TargetGroup{
					Name: "TG1",
					Targets: []api.Target{
						{
							Identifier: "host1.example.com",
							Type:       "Hostname",
						},
						{
							Identifier: "host2.example.com",
							Type:       "Hostname",
						},
					},
				},
				ChecktypesGroup: api.ChecktypesGroup{
					Name: "CTG1",
					Checktypes: []api.Checktype{
						{Name: "vulcan-http-headers"},
						{Name: "vulcan-vulners"},
					},
				},
			},
		},

		ChecktypesInfo: checksTypesInfoTest,
	}
)

func TestChecksCreator_CreateScanChecks(t *testing.T) {
	type fields struct {
		store  Store
		sender CheckSender
		l      Logger
	}
	tests := []struct {
		name         string
		fields       fields
		id           string
		stateChecker func(Store, CheckSender) string
		wantErr      bool
	}{
		{
			name: "HappyPath",
			fields: fields{
				l: log.NewNopLogger(),
				store: &inMemoryStore{
					scans: map[string]api.Scan{
						"234da2ca-0da9-4ad8-b69a-c7714e9434cc": scan1,
					},
					checks: map[string]api.Check{},
				},
				sender: &inMemCheckSender{},
			},
			id: "234da2ca-0da9-4ad8-b69a-c7714e9434cc",
			stateChecker: func(s Store, c CheckSender) string {
				store := s.(*inMemoryStore)
				snsStore := c.(*inMemCheckSender)
				// Copy the test scan.
				want := scan1
				// Set the values to the expected ones.
				want.ChecksCreated = intToPtr(4)
				want.LastTargetCheckGCreated = intToPtr(0)
				want.LastCheckCreated = intToPtr(-1)
				got := store.scans["234da2ca-0da9-4ad8-b69a-c7714e9434cc"]
				scansDiff := cmp.Diff(want, got)
				gotSend := snsStore.msgs
				wantSend := scan1ClientChecks
				checksDiff := cmp.Diff(wantSend, gotSend, cmpopts.IgnoreFields(client.CheckData{}, "ID"))
				return scansDiff + checksDiff
			},
		},

		{
			name: "DoesNotCreateSameCheckTwice",
			fields: fields{
				l: log.NewNopLogger(),
				store: &inMemoryStore{
					scans: map[string]api.Scan{
						scan2.ID.String(): scan2,
					},
					checks: map[string]api.Check{
						scan2Check.ID: scan2Check,
					},
				},
				sender: &inMemCheckSender{},
			},
			id: scan2.ID.String(),
			stateChecker: func(s Store, c CheckSender) string {
				store := s.(*inMemoryStore)
				snsStore := c.(*inMemCheckSender)
				// Copy the test scan.
				want := scan2
				// Set the values to the expected ones.
				want.ChecksCreated = intToPtr(4)
				want.LastTargetCheckGCreated = intToPtr(0)
				want.LastCheckCreated = intToPtr(-1)
				got := store.scans[scan2.ID.String()]
				scansDiff := cmp.Diff(want, got)
				gotSend := snsStore.msgs
				wantSend := scan2ClientChecks
				if len(gotSend) < 1 {
					return scansDiff + "invalid number of checks"
				}
				gotCID := gotSend[0].Check.ID.String()
				wantCID := wantSend[0].Check.ID.String()
				if gotCID != wantCID {
					return scansDiff + "invalid check ID"
				}
				checksDiff := cmp.Diff(wantSend, gotSend, cmpopts.IgnoreFields(client.CheckData{}, "ID"))
				return scansDiff + checksDiff
			},
		},

		{
			name: "FinishesScanOlderThanMaxAge",
			fields: fields{
				l: log.NewNopLogger(),
				store: &inMemoryStore{
					scans: map[string]api.Scan{
						scan3.ID.String(): scan3,
					},
				},
				sender: &inMemCheckSender{},
			},
			id: scan3.ID.String(),
			stateChecker: func(s Store, c CheckSender) string {
				store := s.(*inMemoryStore)
				// Copy the test scan.
				want := scan3
				// Set the values to the expected ones.
				finished := service.ScanStatusFinished
				want.Status = &finished
				got := store.scans[scan3.ID.String()]
				scansDiff := cmp.Diff(want, got)
				return scansDiff
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &ChecksCreator{
				store:  tt.fields.store,
				sender: tt.fields.sender,
				l:      tt.fields.l,
			}
			if err := c.CreateScanChecks(tt.id); (err != nil) != tt.wantErr {
				t.Errorf("ChecksCreator.CreateScanChecks() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := tt.stateChecker(c.store, c.sender); diff != "" {
				t.Errorf("want!=got, diff %s", diff)
			}
		})
	}
}

func mustUUIDFromString(id string) uuid.UUID {
	u, err := uuid.FromString(id)
	if err != nil {
		panic(err)
	}
	return u
}

func mustPtrUUIDFromString(id string) *uuid2.UUID {
	u, err := uuid2.FromString(id)
	if err != nil {
		panic(err)
	}
	return &u
}

func intToPtr(i int) *int {
	return &i
}

func floatToPtr(i float32) *float32 {
	return &i
}

func strToPtr(s string) *string {
	return &s
}

func timeToPtr(t time.Time) *time.Time {
	return &t
}

func mergeScans(scan1 api.Scan, scan2 api.Scan) api.Scan {
	// Dirty trick to simulate merging scans data like postgres does.
	content1, err := json.Marshal(scan1)
	if err != nil {
		panic(err)
	}
	content2, err := json.Marshal(scan2)
	if err != nil {
		panic(err)
	}
	var scan api.Scan
	if err = json.Unmarshal(content1, &scan); err != nil {
		panic(err)
	}
	if err = json.Unmarshal(content2, &scan); err != nil {
		panic(err)
	}
	return scan
}
