/*
Copyright 2021 Adevinta
*/

package scans

import (
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/adevinta/vulcan-scan-engine/pkg/api"
	"github.com/adevinta/vulcan-scan-engine/pkg/api/persistence/db"
	"github.com/adevinta/vulcan-scan-engine/pkg/api/service"
	"github.com/go-kit/log"
	uuid2 "github.com/goadesign/goa/uuid"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	uuid "github.com/satori/go.uuid"

	"github.com/adevinta/vulcan-core-cli/vulcan-core/client"
)

var (
	ChecksTrans = cmp.Transformer("Sort", func(in []api.Check) []api.Check {
		out := append([]api.Check(nil), in...)
		sort.Slice(out, func(i, j int) bool {
			less := strings.Compare(*out[i].ChecktypeName, *out[j].ChecktypeName)
			return less < 0

		})
		return out
	})

	JobsTrans = cmp.Transformer("Sort", func(in []Job) []Job {
		out := append([]Job(nil), in...)
		sort.Slice(out, func(i, j int) bool {
			less := strings.Compare(out[i].Image, out[j].Image)
			return less < 0

		})
		return out
	})

	checktypes = map[string]client.Checktype{
		"vulcan-http-headers": {
			Checktype: &client.ChecktypeType{
				ID:           mustUUID2FromString("09aac496-5f5d-443e-bd0b-6c42e0a05ee1"),
				Assets:       []string{"Hostname"},
				Name:         "vulcan-http-headers",
				Image:        "example.com/vulcan-checks/vulcan-http-headers:285",
				Enabled:      boolToPtr(true),
				RequiredVars: []string{"VAR1", "VAR2"},
				QueueName:    strToPtr("queue1"),
				Timeout:      intToPtr(700),
				Options:      strToPtr("{}"),
			},
		},
		"vulcan-nessus": {
			Checktype: &client.ChecktypeType{
				ID:           mustUUID2FromString("8f8727fe-55bc-11eb-ae93-0242ac130002"),
				Assets:       []string{"Hostname"},
				Name:         "vulcan-nessus",
				Image:        "example.com/vulcan-checks/vulcan-nessus:2",
				Enabled:      boolToPtr(true),
				RequiredVars: []string{"VAR1"},
				QueueName:    strToPtr("queue2"),
				Timeout:      intToPtr(100),
				Options:      strToPtr("{\"option\":1}"),
			},
		},
		"vulcan-docker": {
			Checktype: &client.ChecktypeType{
				ID:           mustUUID2FromString("8f8727fe-55bc-11eb-ae93-0242ac130002"),
				Assets:       []string{"Hostname"},
				Name:         "vulcan-docker",
				Image:        "example.com/vulcan-checks/vulcan-docker:1",
				Enabled:      boolToPtr(true),
				RequiredVars: []string{},
				Timeout:      intToPtr(100),
			},
		},
	}

	jobsCheckTypesInfoTest = map[string]map[string]struct{}{
		"Hostname": {
			"vulcan-http-headers": {},
			"vulcan-nessus":       {},
		},
		"IP": {
			"vulcan-docker": {},
		},
	}

	scan4ID = "48fc7d46-53fc-11eb-ae93-0242ac130002"

	scan4 = api.Scan{
		ID:            mustUUIDFromString(scan4ID),
		CheckCount:    intToPtr(1),
		ChecksCreated: intToPtr(0),
		StartTime:     timeToPtr(time.Now()),
		Status:        strToPtr(service.ScanStatusRunning),
		Tag:           strToPtr("5a1346f1"),
		ExternalID:    strToPtr("scan4Program"),
		TargetGroups: &[]api.TargetsChecktypesGroup{
			{
				TargetGroup: api.TargetGroup{
					Name: "TG1",
					Targets: []api.Target{
						{
							Identifier: "host1.example.com",
							Type:       "Hostname",
						},
					},
				},
				ChecktypesGroup: api.ChecktypesGroup{
					Name: "CTG1",
					Checktypes: []api.Checktype{
						{Name: "vulcan-http-headers"},
						{Name: "vulcan-nessus"},
					},
				},
			},
			{
				TargetGroup: api.TargetGroup{
					Name: "TG2",
					Targets: []api.Target{
						{
							Identifier: "192.168.0.1",
							Type:       "IP",
						},
					},
				},
				ChecktypesGroup: api.ChecktypesGroup{
					Name: "CTG2",
					Checktypes: []api.Checktype{
						{Name: "vulcan-docker"},
					},
				},
			},
		},

		ChecktypesInfo: jobsCheckTypesInfoTest,
	}

	scan4Checks = []api.Check{
		{
			ID:            "38a76796-5724-11eb-861d-acde48001122",
			Status:        "CREATED",
			ScanID:        "48fc7d46-53fc-11eb-ae93-0242ac130002",
			Target:        "host1.example.com",
			Progress:      floatToPtr(0),
			ScanIndex:     strToPtr("0_0"),
			ChecktypeID:   strToPtr("09aac496-5f5d-443e-bd0b-6c42e0a05ee1"),
			ChecktypeName: strToPtr("vulcan-http-headers"),
			Image:         strToPtr("example.com/vulcan-checks/vulcan-http-headers:285"),
			Options:       strToPtr("{}"),
			QueueName:     strToPtr("queue1"),
			Tag:           strToPtr("5a1346f1"),
			Assettype:     strToPtr("Hostname"),
			Metadata:      &map[string]string{"program": "scan4Program", "team": "5a1346f1"},
			RequiredVars:  &[]string{"VAR1", "VAR2"},
			Timeout:       intToPtr(700),
		},
		{
			ID:            "38a779e8-5724-11eb-861d-acde48001122",
			Status:        "CREATED",
			ScanID:        "48fc7d46-53fc-11eb-ae93-0242ac130002",
			Target:        "host1.example.com",
			Progress:      floatToPtr(0),
			ScanIndex:     strToPtr("0_1"),
			ChecktypeID:   strToPtr("8f8727fe-55bc-11eb-ae93-0242ac130002"),
			ChecktypeName: strToPtr("vulcan-nessus"),
			Image:         strToPtr("example.com/vulcan-checks/vulcan-nessus:2"),
			Options:       strToPtr(`{"option":1}`),
			QueueName:     strToPtr("queue2"),
			Tag:           strToPtr("5a1346f1"),
			Assettype:     strToPtr("Hostname"),
			Metadata:      &map[string]string{"program": "scan4Program", "team": "5a1346f1"},
			RequiredVars:  &[]string{"VAR1"},
			Timeout:       intToPtr(100),
		},
		{
			ID:            "16103e20-5a70-11eb-ac57-acde48001122",
			Status:        "CREATED",
			ScanID:        "48fc7d46-53fc-11eb-ae93-0242ac130002",
			Target:        "192.168.0.1",
			Progress:      floatToPtr(0),
			ScanIndex:     strToPtr("1_0"),
			ChecktypeID:   strToPtr("8f8727fe-55bc-11eb-ae93-0242ac130002"),
			ChecktypeName: strToPtr("vulcan-docker"),
			Image:         strToPtr("example.com/vulcan-checks/vulcan-docker:1"),
			Options:       strToPtr("{}"),
			QueueName:     strToPtr(""),
			Tag:           strToPtr("5a1346f1"),
			Assettype:     strToPtr("IP"),
			Metadata:      &map[string]string{"program": "scan4Program", "team": "5a1346f1"},
			RequiredVars:  &[]string{},
			Timeout:       intToPtr(100),
		},
	}

	scan4Jobs = []inMemJobsSenderItem{
		{
			Job: Job{

				CheckID:       "ad11932b-e68f-48a9-bfab-5789a8aa20e8",
				AssetType:     "Hostname",
				Image:         checktypes["vulcan-http-headers"].Checktype.Image,
				ScanID:        scan4ID,
				Target:        "host1.example.com",
				ScanStartTime: time.Now(),
				Timeout:       *checktypes["vulcan-http-headers"].Checktype.Timeout,
				Options:       *checktypes["vulcan-http-headers"].Checktype.Options,
				Metadata:      map[string]string{"program": "scan4Program", "team": "5a1346f1"},
				RequiredVars:  checktypes["vulcan-http-headers"].Checktype.RequiredVars,
			},
			Queue:         *checktypes["vulcan-http-headers"].Checktype.QueueName,
			ChecktypeName: "vulcan-http-headers",
		},
		{
			Job: Job{
				CheckID:       "bdac576b-75db-42c1-86e0-d971f1c1ea67",
				ScanID:        "48fc7d46-53fc-11eb-ae93-0242ac130002",
				ScanStartTime: time.Now(),
				Image:         "example.com/vulcan-checks/vulcan-nessus:2",
				Target:        "host1.example.com",
				Timeout:       100,
				AssetType:     "Hostname",
				Options:       `{"option":1}`,
				RequiredVars:  []string{"VAR1"},
				Metadata:      map[string]string{"program": "scan4Program", "team": "5a1346f1"},
			},
			Queue:         "queue2",
			ChecktypeName: "vulcan-nessus",
		},
		{
			Job: Job{
				CheckID:      "c8d7e69e-5a74-11eb-8b36-acde48001122",
				ScanID:       "48fc7d46-53fc-11eb-ae93-0242ac130002",
				Image:        "example.com/vulcan-checks/vulcan-docker:1",
				Target:       "192.168.0.1",
				Timeout:      100,
				AssetType:    "IP",
				Options:      "{}",
				RequiredVars: []string{},
				Metadata:     map[string]string{"program": "scan4Program", "team": "5a1346f1"},
			},
			ChecktypeName: "vulcan-docker",
		},
	}
)

type inMemChecktypesInformer struct {
	Checktypes map[string]client.Checktype
}

func (i inMemChecktypesInformer) GetChecktype(name string) (*client.Checktype, error) {
	checktype, ok := i.Checktypes[name]
	if !ok {
		return nil, nil
	}
	return &checktype, nil
}

type inMemJobsSender struct {
	msgs []inMemJobsSenderItem
}

func (in *inMemJobsSender) Send(queueName string, checktypeName string, j Job) error {
	msgs := in.msgs
	msgs = append(msgs, inMemJobsSenderItem{
		Job:           j,
		Queue:         queueName,
		ChecktypeName: checktypeName,
	})
	in.msgs = msgs
	return nil
}

type inMemJobsSenderItem struct {
	Job           Job
	Queue         string
	ChecktypeName string
}

type inMemChecksListener struct {
	checks []api.Check
}

func (cl *inMemChecksListener) CheckUpdated(ch api.Check, programID string) {
	if cl.checks == nil {
		cl.checks = []api.Check{}
	}
	cl.checks = append(cl.checks, ch)
}

func TestChecksRunner_CreateScanChecks(t *testing.T) {
	type fields struct {
		store      Store
		sender     JobSender
		listener   CheckNotifier
		l          Logger
		pclient    ChecktypeInformer
		checkpoint int
	}

	tests := []struct {
		name         string
		fields       fields
		id           string
		stateChecker func(Store, JobSender, CheckNotifier, *testing.T)
		wantErr      bool
	}{
		{
			name: "HappyPath",
			fields: fields{
				l: log.NewNopLogger(),
				store: &inMemoryStore{
					scans: map[string]api.Scan{
						scan4ID: scan4,
					},
					checks: map[string]api.Check{},
				},
				listener: &inMemChecksListener{},
				pclient: inMemChecktypesInformer{
					Checktypes: checktypes,
				},
				sender:     &inMemJobsSender{},
				checkpoint: 2,
			},
			id: scan4ID,
			stateChecker: func(s Store, c JobSender, listener CheckNotifier, t *testing.T) {
				store := s.(*inMemoryStore)
				jobsStore := c.(*inMemJobsSender)
				// Copy the test scan.
				wantScan := scan4
				wantScan.ChecksCreated = intToPtr(3)
				wantScan.LastTargetCheckGCreated = intToPtr(1)
				wantScan.LastCheckCreated = intToPtr(-1)
				wantScan.TargetGroups = &[]api.TargetsChecktypesGroup{}
				gotScan := store.scans[scan4ID]
				scansDiff := cmp.Diff(wantScan, gotScan)
				if scansDiff != "" {
					t.Fatalf("stored scans, want!=got, diff:%s", scansDiff)
				}

				var gotChecks = []api.Check{}
				for _, c := range store.checks {
					gotChecks = append(gotChecks, c)
				}
				wantChecks := scan4Checks
				checksDiff := cmp.Diff(wantChecks, gotChecks, ChecksTrans, cmpopts.IgnoreFields(api.Check{}, "ID", "CreatedAt", "UpdatedAt", "Data"))
				if checksDiff != "" {
					t.Fatalf("stored checks, want!=got, diff:%s", checksDiff)
				}
				listenerStore := listener.(*inMemChecksListener)
				gotChecks = []api.Check{}
				gotChecks = append(gotChecks, listenerStore.checks...)
				wantChecksUpdated := scan4Checks
				checksUpdatedDiff := cmp.Diff(wantChecksUpdated, gotChecks, ChecksTrans, cmpopts.IgnoreFields(api.Check{}, "ID", "CreatedAt", "UpdatedAt", "Data"))
				if checksUpdatedDiff != "" {
					t.Fatalf("send updated checks to listener, want!=got, diff:%s", checksUpdatedDiff)
				}

				wantJobs := scan4Jobs
				gotJobs := jobsStore.msgs
				jobsDiff := cmp.Diff(wantJobs, gotJobs, JobsTrans, cmpopts.IgnoreFields(Job{}, "CheckID", "ScanStartTime"))
				if jobsDiff != "" {
					t.Fatalf("enqueued jobs, want!=got, diff:%s", jobsDiff)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &ChecksRunner{
				store:          tt.fields.store,
				sender:         tt.fields.sender,
				checksListener: tt.fields.listener,
				l:              tt.fields.l,
				ctinformer:     tt.fields.pclient,
				checkpoint:     tt.fields.checkpoint,
			}
			if err := c.CreateScanChecks(tt.id); (err != nil) != tt.wantErr {
				t.Errorf("ChecksCreator.CreateScanChecks() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			tt.stateChecker(c.store, c.sender, c.checksListener, t)
		})
	}
}

func Test_deepMergeJsons(t *testing.T) {
	tests := []struct {
		name    string
		jsonA   string
		jsonB   string
		want    string
		wantErr bool
	}{
		{
			name:  "HappyPath",
			jsonA: `{"prop1":true,"prop2":{"innerprop":"value"}}`,
			jsonB: `{"prop1":false,"prop2":{"innerprop":"othervalue"}}`,
			want:  `{"prop1":false,"prop2":{"innerprop":"othervalue"}}`,
		},
		{
			name:  "DoNotOverrideNotExistentPropsInJsonB",
			jsonA: `{"prop1":true,"prop2":{"innerprop":"value"}}`,
			jsonB: `{"prop2":{"innerprop":"othervalue"}}`,
			want:  `{"prop1":true,"prop2":{"innerprop":"othervalue"}}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := deepMergeJsons(tt.jsonA, tt.jsonB)
			if (err != nil) != tt.wantErr {
				t.Errorf("deepMergeJsons() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("deepMergeJsons() = %v, want %v", got, tt.want)
			}
		})
	}
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

func mustUUID2FromString(id string) uuid2.UUID {
	u, err := uuid2.FromString(id)
	if err != nil {
		panic(err)
	}
	return u
}

func mustUUIDFromString(id string) uuid.UUID {
	u, err := uuid.FromString(id)
	if err != nil {
		panic(err)
	}
	return u
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

func boolToPtr(val bool) *bool {
	return &val
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
