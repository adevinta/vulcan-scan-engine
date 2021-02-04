/*
Copyright 2021 Adevinta
*/

package service

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-kit/kit/log"
	goauuid "github.com/goadesign/goa/uuid"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	uuid "github.com/satori/go.uuid"

	"github.com/adevinta/errors"
	"github.com/adevinta/vulcan-core-cli/vulcan-core/client"
	metrics "github.com/adevinta/vulcan-metrics-client"
	"github.com/adevinta/vulcan-scan-engine/pkg/api"
)

var (
	baseModelFieldNames = []string{"StartTime"}
	ignoreFieldsScan    = cmpopts.IgnoreFields(api.Scan{}, baseModelFieldNames...)
	statusRUNNING       = "RUNNING"
	ErrDocDoesNotExist  = errors.NotFound("Document does not exists")
	assettypes          = client.AssettypeCollection{
		&client.Assettype{
			Assettype: nil,
			Name: []string{
				"vulcan-no-exec",
			},
		},
		&client.Assettype{
			Assettype: strToPtr("Hostname"),
			Name: []string{
				"vulcan-nessus",
				"vulcan-aws-trusted-advisor",
			},
		},
		&client.Assettype{
			Assettype: strToPtr("DomainName"),
			Name: []string{
				"vulcan-spf",
			},
		},
		&client.Assettype{
			Assettype: strToPtr("IP"),
			Name:      []string{"vulcan-exposed-amt"},
		},
	}

	testCheckCreator = CheckCreator{
		assettypeInformer: &inMemoryAssettypeInformer{
			assetypes: assettypes,
		},
	}
)

func Test_mergeOptions(t *testing.T) {
	type args struct {
		optsA map[string]interface{}
		optsB map[string]interface{}
	}
	tests := []struct {
		name string
		args args
		want map[string]interface{}
	}{
		{
			name: "MergesNonIntersectingOptions",
			args: args{
				optsA: map[string]interface{}{"a": "value1"},
				optsB: map[string]interface{}{"b": 2},
			},
			want: map[string]interface{}{"a": "value1", "b": 2},
		},
		{
			name: "OverridesIntersectingOptions",
			args: args{
				optsA: map[string]interface{}{"a": "value1"},
				optsB: map[string]interface{}{"a": "value2", "c": "value3"},
			},
			want: map[string]interface{}{"a": "value2", "c": "value3"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mergeOptions(tt.args.optsA, tt.args.optsB)
			diff := cmp.Diff(got, tt.want)
			if diff != "" {
				t.Errorf("Error got!=want. Diff:\n %s", diff)
			}
		})
	}
}

type fakeScansPersistence struct {
	ScanCreator             func(uuid.UUID, api.Scan) (int64, error)
	CheckUpsert             func(scanID, id uuid.UUID, check api.Check, updateStates []string) (int64, error)
	ScanCheckGetter         func(scanID uuid.UUID) ([]api.Check, error)
	ChecksStatusStatsGetter func(scanID uuid.UUID) (map[string]int, error)
	ScanGetter              func(id uuid.UUID) (api.Scan, error)
	ScanUpdater             func(id uuid.UUID, scan api.Scan, updateStates []string) (int64, error)
	ScanBYExternalIDGetter  func(ID string, limit *uint32) ([]api.Scan, error)
	ScanChecksRemover       func(scanID uuid.UUID) error
}

func (f fakeScansPersistence) CreateScan(id uuid.UUID, scan api.Scan) (int64, error) {
	return f.ScanCreator(id, scan)
}
func (f fakeScansPersistence) UpsertCheck(scanID, id uuid.UUID, check api.Check, updateStates []string) (int64, error) {
	return f.CheckUpsert(scanID, id, check, updateStates)
}
func (f fakeScansPersistence) GetScanChecks(scanID uuid.UUID) ([]api.Check, error) {
	return f.ScanCheckGetter(scanID)
}
func (f fakeScansPersistence) GetScanByID(id uuid.UUID) (api.Scan, error) {
	return f.ScanGetter(id)
}
func (f fakeScansPersistence) UpdateScan(id uuid.UUID, scan api.Scan, updateStates []string) (int64, error) {
	return f.ScanUpdater(id, scan, updateStates)
}

func (f fakeScansPersistence) AddEvent(scanID uuid.UUID, e api.Event) (int64, error) {
	return 1, nil
}

func (f fakeScansPersistence) AddMalformedEvent(e api.MalformedEvent) (int64, error) {
	return 1, nil
}

func (f fakeScansPersistence) GetScansByExternalIDWithLimit(ID string, limit *uint32) ([]api.Scan, error) {
	return f.ScanBYExternalIDGetter(ID, limit)
}

func (f fakeScansPersistence) GetChecksStatusStats(scanID uuid.UUID) (map[string]int, error) {
	return f.ChecksStatusStatsGetter(scanID)
}

func (f fakeScansPersistence) DeleteScanChecks(scanID uuid.UUID) error {
	return f.ScanChecksRemover(scanID)
}

type fakeVulcanCoreAPI struct {
	FileScanUploader func(context.Context, string, *client.FileScanPayload) (*http.Response, error)
	ScanAborter      func(ctx context.Context, path string) (*http.Response, error)
	ScanDecoder      func(resp *http.Response) (*client.Scan, error)
	AssetTypeIndexer func(ctx context.Context, path string) (*http.Response, error)
	AssettypeDecoder func(resp *http.Response) (client.AssettypeCollection, error)
}

func (f fakeVulcanCoreAPI) UploadFileScans(ctx context.Context, path string, payload *client.FileScanPayload) (*http.Response, error) {
	return f.FileScanUploader(ctx, path, payload)
}

func (f fakeVulcanCoreAPI) AbortScans(ctx context.Context, path string) (*http.Response, error) {
	return f.ScanAborter(ctx, path)
}

func (f fakeVulcanCoreAPI) DecodeScan(resp *http.Response) (*client.Scan, error) {
	return f.ScanDecoder(resp)
}

func (f fakeVulcanCoreAPI) IndexAssettypes(ctx context.Context, path string) (*http.Response, error) {
	return f.AssetTypeIndexer(ctx, path)
}
func (f fakeVulcanCoreAPI) DecodeAssettypeCollection(resp *http.Response) (client.AssettypeCollection, error) {
	return f.AssettypeDecoder(resp)
}

type fixedIDVulcanCoreAPI struct {
	scans *sync.Map
	fakeVulcanCoreAPI
}

func newFixedIDVulcanCoreAPI(id string, scans *sync.Map, at AssettypeInformer) fixedIDVulcanCoreAPI {
	api := fixedIDVulcanCoreAPI{
		scans: scans,
		fakeVulcanCoreAPI: fakeVulcanCoreAPI{
			FileScanUploader: func(ctx context.Context, path string, payLoad *client.FileScanPayload) (*http.Response, error) {
				content, err := ioutil.ReadFile(payLoad.Upload)
				if err != nil {
					return nil, err
				}
				scan := client.ScanPayload{}
				err = json.Unmarshal(content, &scan)
				if err != nil {
					return nil, err
				}
				id, err := goauuid.FromString(id)
				if err != nil {
					return nil, err
				}
				scans.Store(id, scan)
				data := client.Scandata{
					ID:   id,
					Size: len(scan.Scan.Checks),
				}
				ret := client.Scan{
					Scan: &data,
				}
				content, err = json.Marshal(ret)
				if err != nil {
					return nil, err
				}
				recorder := httptest.NewRecorder()
				recorder.WriteHeader(http.StatusCreated)
				recorder.WriteString(string(content))

				return recorder.Result(), nil
			},
			ScanDecoder: func(resp *http.Response) (*client.Scan, error) {
				content, err := ioutil.ReadAll(resp.Body)
				if err != nil {
					return nil, err
				}
				scan := client.Scan{}
				err = json.Unmarshal(content, &scan)
				if err != nil {
					return nil, err
				}
				return &scan, err
			},
			AssetTypeIndexer: func(ctx context.Context, path string) (*http.Response, error) {
				return at.IndexAssettypes(ctx, path)
			},
			AssettypeDecoder: func(resp *http.Response) (client.AssettypeCollection, error) {
				return at.DecodeAssettypeCollection(resp)
			},
		},
	}
	return api
}

type inMemoryStore struct {
	scans *sync.Map
	fakeScansPersistence
}

func newInMemoryStore(scans *sync.Map) inMemoryStore {
	store := inMemoryStore{
		scans: scans,
		fakeScansPersistence: fakeScansPersistence{
			ScanCreator: func(id uuid.UUID, scan api.Scan) (int64, error) {
				scans.Store(id, scan)
				return 1, nil
			},
			ScanGetter: func(id uuid.UUID) (api.Scan, error) {
				s, ok := scans.Load(id)
				if !ok {
					return api.Scan{}, errors.NotFound(nil)
				}
				scan := s.(api.Scan)
				return scan, nil
			},
			ScanCheckGetter: func(scanID uuid.UUID) ([]api.Check, error) {
				return []api.Check{}, nil
			},
			ChecksStatusStatsGetter: func(scanID uuid.UUID) (map[string]int, error) {
				return map[string]int{}, nil
			},
			ScanUpdater: func(id uuid.UUID, scan api.Scan, updateStates []string) (int64, error) {
				var current api.Scan
				s, ok := scans.Load(id)
				if ok {
					current = s.(api.Scan)
				}
				// Merge the data
				current.Status = scan.Status
				scans.Store(id, current)
				return 1, nil
			},
			ScanBYExternalIDGetter: func(ID string, limit *uint32) ([]api.Scan, error) {
				snapshot := []api.Scan{}
				scans.Range(func(k, v interface{}) bool {
					current := v.(api.Scan)
					if current.ExternalID == nil {
						return true
					}
					id := *current.ExternalID
					if id == ID {
						snapshot = append(snapshot, current)
					}
					return true
				})
				return snapshot, nil
			},
			ScanChecksRemover: func(scanID uuid.UUID) error {
				scans.Delete(scanID)
				return nil
			},
		},
	}
	return store
}

type mockMetricsClient struct {
	metrics.Client
}

func (mc *mockMetricsClient) Push(m metrics.Metric)              {}
func (mc *mockMetricsClient) PushWithRate(m metrics.RatedMetric) {}

func TestScansService_CreateScan(t *testing.T) {
	date := time.Date(2019, time.March, 4, 10, 0, 0, 0, time.UTC)
	type fields struct {
		db            inMemoryStore
		logger        log.Logger
		vulcanCore    CoreAPI
		ccreator      CheckCreator
		metricsClient metrics.Client
	}
	type args struct {
		ctx  context.Context
		scan *api.Scan
	}
	tests := []struct {
		name     string
		fields   fields
		args     args
		want     uuid.UUID
		wantScan *api.Scan
		wantErr  bool
	}{
		{
			name: "CreateAndStoreNewScan",
			fields: fields{
				db:            newInMemoryStore(new(sync.Map)),
				logger:        log.NewLogfmtLogger(os.Stdout),
				vulcanCore:    newFixedIDVulcanCoreAPI("b3b5af18-4e1d-11e8-9c2d-fa7ae01bbebd", new(sync.Map), &inMemoryAssettypeInformer{}),
				metricsClient: &mockMetricsClient{},
			},
			args: args{
				ctx: context.Background(),
				scan: &api.Scan{
					ChecktypesGroup: &api.ChecktypesGroup{
						Name: "OneGroup",
						Checktypes: []api.Checktype{
							{
								Name:    "onecheck",
								Options: `{"port":"8080"}`,
							},
						},
					},
					Targets: &api.TargetGroup{
						Name: "OneGroup",
						Targets: []api.Target{
							{Identifier: "localhost"},
						},
					},
				},
			},
			want: func() uuid.UUID {
				id, _ := uuid.FromString("b3b5af18-4e1d-11e8-9c2d-fa7ae01bbebd")
				return id
			}(),
			wantScan: &api.Scan{
				ID: func() uuid.UUID {
					id, _ := uuid.FromString("b3b5af18-4e1d-11e8-9c2d-fa7ae01bbebd")
					return id
				}(),
				ChecktypesGroup: &api.ChecktypesGroup{
					Name: "OneGroup",
					Checktypes: []api.Checktype{
						{
							Name:    "onecheck",
							Options: `{"port":"8080"}`,
						},
					},
				},
				Status: &statusRUNNING,
				Targets: &api.TargetGroup{
					Name: "OneGroup",
					Targets: []api.Target{
						{Identifier: "localhost"},
					},
				},
				CheckCount: intToPtr(1),
			},
		},

		{
			name: "UseMultipleTargetGroups",
			fields: fields{
				db:     newInMemoryStore(new(sync.Map)),
				logger: log.NewLogfmtLogger(os.Stdout),
				vulcanCore: newFixedIDVulcanCoreAPI("b3b5af18-4e1d-11e8-9c2d-fa7ae01bbebe", new(sync.Map), &inMemoryAssettypeInformer{
					assetypes: assettypes,
				}),
				ccreator:      testCheckCreator,
				metricsClient: &mockMetricsClient{},
			},
			args: args{
				ctx: context.Background(),
				scan: &api.Scan{
					ScheduledTime: &date,
					TargetGroups: &[]api.TargetsChecktypesGroup{
						{
							ChecktypesGroup: api.ChecktypesGroup{
								Name: "default",
								Checktypes: []api.Checktype{
									{
										Name:    "vulcan-nessus",
										Options: `{"key":1}`,
									},
									{
										Name: "vulcan-aws-trusted-advisor",
									},
								},
							},
							TargetGroup: api.TargetGroup{
								Name: "default",
								Targets: []api.Target{
									{
										Identifier: "one.com",
										Type:       "Hostname",
										Options:    `{"key":2}`,
									},
									{
										Identifier: "127.0.0.1",
										Type:       "IP",
										Options:    `{"key":2}`,
									},
									{
										Identifier: "one.com",
										Type:       "DomainName",
										Options:    `{"key":3}`,
									},
								},
							},
						},
					},
				},
			},
			want: func() uuid.UUID {
				id, _ := uuid.FromString("b3b5af18-4e1d-11e8-9c2d-fa7ae01bbebe")
				return id
			}(),
			wantScan: &api.Scan{
				ID: func() uuid.UUID {
					id, _ := uuid.FromString("b3b5af18-4e1d-11e8-9c2d-fa7ae01bbebe")
					return id
				}(),
				ScheduledTime: &date,
				TargetGroups: &[]api.TargetsChecktypesGroup{
					{
						TargetGroup: api.TargetGroup{Name: "default",
							Targets: []api.Target{
								{
									Identifier: "one.com", Type: "Hostname", Options: `{"key":2}`,
								},
								{
									Identifier: "127.0.0.1", Type: "IP",
									Options: `{"key":2}`},
								{
									Identifier: "one.com",
									Type:       "DomainName",
									Options:    `{"key":3}`}}},
						ChecktypesGroup: api.ChecktypesGroup{
							Name: "default",
							Checktypes: []api.Checktype{
								{
									Name:    "vulcan-nessus",
									Options: `{"key":1}`,
								},
								{
									Name: "vulcan-aws-trusted-advisor",
								},
							},
						},
					},
				},
				Status:     &statusRUNNING,
				CheckCount: intToPtr(2),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := ScansService{
				db:            tt.fields.db,
				logger:        tt.fields.logger,
				vulcanCore:    tt.fields.vulcanCore,
				ccreator:      &tt.fields.ccreator,
				metricsClient: tt.fields.metricsClient,
			}
			got, err := s.CreateScan(tt.args.ctx, tt.args.scan)
			if (err != nil) != tt.wantErr {
				t.Errorf("ScansService.CreateScan() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ScansService.CreateScan() = %v, want %v", got, tt.want)
				return
			}

			if tt.wantScan != nil {
				val, ok := tt.fields.db.scans.Load(got)
				if !ok {
					t.Error("Expected scan not stored in db.")
					return
				}
				gotScan, ok := val.(api.Scan)
				if !ok {
					t.Error("Got scan not found")
					return
				}
				diff := cmp.Diff(gotScan, *tt.wantScan, ignoreFieldsScan)
				if diff != "" {
					t.Errorf("gotScan != wantScan.diff %v", diff)
				}
			}

		})
	}
}

func TestScansService_AbortScan(t *testing.T) {
	type fields struct {
		storeCreator func() ScansPersistence
		logger       log.Logger
		vulcanCore   CoreAPI
	}
	type args struct {
		ctx    context.Context
		scanID string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr error
	}{
		{
			name: "CallsCoreToAbortAGivenScan",
			fields: fields{
				storeCreator: func() ScansPersistence {
					scans := new(sync.Map)
					id, _ := uuid.FromString("b3b5af18-4e1d-11e8-9c2d-fa7ae01bbebd")
					scans.Store(id, api.Scan{
						ID: id,
					})
					return newInMemoryStore(scans)
				},
				logger: log.NewLogfmtLogger(os.Stdout),
				vulcanCore: fakeVulcanCoreAPI{
					ScanAborter: func(ctx context.Context, path string) (*http.Response, error) {
						u, err := url.Parse(path)
						if err != nil {
							return nil, err
						}
						parts := strings.Split(u.Path, "/")
						correct := len(parts) == 5 && parts[2] == "scans" &&
							parts[3] == "b3b5af18-4e1d-11e8-9c2d-fa7ae01bbebd" &&
							parts[4] == "abort"
						recorder := httptest.NewRecorder()
						if correct {
							recorder.WriteHeader(http.StatusAccepted)
							return recorder.Result(), nil
						}
						return nil, errors.Default("unexpected path ")
					},
				},
			},
			args: args{
				ctx:    context.Background(),
				scanID: "b3b5af18-4e1d-11e8-9c2d-fa7ae01bbebd",
			},
		},
		{
			name: "ReturnsNotFoundIfScanDoesNotExist",
			fields: fields{
				storeCreator: func() ScansPersistence {
					return newInMemoryStore(new(sync.Map))
				},
				logger:     log.NewLogfmtLogger(os.Stdout),
				vulcanCore: fakeVulcanCoreAPI{},
			},
			args: args{
				ctx:    context.Background(),
				scanID: "b3b5af18-4e1d-11e8-9c2d-fa7ae01bbebd",
			},
			wantErr: errors.NotFound(nil),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := ScansService{
				db:         tt.fields.storeCreator(),
				logger:     tt.fields.logger,
				vulcanCore: tt.fields.vulcanCore,
			}
			err := s.AbortScan(tt.args.ctx, tt.args.scanID)
			if errorToStr(err) != errorToStr(tt.wantErr) {
				t.Errorf("ScansService.AbortScan() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
func Test_states_LessOrEqual(t *testing.T) {
	type args struct {
		s string
	}
	tests := []struct {
		name    string
		c       states
		args    args
		want    []string
		wantErr bool
	}{
		{
			name: "GetAllStates",
			c:    checkStates,
			args: args{
				s: "FINISHED",
			},
			want: func() []string {
				res := []string{}
				for _, v := range checkStates {
					res = append(res, v...)
				}
				return res
			}(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.c.LessOrEqual(tt.args.s)
			if (err != nil) != tt.wantErr {
				t.Errorf("states.LessOrEqual() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("states.LessOrEqual() = %v, want %v", got, tt.want)
			}
		})
	}
}

func errorToStr(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func intToPtr(in int) *int {
	return &in
}

func floatToPtr(in float32) *float32 {
	return &in
}

func Test_statusFromChecks(t *testing.T) {
	type args struct {
		scanID     uuid.UUID
		checkStats map[string]int
		n          float32
	}
	tests := []struct {
		name string
		args args
		want api.Scan
	}{
		{
			name: "RunningWhenNotAllChecksFinished",
			args: args{
				scanID: uuid.FromStringOrNil("b3b5af18-4e1d-11e8-9c2d-fa7ae01bbebd"),
				checkStats: map[string]int{
					"FINISHED": 5,
					"RUNNING":  1,
				},
				n: 10,
			},
			want: api.Scan{
				ID:       uuid.FromStringOrNil("b3b5af18-4e1d-11e8-9c2d-fa7ae01bbebd"),
				Status:   strToPtr(statusRUNNING),
				Progress: floatToPtr(0.5),
			},
		},
		{
			name: "FinishedWhenAllChecksAreInFinalStatus",
			args: args{
				scanID: uuid.FromStringOrNil("b3b5af18-4e1d-11e8-9c2d-fa7ae01bbebd"),
				checkStats: map[string]int{
					"FINISHED": 5,
					"FAILED":   5,
				},
				n: 10,
			},
			want: api.Scan{
				ID:       uuid.FromStringOrNil("b3b5af18-4e1d-11e8-9c2d-fa7ae01bbebd"),
				Status:   strToPtr(ScanStatusFinished),
				Progress: floatToPtr(1),
			},
		},
		{
			name: "FinishedWhenAllChecksAreInFinalStatus",
			args: args{
				scanID: uuid.FromStringOrNil("b3b5af18-4e1d-11e8-9c2d-fa7ae01bbebd"),
				checkStats: map[string]int{
					"FINISHED": 5,
					"FAILED":   4,
					"ABORTED":  1,
				},
				n: 10,
			},
			want: api.Scan{
				ID:       uuid.FromStringOrNil("b3b5af18-4e1d-11e8-9c2d-fa7ae01bbebd"),
				Status:   strToPtr(ScanStatusAborted),
				Progress: floatToPtr(1),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			got := statusFromChecks(tt.args.scanID, tt.args.checkStats, tt.args.n, log.NewNopLogger())
			diff := cmp.Diff(tt.want, got, cmpopts.IgnoreFields(api.Scan{}, "EndTime"))
			if diff != "" {
				t.Errorf("want!=got, diff: %s", diff)
			}
		})
	}
}
