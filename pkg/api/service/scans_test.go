/*
Copyright 2021 Adevinta
*/

package service

import (
	"context"
	"os"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/go-kit/log"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	uuid "github.com/satori/go.uuid"

	"github.com/adevinta/errors"
	metrics "github.com/adevinta/vulcan-metrics-client"
	"github.com/adevinta/vulcan-scan-engine/pkg/api"
	"github.com/adevinta/vulcan-scan-engine/pkg/api/persistence"
	"github.com/adevinta/vulcan-scan-engine/pkg/checktypes"
	"github.com/adevinta/vulcan-scan-engine/pkg/stream"
)

var (
	statusRUNNING      = "RUNNING"
	ErrDocDoesNotExist = errors.NotFound("Document does not exists")
)

type fakeScansPersistence struct {
	ScanCreator              func(uuid.UUID, api.Scan) (int64, error)
	CheckUpsert              func(scanID, id uuid.UUID, check api.Check, updateStates []string) (int64, error)
	ScanChecksGetter         func(scanID uuid.UUID) ([]api.Check, error)
	ScanChecksByStatusGetter func(scanID uuid.UUID, status string) ([]api.Check, error)
	ScanStatsGetter          func(scanID uuid.UUID) (map[string]int, error)
	ScansGetter              func(offset, limit uint32) ([]api.Scan, error)
	ScanGetter               func(id uuid.UUID) (api.Scan, error)
	ScanUpdater              func(id uuid.UUID, scan api.Scan, updateStates []string) (int64, error)
	ScanByExternalIDGetter   func(ID string, offset, limit uint32) ([]api.Scan, error)
	ScanChecksRemover        func(scanID uuid.UUID) error
	ScanIDForCheckGetter     func(ID uuid.UUID) (uuid.UUID, error)
	CheckGetter              func(id uuid.UUID) (api.Check, error)
	FinishedCheckAdder       func(ID uuid.UUID) (int64, error)
	ScanStatusGetter         func(ID uuid.UUID) (api.Scan, error)
}

func (f fakeScansPersistence) CreateScan(id uuid.UUID, scan api.Scan) (int64, error) {
	return f.ScanCreator(id, scan)
}
func (f fakeScansPersistence) UpsertCheck(scanID, id uuid.UUID, check api.Check, updateStates []string) (int64, error) {
	return f.CheckUpsert(scanID, id, check, updateStates)
}
func (f fakeScansPersistence) GetScanChecks(scanID uuid.UUID) ([]api.Check, error) {
	return f.ScanChecksGetter(scanID)
}
func (f fakeScansPersistence) GetScanChecksByStatus(scanID uuid.UUID, status string) ([]api.Check, error) {
	return f.ScanChecksByStatusGetter(scanID, status)
}
func (f fakeScansPersistence) GetScans(offset, limit uint32) ([]api.Scan, error) {
	return f.ScansGetter(offset, limit)
}
func (f fakeScansPersistence) GetScanByID(id uuid.UUID) (api.Scan, error) {
	return f.ScanGetter(id)
}
func (f fakeScansPersistence) UpdateScan(id uuid.UUID, scan api.Scan, updateStates []string) (int64, error) {
	return f.ScanUpdater(id, scan, updateStates)
}

func (f fakeScansPersistence) GetScansByExternalID(ID string, offset, limit uint32) ([]api.Scan, error) {
	return f.ScanByExternalIDGetter(ID, offset, limit)
}

func (f fakeScansPersistence) GetScanStats(scanID uuid.UUID) (map[string]int, error) {
	return f.ScanStatsGetter(scanID)
}

func (f fakeScansPersistence) DeleteScanChecks(scanID uuid.UUID) error {
	return f.ScanChecksRemover(scanID)
}

func (f fakeScansPersistence) GetScanIDForCheck(ID uuid.UUID) (uuid.UUID, error) {
	return f.ScanIDForCheckGetter(ID)
}

func (f fakeScansPersistence) GetCheckByID(id uuid.UUID) (api.Check, error) {
	return f.CheckGetter(id)
}

func (f fakeScansPersistence) AddCheckAsFinished(checkID uuid.UUID) (int64, error) {
	return f.FinishedCheckAdder(checkID)
}

func (f fakeScansPersistence) GetScanStatus(ID uuid.UUID) (api.Scan, error) {
	return f.ScanStatusGetter(ID)
}

type inMemoryAssettypeInformer struct {
	assetypes checktypes.AssettypeCollection
}

func (i *inMemoryAssettypeInformer) GetAssettypes() (*checktypes.AssettypeCollection, error) {
	return &i.assetypes, nil
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
			ScansGetter: func(offset, limit uint32) ([]api.Scan, error) {
				// TODO: handle offset and limit
				snapshot := []api.Scan{}
				scans.Range(func(k, v interface{}) bool {
					current := v.(api.Scan)
					snapshot = append(snapshot, current)
					return true
				})
				return snapshot, nil
			},
			ScanGetter: func(id uuid.UUID) (api.Scan, error) {
				s, ok := scans.Load(id)
				if !ok {
					return api.Scan{}, errors.NotFound(nil)
				}
				scan := s.(api.Scan)
				return scan, nil
			},
			ScanChecksGetter: func(scanID uuid.UUID) ([]api.Check, error) {
				return []api.Check{}, nil
			},
			ScanStatsGetter: func(scanID uuid.UUID) (map[string]int, error) {
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
			ScanByExternalIDGetter: func(ID string, offset, limit uint32) ([]api.Scan, error) {
				// TODO: handle offset and limit
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

type mockStreamClient struct {
	abortFunc func(ctx context.Context, checks []string) error
}

func (m *mockStreamClient) AbortChecks(ctx context.Context, checks []string) error {
	return m.abortFunc(ctx, checks)
}

func TestScansService_CreateScan(t *testing.T) {
	date := time.Date(2019, time.March, 4, 10, 0, 0, 0, time.UTC)
	type fields struct {
		db                 inMemoryStore
		logger             log.Logger
		checktypesInformer ChecktypesInformer
		metricsClient      metrics.Client
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
			name: "CreateAndStoreScans",
			fields: fields{
				db:            newInMemoryStore(new(sync.Map)),
				logger:        log.NewLogfmtLogger(os.Stdout),
				metricsClient: &mockMetricsClient{},
				checktypesInformer: &inMemoryAssettypeInformer{
					assetypes: checktypes.AssettypeCollection{
						checktypes.Assettype{
							Assettype: "",
							Name: []string{
								"vulcan-no-exec",
							},
						},
						checktypes.Assettype{
							Assettype: "Hostname",
							Name: []string{
								"vulcan-nessus",
							},
						},
						checktypes.Assettype{
							Assettype: "DomainName",
							Name: []string{
								"vulcan-spf",
							},
						},
						checktypes.Assettype{
							Assettype: "IP",
							Name:      []string{},
						},
					},
				},
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
				Status:         &statusRUNNING,
				CheckCount:     intToPtr(1),
				ChecksCreated:  intToPtr(0),
				ChecksFinished: intToPtr(0),
				Progress:       floatToPtr(0.0),
				ChecktypesInfo: &api.ChecktypesByAssettypes{"DomainName": {"vulcan-spf": {}}, "Hostname": {"vulcan-nessus": {}}, "IP": {}},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := ScansService{
				db:            tt.fields.db,
				logger:        tt.fields.logger,
				ctInformer:    tt.fields.checktypesInformer,
				metricsClient: tt.fields.metricsClient,
			}
			got, err := s.CreateScan(tt.args.ctx, tt.args.scan)
			if (err != nil) != tt.wantErr {
				t.Errorf("ScansService.CreateScan() error = %v, wantErr %v", err, tt.wantErr)
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
				if gotScan.ID.String() != got.String() {
					t.Errorf("gotScanID != storedScanID %s, %s", gotScan.ID.String(), got.String())
				}

				diff := cmp.Diff(gotScan, *tt.wantScan, cmpopts.IgnoreFields(api.Scan{}, "ID", "StartTime"))
				if diff != "" {
					t.Errorf("gotScan != wantScan.diff %v", diff)
				}
			}

		})
	}
}

func TestScansService_AbortScan(t *testing.T) {
	type fields struct {
		storeCreator        func() persistence.ScansStore
		streamClientCreator func() stream.Client
		logger              log.Logger
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
			name: "PushMessageToAbort",
			fields: fields{
				storeCreator: func() persistence.ScansStore {
					scans := new(sync.Map)
					id, _ := uuid.FromString("b3b5af18-4e1d-11e8-9c2d-fa7ae01bbebd")
					scans.Store(id, api.Scan{
						ID: id,
					})
					return newInMemoryStore(scans)
				},
				streamClientCreator: func() stream.Client {
					return &mockStreamClient{
						abortFunc: func(ctx context.Context, checks []string) error {
							return nil // push OK
						},
					}
				},
				logger: log.NewLogfmtLogger(os.Stdout),
			},
			args: args{
				ctx:    context.Background(),
				scanID: "b3b5af18-4e1d-11e8-9c2d-fa7ae01bbebd",
			},
		},
		{
			name: "ReturnsNotFoundIfScanDoesNotExist",
			fields: fields{
				storeCreator: func() persistence.ScansStore {
					return newInMemoryStore(new(sync.Map))
				},
				streamClientCreator: func() stream.Client {
					return nil
				},
				logger: log.NewLogfmtLogger(os.Stdout),
			},
			args: args{
				ctx:    context.Background(),
				scanID: "b3b5af18-4e1d-11e8-9c2d-fa7ae01bbebd",
			},
			wantErr: errors.NotFound(nil),
		},
		{
			name: "ReturnsErrorIfStreamCommunicationFails",
			fields: fields{
				storeCreator: func() persistence.ScansStore {
					return newInMemoryStore(new(sync.Map))
				},
				streamClientCreator: func() stream.Client {
					return &mockStreamClient{
						abortFunc: func(ctx context.Context, checks []string) error {
							return errors.Default(nil)
						},
					}
				},
				logger: log.NewLogfmtLogger(os.Stdout),
			},
			args: args{
				ctx:    context.Background(),
				scanID: "b3b5af18-4e1d-11e8-9c2d-fa7ae01bbebd",
			},
			wantErr: errors.Default(nil),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := ScansService{
				db:           tt.fields.storeCreator(),
				streamClient: tt.fields.streamClientCreator(),
				logger:       tt.fields.logger,
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
		name string
		c    api.States
		args args
		want []string
	}{
		{
			name: "GetAllStates",
			c:    api.CheckStates,
			args: args{
				s: "FINISHED",
			},
			want: func() []string {
				res := []string{}
				for _, v := range api.CheckStates {
					res = append(res, v...)
				}
				return res
			}(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.c.LessOrEqual(tt.args.s)
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
