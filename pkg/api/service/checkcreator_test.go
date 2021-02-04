/*
Copyright 2021 Adevinta
*/

package service

import (
	"context"
	"net/http"
	"testing"

	"github.com/adevinta/vulcan-core-cli/vulcan-core/client"
	"github.com/adevinta/vulcan-scan-engine/pkg/api"
	"github.com/google/go-cmp/cmp"
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

func TestCheckCreator_CreateScanChecks(t *testing.T) {
	type args struct {
		ctx  context.Context
		scan api.Scan
	}
	tests := []struct {
		name     string
		informer AssettypeInformer
		args     args
		want     []*client.CheckPayload
		wantErr  bool
	}{
		{
			name: "CreatesChecksOnlyForValidAssetTypes",
			informer: &inMemoryAssettypeInformer{
				assetypes: client.AssettypeCollection{
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
						Name:      []string{},
					},
				},
			},
			args: args{
				scan: api.Scan{
					Tag:        strToPtr("tag"),
					ExternalID: strToPtr("extid"),
					TargetGroups: &[]api.TargetsChecktypesGroup{
						api.TargetsChecktypesGroup{
							ChecktypesGroup: api.ChecktypesGroup{
								Name: "default",
								Checktypes: []api.Checktype{
									api.Checktype{
										Name:    "vulcan-nessus",
										Options: `{"key":1}`,
									},
									api.Checktype{
										Name: "vulcan-aws-trusted-advisor",
									},
								},
							},
							TargetGroup: api.TargetGroup{
								Name: "default",
								Targets: []api.Target{
									api.Target{
										Identifier: "one.com",
										Type:       "Hostname",
										Options:    `{"key":2}`,
									},
									api.Target{
										Identifier: "127.0.0.1",
										Type:       "IP",
										Options:    `{"key":2}`,
									},
									api.Target{
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
			want: []*client.CheckPayload{
				&client.CheckPayload{
					Check: &client.CheckData{
						ChecktypeName: strToPtr("vulcan-nessus"),
						Tag:           strToPtr("tag"),
						Target:        "one.com",
						Assettype:     strToPtr("Hostname"),
						Options:       strToPtr(`{"key":2}`),
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &CheckCreator{
				assettypeInformer: tt.informer,
			}
			got, err := c.CreateScanChecks(tt.args.ctx, tt.args.scan)
			if (err != nil) != tt.wantErr {
				t.Errorf("CheckCreator.CreateScanChecks() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			diff := cmp.Diff(got, tt.want)
			if diff != "" {
				t.Errorf("CheckCreator.CreateScanChecks() got!=want, diff %s", diff)
				return
			}
		})
	}
}

func strToPtr(in string) *string {
	return &in
}

func Test_buildOptionsForCheck(t *testing.T) {
	type args struct {
		targetGroupOpts string
		targetOpts      string
		checktypeOpts   string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "OverridesOptionsWithPriority",
			args: args{
				checktypeOpts:   `{"key":"check"}`,
				targetGroupOpts: `{"key":"targetGroup"}`,
				targetOpts:      `{"key":"target"}`,
			},
			want: `{"key":"target"}`,
		},
		{
			name: "TakesIntoAccountEmptyOptions",
			args: args{
				checktypeOpts:   ``,
				targetGroupOpts: `{"key":"targetGroup"}`,
				targetOpts:      ``,
			},
			want: `{"key":"targetGroup"}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := buildOptionsForCheck(tt.args.checktypeOpts, tt.args.targetGroupOpts, tt.args.targetOpts)
			if (err != nil) != tt.wantErr {
				t.Errorf("buildOptionsForCheck() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("buildOptionsForCheck() = %v, want %v", got, tt.want)
			}
		})
	}
}
