/*
Copyright 2021 Adevinta
*/

package endpoint

import (
	"context"
	"testing"

	"github.com/adevinta/vulcan-scan-engine/pkg/testutil"
	"github.com/google/go-cmp/cmp"
)

type FakeHealthChecker struct {
	do func(context.Context) error
}

func (f FakeHealthChecker) Healthcheck(ctx context.Context) error {
	return (f.do(ctx))
}

func TestHealthcheckEndpoint(t *testing.T) {
	tests := []struct {
		req     interface{}
		srv     HealthChecker
		name    string
		want    interface{}
		wantErr error
	}{
		{
			name: "HealthcheckOK",
			srv: FakeHealthChecker{
				do: func(ctx context.Context) error {
					return nil
				},
			},
			want: Ok{
				Data: HealthcheckResponse{
					Status: "OK",
				},
			},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got, err := makeHealthcheckEndpoint(tt.srv)(context.Background(), tt.req)
			diff := cmp.Diff(testutil.ErrToStr(err), testutil.ErrToStr(tt.wantErr))
			if diff != "" {
				t.Fatalf("%v\n", diff)
			}

			diff = cmp.Diff(tt.want, got)
			if diff != "" {
				t.Errorf("%v\n", diff)
			}
		})
	}
}
