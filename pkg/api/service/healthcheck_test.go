/*
Copyright 2021 Adevinta
*/

package service

import (
	"context"
	"errors"
	"testing"

	"github.com/adevinta/vulcan-scan-engine/pkg/testutil"
	"github.com/google/go-cmp/cmp"
)

type FakeHealthcheckPersistence struct {
	do func() error
}

func (f FakeHealthcheckPersistence) Ping() error {
	return f.do()
}
func TestHealthcheckOk(t *testing.T) {
	anError := errors.New("One weird error")
	tests := []struct {
		name        string
		persistence FakeHealthcheckPersistence
		wantErr     error
	}{
		{
			name: "HealthcheckOK",
			persistence: FakeHealthcheckPersistence{
				do: func() error {
					return nil
				},
			},
			wantErr: nil,
		},
		{
			name: "HealthcheckDOWN",
			persistence: FakeHealthcheckPersistence{
				do: func() error {
					return anError
				},
			},
			wantErr: anError,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			s := HealthcheckService{
				DB: tt.persistence,
			}
			err := s.Healthcheck(context.Background())
			diff := cmp.Diff(testutil.ErrToStr(err), testutil.ErrToStr(tt.wantErr))
			if diff != "" {
				t.Fatalf("%v\n", diff)
			}
		})
	}
}
