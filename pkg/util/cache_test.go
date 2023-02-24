package util

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func Test_cache(t *testing.T) {
	tests := []struct {
		name       string
		expiration time.Duration
		wait       time.Duration
		setup      map[string]string
		want       map[string]string
		notFound   []string
	}{
		{
			name:       "HappyPath",
			expiration: time.Second * 10,
			setup:      map[string]string{"a": "1", "b": "2"},
			wait:       time.Second * 0,
			want:       map[string]string{"a": "1", "b": "2"},
			notFound:   []string{"c"},
		},
		{
			name:       "Expired",
			expiration: time.Second * 1,
			setup:      map[string]string{"a": "1"},
			wait:       time.Second * 2,
			want:       map[string]string{},
			notFound:   []string{"a", "b"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCache(tt.expiration)
			for k, v := range tt.setup {
				c.Set(k, v)
			}
			time.Sleep(tt.wait)
			for k, v := range tt.want {
				c, found := c.Get(k)
				if !found {
					t.Errorf("key %s not found", k)
					continue
				}
				vDiff := cmp.Diff(v, c)
				if vDiff != "" {
					t.Fatalf("cache value mismatch, diff:%s", vDiff)
				}
			}
			for _, k := range tt.notFound {
				_, found := c.Get(k)
				if found {
					t.Errorf("key %s found. Should be expired", k)
				}
			}
		})
	}
}
