/*
Copyright 2021 Adevinta
*/

package apiclient

import (
	"context"
	"errors"
	"time"

	"github.com/adevinta/vulcan-scan-engine/pkg/checktypes"
	"github.com/adevinta/vulcan-scan-engine/pkg/util"
)

var errChecktypeNotFound = errors.New("checktype no found")

type CachedAPIClient struct {
	cache  *util.Cache
	client *checktypes.Client
}

// NewCachedAPIClient creates an api client that caches the results for indicated expiration.
func NewCachedAPIClient(api *checktypes.Client, expiration time.Duration) *CachedAPIClient {
	c := util.NewCache(expiration)
	return &CachedAPIClient{
		client: api,
		cache:  &c,
	}
}

// GetChecktype retrieves the checktype with the indicated name.
func (s *CachedAPIClient) GetChecktype(name string) (*checktypes.Checktype, error) {
	if x, found := s.cache.Get(name); found {
		return x.(*checktypes.Checktype), nil
	}
	resp, err := s.client.GetChecktype(context.Background(), name)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, errChecktypeNotFound
	}
	s.cache.Set(name, resp)
	return resp, err
}

const assettypeKey = "assettypeskey"

// GetAssettypes retrieves the list of assettypes with the associated checktypes.
func (s *CachedAPIClient) GetAssettypes() (*checktypes.AssettypeCollection, error) {
	if x, found := s.cache.Get(assettypeKey); found {
		return x.(*checktypes.AssettypeCollection), nil
	}

	resp, err := s.client.GetAssettypes(context.Background())
	if err != nil {
		return nil, err
	}
	s.cache.Set(assettypeKey, &resp)
	return &resp, err
}
