/*
Copyright 2021 Adevinta
*/

package apiclient

import (
	"context"
	"errors"
	"time"

	"github.com/adevinta/vulcan-core-cli/vulcan-core/client"
	"github.com/adevinta/vulcan-scan-engine/pkg/util"
)

var errChecktypeNotFound = errors.New("checktype no found")

type CachedAPIClient struct {
	cache  *util.Cache
	client *client.Client
}

// NewCachedAPIClient creates a api client that caches the results for indicated expiration.
func NewCachedAPIClient(api *client.Client, expiration time.Duration) *CachedAPIClient {
	c := util.NewCache(expiration)
	return &CachedAPIClient{
		client: api,
		cache:  &c,
	}
}

// GetChecktype retrieves the checktype with the indicated name
func (s *CachedAPIClient) GetChecktype(name string) (*client.Checktype, error) {
	enabled := "true"

	if x, found := s.cache.Get(name); found {
		return x.(*client.Checktype), nil
	}
	resp, err := s.client.IndexChecktypes(context.Background(), client.IndexChecktypesPath(), &enabled, &name)
	if err != nil {
		return nil, err
	}
	ct, err := s.client.DecodeChecktype(resp)
	if err != nil {
		return nil, err
	}
	if ct == nil {
		return nil, errChecktypeNotFound
	}
	s.cache.Set(name, ct)
	return ct, err
}

const assettypeKey = "assettypeskey"

// GetAssettypes retrieves the list of assettypes with the associated checktypes.
func (s *CachedAPIClient) GetAssettypes() (*client.AssettypeCollection, error) {
	if x, found := s.cache.Get(assettypeKey); found {
		return x.(*client.AssettypeCollection), nil
	}

	resp, err := s.client.IndexAssettypes(context.Background(), client.IndexAssettypesPath())
	if err != nil {
		return nil, err
	}
	assettypes, err := s.client.DecodeAssettypeCollection(resp)
	if err != nil {
		return nil, err
	}
	s.cache.Set(assettypeKey, &assettypes)
	return &assettypes, err
}
