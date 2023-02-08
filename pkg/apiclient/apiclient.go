/*
Copyright 2021 Adevinta
*/

package apiclient

import (
	"context"
	"errors"
	"time"

	"github.com/adevinta/vulcan-core-cli/vulcan-core/client"
	cache "github.com/patrickmn/go-cache"
)

var errChecktypeNotFound = errors.New("checktype no found")

type CachedApiClient struct {
	cache  *cache.Cache
	client *client.Client
}

func NewCachedChecktypeInformer(api *client.Client, expiration time.Duration) CachedApiClient {
	return CachedApiClient{
		client: api,
		cache:  cache.New(cache.DefaultExpiration, cache.DefaultExpiration),
	}
}

func (s CachedApiClient) GetChecktype(name string) (*client.Checktype, error) {
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
	s.cache.Set(name, ct, cache.DefaultExpiration)
	return ct, err
}

const assettypeKey = "assettypeskey"

func (s CachedApiClient) GetAssettypes() (*client.AssettypeCollection, error) {
	if x, found := s.cache.Get(assettypeKey); found {
		return x.(*client.AssettypeCollection), nil
	}

	resp, err := s.client.IndexAssettypes(context.Background(), client.IndexAssettypesPath())
	if err != nil {
		return nil, err
	}
	assettypes, err := s.client.DecodeAssettypeCollection(resp)
	s.cache.Set(assettypeKey, &assettypes, cache.DefaultExpiration)
	return &assettypes, err
}
