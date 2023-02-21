package util

import (
	"sync"
	"time"
)

type element struct {
	Value      interface{}
	Expiration time.Time
}

type Cache struct {
	data       map[string]element
	expiration time.Duration
	mu         sync.Mutex
}

func NewCache(expiration time.Duration) Cache {
	return Cache{
		data:       map[string]element{},
		expiration: expiration,
	}
}

// Set stores the value associated with the key for the expiration.
func (c *Cache) Set(key string, value interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data[key] = element{
		Value:      value,
		Expiration: time.Now().Add(c.expiration),
	}
}

// Get retrieves the value associated with the key in case it exists and is not expired
func (c *Cache) Get(key string) (interface{}, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.data[key]
	if !ok {
		return nil, false
	}
	if time.Now().After(e.Expiration) {
		// No need to remove it. It would be replaced afterwards.
		return nil, false
	}
	return e.Value, true
}
