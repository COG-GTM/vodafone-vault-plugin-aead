package aeadutils

import (
	"sync"
	"sync/atomic"

	"github.com/google/tink/go/tink"
)

// Tink primitives are safe for concurrent use. Entries are keyed by the full
// keyset JSON, so a rotated or replaced keyset is simply a new entry.
const maxCachedKeysets = 1024

type keysetCache struct {
	m     sync.Map
	count atomic.Int64
}

func (c *keysetCache) load(rawKeyset string) (interface{}, bool) {
	return c.m.Load(rawKeyset)
}

func (c *keysetCache) store(rawKeyset string, v interface{}) {
	if c.count.Load() >= maxCachedKeysets {
		c.m.Range(func(k, _ interface{}) bool {
			c.m.Delete(k)
			return true
		})
		c.count.Store(0)
	}
	if _, loaded := c.m.LoadOrStore(rawKeyset, v); !loaded {
		c.count.Add(1)
	}
}

var (
	validKeysets keysetCache
	aeadCache    keysetCache
	daeadCache   keysetCache
)

func isValidKeySetJsonCached(keySetJson string) bool {
	if _, ok := validKeysets.load(keySetJson); ok {
		return true
	}
	if _, err := ValidateKeySetJson(keySetJson); err != nil {
		return false
	}
	validKeysets.store(keySetJson, struct{}{})
	return true
}

// GetCachedAead returns the AEAD primitive for a cleartext keyset, building it once per keyset.
func GetCachedAead(rawKeyset string) (tink.AEAD, error) {
	if v, ok := aeadCache.load(rawKeyset); ok {
		return v.(tink.AEAD), nil
	}
	_, a, err := CreateInsecureHandleAndAead(rawKeyset)
	if err == nil && a != nil {
		aeadCache.store(rawKeyset, a)
	}
	return a, err
}

// GetCachedDeterministicAead returns the deterministic AEAD primitive for a cleartext keyset, building it once per keyset.
func GetCachedDeterministicAead(rawKeyset string) (tink.DeterministicAEAD, error) {
	if v, ok := daeadCache.load(rawKeyset); ok {
		return v.(tink.DeterministicAEAD), nil
	}
	_, d, err := CreateInsecureHandleAndDeterministicAead(rawKeyset)
	if err == nil && d != nil {
		daeadCache.store(rawKeyset, d)
	}
	return d, err
}
