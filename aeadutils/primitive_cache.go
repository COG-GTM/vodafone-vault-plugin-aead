package aeadutils

import (
	"sync"

	"github.com/google/tink/go/tink"
)

// Tink primitives are safe for concurrent use. Entries are keyed by the full
// keyset JSON, so a rotated or replaced keyset is simply a new entry.
// ResetPrimitiveCaches is called whenever the config changes so that deleted
// or replaced keysets do not stay resident.
const (
	maxCachedKeysets     = 1024
	maxCachedKeysetBytes = 8 << 20
)

type keysetCache struct {
	mu    sync.RWMutex
	m     map[string]interface{}
	bytes int
	gen   uint64
}

func (c *keysetCache) generation() uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.gen
}

func (c *keysetCache) load(rawKeyset string) (interface{}, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	v, ok := c.m[rawKeyset]
	return v, ok
}

// store drops v if the cache was reset after gen was read, so a request that
// overlaps a config change cannot re-insert a deleted keyset.
func (c *keysetCache) store(rawKeyset string, v interface{}, gen uint64) {
	if len(rawKeyset) > maxCachedKeysetBytes {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if gen != c.gen {
		return
	}
	if _, ok := c.m[rawKeyset]; ok {
		return
	}
	if c.m == nil || len(c.m) >= maxCachedKeysets || c.bytes+len(rawKeyset) > maxCachedKeysetBytes {
		c.m = make(map[string]interface{})
		c.bytes = 0
	}
	c.m[rawKeyset] = v
	c.bytes += len(rawKeyset)
}

func (c *keysetCache) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m = nil
	c.bytes = 0
	c.gen++
}

func (c *keysetCache) len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.m)
}

var (
	validKeysets keysetCache
	aeadCache    keysetCache
	daeadCache   keysetCache
)

// ResetPrimitiveCaches drops every cached keyset and primitive.
func ResetPrimitiveCaches() {
	validKeysets.reset()
	aeadCache.reset()
	daeadCache.reset()
}

func isValidKeySetJsonCached(keySetJson string) bool {
	if _, ok := validKeysets.load(keySetJson); ok {
		return true
	}
	gen := validKeysets.generation()
	if _, err := ValidateKeySetJson(keySetJson); err != nil {
		return false
	}
	validKeysets.store(keySetJson, struct{}{}, gen)
	return true
}

// GetCachedAead returns the AEAD primitive for a cleartext keyset, building it once per keyset.
func GetCachedAead(rawKeyset string) (tink.AEAD, error) {
	if v, ok := aeadCache.load(rawKeyset); ok {
		return v.(tink.AEAD), nil
	}
	gen := aeadCache.generation()
	_, a, err := CreateInsecureHandleAndAead(rawKeyset)
	if err == nil && a != nil {
		aeadCache.store(rawKeyset, a, gen)
	}
	return a, err
}

// GetCachedDeterministicAead returns the deterministic AEAD primitive for a cleartext keyset, building it once per keyset.
func GetCachedDeterministicAead(rawKeyset string) (tink.DeterministicAEAD, error) {
	if v, ok := daeadCache.load(rawKeyset); ok {
		return v.(tink.DeterministicAEAD), nil
	}
	gen := daeadCache.generation()
	_, d, err := CreateInsecureHandleAndDeterministicAead(rawKeyset)
	if err == nil && d != nil {
		daeadCache.store(rawKeyset, d, gen)
	}
	return d, err
}
