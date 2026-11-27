package aeadutils

import (
	"bytes"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/daead"
	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/keyset"
)

func keysetJSON(t *testing.T, h *keyset.Handle) string {
	t.Helper()
	buf := new(bytes.Buffer)
	if err := insecurecleartextkeyset.Write(h, keyset.NewJSONWriter(buf)); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func TestCachedDeterministicAeadMatchesUncached(t *testing.T) {
	h, err := keyset.NewHandle(daead.AESSIVKeyTemplate())
	if err != nil {
		t.Fatal(err)
	}
	ks := keysetJSON(t, h)
	_, fresh, _ := CreateInsecureHandleAndDeterministicAead(ks)
	want, _ := fresh.EncryptDeterministically([]byte("hello"), []byte("field"))
	for i := 0; i < 3; i++ {
		cached, err := GetCachedDeterministicAead(ks)
		if err != nil {
			t.Fatal(err)
		}
		got, _ := cached.EncryptDeterministically([]byte("hello"), []byte("field"))
		if !bytes.Equal(got, want) {
			t.Fatalf("cached ciphertext differs")
		}
	}
	if _, ok := daeadCache.load(ks); !ok {
		t.Fatal("primitive was not cached")
	}
}

func TestCachedAeadRoundTripsWithUncached(t *testing.T) {
	h, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
	if err != nil {
		t.Fatal(err)
	}
	ks := keysetJSON(t, h)
	_, fresh, _ := CreateInsecureHandleAndAead(ks)
	cached, err := GetCachedAead(ks)
	if err != nil {
		t.Fatal(err)
	}
	ct, _ := cached.Encrypt([]byte("hello"), []byte("field"))
	pt, err := fresh.Decrypt(ct, []byte("field"))
	if err != nil || string(pt) != "hello" {
		t.Fatalf("uncached primitive could not decrypt cached ciphertext: %v", err)
	}
	if !isValidKeySetJsonCached(ks) || isValidKeySetJsonCached("not-a-key") {
		t.Fatal("keyset validation cache disagrees with ValidateKeySetJson")
	}
}

func TestKeysetCacheIsBounded(t *testing.T) {
	var c keysetCache
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < maxCachedKeysets; i++ {
				c.store(strconv.Itoa(w)+"-"+strconv.Itoa(i), i)
			}
		}(w)
	}
	wg.Wait()
	if n := c.len(); n > maxCachedKeysets {
		t.Fatalf("cache grew to %d entries", n)
	}
	c.store(strings.Repeat("x", maxCachedKeysetBytes+1), 1)
	if c.bytes > maxCachedKeysetBytes {
		t.Fatalf("cache holds %d bytes", c.bytes)
	}
}

func TestResetPrimitiveCaches(t *testing.T) {
	h, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
	if err != nil {
		t.Fatal(err)
	}
	ks := keysetJSON(t, h)
	if _, err := GetCachedAead(ks); err != nil || !isValidKeySetJsonCached(ks) {
		t.Fatal("expected keyset to be cached")
	}
	ResetPrimitiveCaches()
	if _, ok := aeadCache.load(ks); ok {
		t.Fatal("aead cache not cleared")
	}
	if _, ok := validKeysets.load(ks); ok {
		t.Fatal("validation cache not cleared")
	}
}
