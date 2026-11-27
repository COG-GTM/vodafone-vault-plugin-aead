package aeadplugin

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
)

// Opt-in latency harness for /encrypt: AEAD_LATENCY_ROWS=100 go test -run TestEncryptLatency -v
func TestEncryptLatency(t *testing.T) {
	rowsEnv := os.Getenv("AEAD_LATENCY_ROWS")
	if rowsEnv == "" {
		t.Skip("set AEAD_LATENCY_ROWS to run")
	}
	rows, _ := strconv.Atoi(rowsEnv)
	iters, conc := 300, 4
	if v, err := strconv.Atoi(os.Getenv("AEAD_LATENCY_ITERS")); err == nil {
		iters = v
	}

	b, storage := testBackend(t)
	seedBulkKeys(t, b, storage)

	row := bulkRow
	newData := func() map[string]interface{} {
		if rows == 0 {
			return row(1)
		}
		return bulkData(rows)
	}
	run := func(n int) []time.Duration {
		var mu sync.Mutex
		var wg sync.WaitGroup
		out := make([]time.Duration, 0, n)
		work := make(chan struct{}, n)
		for i := 0; i < n; i++ {
			work <- struct{}{}
		}
		close(work)
		for w := 0; w < conc; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for range work {
					req := &logical.Request{Storage: storage, Operation: logical.UpdateOperation, Path: "encrypt", Data: newData()}
					start := time.Now()
					if _, err := b.HandleRequest(context.Background(), req); err != nil {
						t.Error(err)
					}
					d := time.Since(start)
					mu.Lock()
					out = append(out, d)
					mu.Unlock()
				}
			}()
		}
		wg.Wait()
		return out
	}

	run(iters / 5)
	lat := run(iters)
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	pct := func(p float64) float64 { return float64(lat[int(p*float64(len(lat)-1))].Microseconds()) / 1000 }
	fmt.Printf("RESULT rows=%d n=%d p50=%.2fms p95=%.2fms p99=%.2fms\n", rows, len(lat), pct(0.50), pct(0.95), pct(0.99))
}

func seedBulkKeys(tb testing.TB, b *backend, storage logical.Storage) {
	tb.Helper()
	for path, fields := range map[string][]string{"createAEADkey": {"f0", "f1", "f2"}, "createDAEADkey": {"f3", "f4", "f5"}} {
		data := map[string]interface{}{}
		for _, f := range fields {
			data[f] = "x"
		}
		if _, err := b.HandleRequest(context.Background(), &logical.Request{Storage: storage, Operation: logical.UpdateOperation, Path: path, Data: data}); err != nil {
			tb.Fatal(err)
		}
	}
	config := map[string]interface{}{"f0": "gcm/f0", "f1": "gcm/f1", "f2": "gcm/f2", "f3": "siv/f3", "f4": "siv/f4", "f5": "siv/f5"}
	if _, err := b.HandleRequest(context.Background(), &logical.Request{Storage: storage, Operation: logical.UpdateOperation, Path: "config", Data: config}); err != nil {
		tb.Fatal(err)
	}
}

func bulkRow(i int) map[string]interface{} {
	return map[string]interface{}{"f0": fmt.Sprintf("alice%d@example.com", i), "f1": fmt.Sprintf("+4477000%d", i), "f2": fmt.Sprintf("%d High St", i),
		"f3": fmt.Sprintf("cust-%d", i), "f4": fmt.Sprintf("DOB-%d", i), "f5": fmt.Sprintf("acct-%d", i), "f6": fmt.Sprintf("unkeyed-%d", i)}
}

func bulkData(rows int) map[string]interface{} {
	d := map[string]interface{}{}
	for i := 0; i < rows; i++ {
		d[strconv.Itoa(i)] = bulkRow(i)
	}
	return d
}

func TestBulkEncryptDecryptRoundTrip(t *testing.T) {
	b, storage := testBackend(t)
	seedBulkKeys(t, b, storage)
	call := func(path string, data map[string]interface{}) map[string]interface{} {
		resp, err := b.HandleRequest(context.Background(), &logical.Request{Storage: storage, Operation: logical.UpdateOperation, Path: path, Data: data})
		if err != nil {
			t.Fatal(path, err)
		}
		return resp.Data
	}
	const rows = 50
	enc1 := call("encrypt", bulkData(rows))
	enc2 := call("encrypt", bulkData(rows))
	if len(enc1) != rows {
		t.Fatalf("expected %d rows, got %d", rows, len(enc1))
	}
	for r := 0; r < rows; r++ {
		key := strconv.Itoa(r)
		want := bulkRow(r)
		row1 := enc1[key].(map[string]interface{})
		row2 := enc2[key].(map[string]interface{})
		if len(row1) != len(want) {
			t.Fatalf("row %s: expected %d fields, got %d", key, len(want), len(row1))
		}
		if row1["f6"] != want["f6"] {
			t.Fatalf("row %s: unkeyed field changed: %v", key, row1["f6"])
		}
		for _, f := range []string{"f3", "f4", "f5"} {
			if row1[f] != row2[f] || row1[f] == want[f] {
				t.Fatalf("row %s field %s: deterministic ciphertext not stable: %v %v", key, f, row1[f], row2[f])
			}
		}
		for _, f := range []string{"f0", "f1", "f2"} {
			if row1[f] == row2[f] || row1[f] == want[f] {
				t.Fatalf("row %s field %s: AEAD ciphertext should be randomised", key, f)
			}
		}
	}
	dec := call("decrypt", enc1)
	for r := 0; r < rows; r++ {
		key := strconv.Itoa(r)
		got := dec[key].(map[string]interface{})
		for f, v := range bulkRow(r) {
			if got[f] != v {
				t.Fatalf("row %s field %s: decrypt got %v want %v", key, f, got[f], v)
			}
		}
	}
	single := call("decrypt", call("encrypt", bulkRow(7)))
	for f, v := range bulkRow(7) {
		if single[f] != v {
			t.Fatalf("single row field %s: decrypt got %v want %v", f, single[f], v)
		}
	}
}
