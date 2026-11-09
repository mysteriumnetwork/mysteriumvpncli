package discovery

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const sample = `{"signed":{"schema_version":1,"version":1,"issued_at":"2026-10-27T00:00:00Z","expires_at":"2099-11-10T00:00:00Z","mappings":{"app.mysteriumvpn.com":["unblocked-app.mysteriumvpn.com","app.mysterium.network"]}},"signatures":[]}`

func TestParse(t *testing.T) {
	for _, tt := range []struct {
		name, data string
		valid      bool
	}{
		{"valid", sample, true},
		{"ignored signatures", strings.Replace(sample, `"signatures":[]`, `"signatures":{"future":true}`, 1), true},
		{"missing envelope", `{}`, false},
		{"null", `null`, false},
		{"unsupported schema", strings.Replace(sample, `"schema_version":1`, `"schema_version":2`, 1), false},
		{"missing mappings", strings.Replace(sample, `"mappings":{`, `"other":{`, 1), false},
		{"missing version", strings.Replace(sample, `"version":1,`, "", 1), false},
		{"bad timestamp", strings.Replace(sample, "2026-10-27T00:00:00Z", "yesterday", 1), false},
		{"reversed timestamps", strings.Replace(sample, "2099-11-10T00:00:00Z", "2020-11-10T00:00:00Z", 1), false},
		{"url instead of domain", strings.Replace(sample, "app.mysterium.network", "https://app.mysterium.network", 1), false},
		{"port", strings.Replace(sample, "app.mysterium.network", "app.mysterium.network:443", 1), false},
		{"trailing JSON", sample + `{}`, false},
		{"too large", strings.Repeat(" ", maxConfigSize+1), false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.data))
			if (err == nil) != tt.valid {
				t.Fatalf("Parse() error = %v, valid = %v", err, tt.valid)
			}
		})
	}
}

func TestLoaderRefreshAndCache(t *testing.T) {
	var primaryCalls, mirrorCalls atomic.Int32
	var unavailable atomic.Bool
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		primaryCalls.Add(1)
		fmt.Fprint(w, `{"signed":{"schema_version":99}}`)
	}))
	defer primary.Close()
	mirror := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mirrorCalls.Add(1)
		if unavailable.Load() {
			http.Error(w, "offline", 503)
			return
		}
		fmt.Fprint(w, sample)
	}))
	defer mirror.Close()
	path := filepath.Join(t.TempDir(), "discovery.json")
	loader := New(path)
	loader.Sources = []string{primary.URL, mirror.URL}
	check := func(l *Loader) {
		t.Helper()
		got := l.Fallbacks(context.Background(), "app.mysteriumvpn.com")
		if len(got) != 2 || got[0] != "unblocked-app.mysteriumvpn.com" {
			t.Fatalf("Fallbacks() = %v", got)
		}
		got[0] = "changed.example.com"
	}
	check(loader)
	check(loader)
	if primaryCalls.Load() != 1 || mirrorCalls.Load() != 1 {
		t.Fatal("refresh was not throttled")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("cache mode = %v", info.Mode())
	}
	// A new process uses a recent cache without accessing discovery sources.
	restarted := New(path)
	restarted.Sources = loader.Sources
	check(restarted)
	if mirrorCalls.Load() != 1 {
		t.Fatal("fresh disk cache was refreshed")
	}
	unavailable.Store(true)
	loader.RefreshInterval = -time.Second
	check(loader)
	if mirrorCalls.Load() != 2 {
		t.Fatal("periodic refresh did not run")
	}
	restarted.RefreshInterval = -time.Second
	check(restarted)
	if mirrorCalls.Load() != 3 {
		t.Fatal("disk cache was not retained during outage")
	}
}

func TestPrimarySuccessAndInvalidCache(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; fmt.Fprint(w, sample) }))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "discovery.json")
	if err := os.WriteFile(path, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	loader := New(path)
	loader.Sources = []string{server.URL, "http://invalid.invalid"}
	if got := loader.Fallbacks(context.Background(), "unknown.example.com"); len(got) != 0 {
		t.Fatalf("unexpected alternatives: %v", got)
	}
	if calls != 1 {
		t.Fatalf("calls = %d", calls)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	loader.RefreshInterval = -time.Second
	loader.Fallbacks(ctx, "app.mysteriumvpn.com")
	loader.Fallbacks(context.Background(), "127.0.0.1")
	if calls != 1 {
		t.Fatal("canceled or IP request fetched discovery")
	}
}

func TestConcurrentFallbacks(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); fmt.Fprint(w, sample) }))
	defer server.Close()
	loader := New("")
	loader.Sources = []string{server.URL}
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if got := loader.Fallbacks(context.Background(), "app.mysteriumvpn.com"); len(got) != 2 {
				t.Errorf("Fallbacks() = %v", got)
			}
		}()
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("concurrent refresh calls = %d", calls.Load())
	}
}

func TestExpiredCacheSurvivesUnavailableSources(t *testing.T) {
	path := filepath.Join(t.TempDir(), "discovery.json")
	expired := strings.Replace(sample, "2099-11-10T00:00:00Z", "2026-11-10T00:00:00Z", 1)
	// These dates are in the past regardless of the machine's current date.
	expired = strings.Replace(expired, "2026-10-27T00:00:00Z", "2000-10-27T00:00:00Z", 1)
	expired = strings.Replace(expired, "2026-11-10T00:00:00Z", "2000-11-10T00:00:00Z", 1)
	if err := os.WriteFile(path, []byte(expired), 0600); err != nil {
		t.Fatal(err)
	}
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; http.Error(w, "unavailable", 503) }))
	defer server.Close()
	loader := New(path)
	loader.Sources = []string{server.URL, server.URL}
	if got := loader.Fallbacks(context.Background(), "app.mysteriumvpn.com"); len(got) != 2 {
		t.Fatalf("stale alternatives = %v", got)
	}
	if calls != 2 {
		t.Fatalf("source calls = %d, want 2", calls)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != expired {
		t.Fatal("failed refresh replaced cache")
	}
}

func TestCachedFallbacksNeverRefresh(t *testing.T) {
	path := filepath.Join(t.TempDir(), "discovery.json")
	expired := strings.Replace(sample, "2026-10-27T00:00:00Z", "2000-01-01T00:00:00Z", 1)
	expired = strings.Replace(expired, "2099-11-10T00:00:00Z", "2000-02-01T00:00:00Z", 1)
	if err := os.WriteFile(path, []byte(expired), 0600); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		fmt.Fprint(w, sample)
	}))
	defer source.Close()
	loader := New(path)
	loader.Sources = []string{source.URL}
	for i := 0; i < 2; i++ {
		got := loader.CachedFallbacks("app.mysteriumvpn.com")
		if len(got) != 2 || got[0] != "unblocked-app.mysteriumvpn.com" {
			t.Fatalf("cached alternatives=%v", got)
		}
		got[0] = "mutated.example.com"
	}
	if calls.Load() != 0 {
		t.Fatal("cache read contacted discovery")
	}
	loader.Fallbacks(context.Background(), "app.mysteriumvpn.com")
	if calls.Load() != 1 {
		t.Fatal("cache-only read suppressed the needed refresh")
	}
}
