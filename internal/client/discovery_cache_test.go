package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mysteriumnetwork/mysteriumvpncli/internal/discovery"
)

func TestHealthyEndpointsDoNotRefreshDiscovery(t *testing.T) {
	for _, app := range []bool{false, true} {
		for _, fallback := range []bool{false, true} {
			t.Run(fmt.Sprintf("app=%t/fallback=%t", app, fallback), func(t *testing.T) {
				directory := t.TempDir()
				cachePath := filepath.Join(directory, "discovery.json")
				statePath := filepath.Join(directory, "domain-state.json")
				const config = `{"signed":{"schema_version":1,"version":1,"issued_at":"2000-01-01T00:00:00Z","expires_at":"2000-02-01T00:00:00Z","mappings":{"primary.example.com":["first.example.com","second.example.com"]}}}`
				if err := os.WriteFile(cachePath, []byte(config), 0600); err != nil {
					t.Fatal(err)
				}
				var sourceCalls atomic.Int32
				source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					sourceCalls.Add(1)
					fmt.Fprint(w, config)
				}))
				defer source.Close()
				working := "primary.example.com"
				state := NewDomainState(statePath)
				if fallback {
					state.record("https://primary.example.com", working, false)
					working = "first.example.com"
				}
				state.record("https://primary.example.com", working, true)
				request := func(fail bool) {
					t.Helper()
					// Simulate a new invocation with both caches reloaded from disk.
					loader := discovery.New(cachePath)
					loader.Sources = []string{source.URL}
					c, _ := New("https://primary.example.com/api/v1", time.Second, false)
					c.Discovery = loader
					c.DomainState = NewDomainState(statePath)
					var attempts []string
					c.HTTPClient.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
						attempts = append(attempts, r.URL.Hostname())
						if fail && r.URL.Hostname() != "second.example.com" {
							return nil, errors.New("offline")
						}
						return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"status":"OK"}`))}, nil
					})
					var err error
					if app {
						_, err = c.ReachableURL(context.Background(), "https://primary.example.com/oauth/authorize")
					} else {
						err = c.Get(context.Background(), "resource", nil)
					}
					if err != nil {
						t.Fatal(err)
					}
					if !fail && (len(attempts) != 1 || attempts[0] != working) {
						t.Fatalf("healthy attempts=%v, want only %s", attempts, working)
					}
				}
				for i := 0; i < 3; i++ {
					request(false)
				}
				if sourceCalls.Load() != 0 {
					t.Fatalf("healthy endpoint refreshed discovery %d times", sourceCalls.Load())
				}
				request(true)
				if sourceCalls.Load() != 1 {
					t.Fatalf("failed endpoint discovery refreshes=%d, want 1", sourceCalls.Load())
				}
			})
		}
	}
}
