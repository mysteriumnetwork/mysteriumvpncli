package client

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPersistentDomainsAcrossClients(t *testing.T) {
	for _, app := range []bool{false, true} {
		t.Run(map[bool]string{false: "api", true: "app"}[app], func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "domain-state.json")
			var calls []string
			working := "first.example.com"
			request := func(state *DomainState) {
				t.Helper()
				c, _ := New("https://primary.example.com", time.Second, false)
				c.Discovery = &fallbackList{}
				c.DomainState = state
				c.HTTPClient.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
					calls = append(calls, r.URL.Hostname())
					if r.URL.Hostname() != working {
						return nil, errors.New("offline")
					}
					return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"status":"OK"}`))}, nil
				})
				var err error
				if app {
					var link string
					link, err = c.ReachableURL(context.Background(), "https://primary.example.com/oauth/authorize?request_id=test")
					if err == nil && !strings.Contains(link, working) {
						t.Fatalf("link=%s", link)
					}
				} else {
					err = c.Get(context.Background(), "resource", nil)
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			state := NewDomainState(path)
			request(state)
			calls = nil
			state = NewDomainState(path) // Simulate a fresh CLI invocation.
			request(state)
			if strings.Join(calls, ",") != "first.example.com" {
				t.Fatalf("retried failed primary: %v", calls)
			}
			info, err := os.Stat(path)
			if err != nil || info.Mode().Perm() != 0600 {
				t.Fatalf("state permissions: %v, %v", info, err)
			}
			// Once the cooldown expires, check the primary again.
			future := time.Now().Add(domainCooldown + time.Second)
			state.now = func() time.Time { return future }
			working = "primary.example.com"
			calls = nil
			request(state)
			if strings.Join(calls, ",") != "primary.example.com" {
				t.Fatalf("did not recover primary: %v", calls)
			}
		})
	}
}

func TestDomainStateRecoveryAndIsolation(t *testing.T) {
	s := NewDomainState("")
	hosts := []string{"primary.example.com", "first.example.com", "second.example.com"}
	s.record("api", "primary.example.com", false)
	s.record("api", "first.example.com", true)
	if got := s.order("app", hosts); got[0] != hosts[0] {
		t.Fatalf("state leaked between services: %v", got)
	}
	s.record("api", "first.example.com", false)
	got := s.order("api", hosts)
	if got[0] != "second.example.com" || len(got) != 3 {
		t.Fatalf("recovery order: %v", got)
	}
}

func TestCorruptDomainStateIgnored(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	s := NewDomainState(path)
	if got := s.order("api", []string{"primary.example.com"}); len(got) != 1 {
		t.Fatal(got)
	}
}
