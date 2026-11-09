package client

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type fallbackList struct{ calls int }

func (f *fallbackList) Fallbacks(_ context.Context, host string) []string {
	f.calls++
	return []string{"first.example.com", "second.example.com"}
}

func (f *fallbackList) CachedFallbacks(string) []string {
	return []string{"first.example.com", "second.example.com"}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestDiscoveryFailover(t *testing.T) {
	for _, failure := range []string{"network", "server", "blocked", "read"} {
		t.Run(failure, func(t *testing.T) {
			c, err := New("https://primary.example.com:8443/api/v1", time.Second, false)
			if err != nil {
				t.Fatal(err)
			}
			c.maxRetries = 0
			if failure == "network" {
				c.maxRetries = defaultMaxRetries
			}
			c.SetAccessToken("secret")
			list := &fallbackList{}
			c.Discovery = list
			var hosts []string
			c.HTTPClient.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
				hosts = append(hosts, r.URL.Host)
				if r.URL.Path != "/api/v1/action" || r.URL.RawQuery != "key=value" || r.Method != "POST" || r.Header.Get("Authorization") != "Bearer secret" {
					t.Fatalf("request changed: %v", r)
				}
				body, _ := io.ReadAll(r.Body)
				if string(body) != `{"name":"test"}` {
					t.Fatalf("body = %s", body)
				}
				status := 200
				responseBody := io.NopCloser(strings.NewReader(`{"ok":true}`))
				if r.URL.Hostname() != "second.example.com" {
					switch failure {
					case "network":
						return nil, errors.New("offline")
					case "server":
						status = 503
					case "blocked":
						status = 403
					case "read":
						responseBody = brokenBody{}
					}
				}
				return &http.Response{StatusCode: status, Body: responseBody, Header: make(http.Header)}, nil
			})
			var result struct {
				OK bool `json:"ok"`
			}
			if err := c.Post(context.Background(), "action?key=value", map[string]string{"name": "test"}, &result); err != nil {
				t.Fatal(err)
			}
			if !result.OK || len(hosts) != 3 || hosts[1] != "first.example.com:8443" || list.calls != 1 {
				t.Fatalf("hosts=%v, discovery calls=%d, result=%v", hosts, list.calls, result)
			}
		})
	}
}

type brokenBody struct{}

func (brokenBody) Read([]byte) (int, error) { return 0, errors.New("broken body") }
func (brokenBody) Close() error             { return nil }

func TestDiscoveryOnlyForAvailabilityFailures(t *testing.T) {
	for _, status := range []int{200, 400, 401, 404, 429} {
		c, _ := New("https://primary.example.com", time.Second, false)
		c.maxRetries = 0
		list := &fallbackList{}
		c.Discovery = list
		c.HTTPClient.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header)}, nil
		})
		_ = c.Get(context.Background(), "action", nil)
		if list.calls != 0 {
			t.Fatalf("status %d triggered discovery", status)
		}
	}
}

// A timed-out primary must switch domains after one attempt, even when ordinary
// retries are enabled. The fallback gets a fresh request timeout.
func TestTimeoutFailsOverImmediately(t *testing.T) {
	c, err := New("https://primary.example.com", 20*time.Millisecond, false)
	if err != nil {
		t.Fatal(err)
	}
	c.Discovery = &fallbackList{}
	primaryCalls, fallbackCalls := 0, 0
	c.HTTPClient.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Hostname() == "primary.example.com" {
			primaryCalls++
			<-r.Context().Done()
			return nil, r.Context().Err()
		}
		fallbackCalls++
		if r.Context().Err() != nil {
			t.Fatal("fallback inherited expired timeout")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header)}, nil
	})
	if err := c.Get(context.Background(), "resource", nil); err != nil {
		t.Fatal(err)
	}
	if primaryCalls != 1 || fallbackCalls != 1 {
		t.Fatalf("primary calls=%d, fallback calls=%d", primaryCalls, fallbackCalls)
	}
}

func TestUnavailableDomainsAreNotRetried(t *testing.T) {
	c, _ := New("https://primary.example.com", time.Second, false)
	c.Discovery = &fallbackList{}
	calls := 0
	c.HTTPClient.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) { calls++; return nil, errors.New("unreachable") })
	if err := c.Get(context.Background(), "resource", nil); err == nil {
		t.Fatal("expected failure")
	}
	if calls != 3 {
		t.Fatalf("calls=%d, want one per domain", calls)
	}
}

// Polling must reuse the working fallback, but recover if it becomes unavailable.
func TestDiscoveryRemembersWorkingEndpoint(t *testing.T) {
	c, _ := New("https://primary.example.com:8443/api/v1", time.Second, false)
	c.Discovery = &fallbackList{}
	var hosts []string
	working := "first.example.com"
	c.HTTPClient.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		hosts = append(hosts, r.URL.Host)
		if r.URL.Path != "/api/v1/resource" || r.URL.RawQuery != "key=value" {
			t.Fatalf("request URL changed: %s", r.URL)
		}
		if r.URL.Hostname() != working {
			return nil, errors.New("offline")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("{}")), Header: make(http.Header)}, nil
	})
	request := func() {
		t.Helper()
		if err := c.Get(context.Background(), "resource?key=value", nil); err != nil {
			t.Fatal(err)
		}
	}
	request()
	request()
	working = "primary.example.com"
	request()
	request()
	want := "primary.example.com:8443,first.example.com:8443,first.example.com:8443,first.example.com:8443,primary.example.com:8443,primary.example.com:8443"
	if got := strings.Join(hosts, ","); got != want {
		t.Fatalf("hosts = %s, want %s", got, want)
	}
}
