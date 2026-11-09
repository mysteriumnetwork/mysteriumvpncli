package update

import (
	"context"
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mysteriumnetwork/mysteriumvpncli/internal/client"
)

type releaseDiscovery struct{ calls int }

func (d *releaseDiscovery) Fallbacks(_ context.Context, host string) []string {
	d.calls++
	if host == "api.github.com" {
		return []string{"releases.example.com"}
	}
	return nil
}

type releaseTransport func(*http.Request) (*http.Response, error)

func (f releaseTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestReleaseCheckUsesDiscoveryWithoutAPICredentials(t *testing.T) {
	for _, failure := range []string{"transport", "server", "timeout"} {
		t.Run(failure, func(t *testing.T) {
			c, err := client.New("https://api.mysteriumvpn.com/api/v1", time.Second, false)
			if err != nil {
				t.Fatal(err)
			}
			c.SetAccessToken("private-api-token")
			discovery := &releaseDiscovery{}
			c.Discovery = discovery
			c.HTTPClient.Timeout = 20 * time.Millisecond
			requests := 0
			c.HTTPClient.Transport = releaseTransport(func(r *http.Request) (*http.Response, error) {
				requests++
				if r.Header.Get("Authorization") != "" {
					t.Fatal("API token sent to release endpoint")
				}
				if r.URL.Path != "/repos/mysteriumnetwork/mysteriumvpncli/releases/latest" || r.Header.Get("User-Agent") != "mystvpn-update-notifier" {
					t.Fatalf("unexpected request: %v", r)
				}
				status, body := 200, `{"tag_name":"1.2.4"}`
				if r.URL.Host == "api.github.com" {
					if failure == "timeout" {
						<-r.Context().Done()
						return nil, r.Context().Err()
					}
					if failure == "transport" {
						return nil, errors.New("blocked")
					}
					status = 503
				} else if r.URL.Host != "releases.example.com" {
					t.Fatalf("unexpected host %s", r.URL.Host)
				}
				return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
			})
			n := Notifier{Path: filepath.Join(t.TempDir(), "update.json"), Client: c}
			ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			defer cancel()
			if got := n.Check(ctx, "1.2.3"); got != "1.2.4" {
				t.Fatalf("notice=%q", got)
			}
			if requests != 2 || discovery.calls != 1 {
				t.Fatalf("requests=%d, discovery calls=%d", requests, discovery.calls)
			}
		})
	}
}
