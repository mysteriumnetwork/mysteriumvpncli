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

func TestReachableURLFailover(t *testing.T) {
	for _, failure := range []string{"network", "challenge", "server", "invalid", "unhealthy", "redirect"} {
		t.Run(failure, func(t *testing.T) {
			c, _ := New("https://api.example.com", time.Second, false)
			c.Discovery = &fallbackList{}
			c.SetAccessToken("must-not-be-sent")
			var hosts []string
			c.HTTPClient.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
				hosts = append(hosts, r.URL.Host)
				if r.Header.Get("Authorization") != "" || r.Method != "GET" {
					t.Fatalf("unsafe probe: %v", r)
				}
				if r.URL.Path != "/api/v1/healthcheck" || r.URL.RawQuery != "" {
					t.Fatalf("URL changed: %s", r.URL)
				}
				status := 200
				body := `{"status":"OK"}`
				if r.URL.Hostname() == "app.example.com" {
					switch failure {
					case "network":
						return nil, errors.New("offline")
					case "challenge":
						status = 403
					case "server":
						status = 503
					case "invalid":
						body = "<html>challenge</html>"
					case "unhealthy":
						body = `{"status":"unhealthy"}`
					case "redirect":
						status = 302
					}
				}
				return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
			})
			got, err := c.ReachableURL(context.Background(), "https://app.example.com:8443/oauth/authorize?client_id=cli&request_id=test")
			if err != nil || got != "https://first.example.com:8443/oauth/authorize?client_id=cli&request_id=test" {
				t.Fatalf("URL=%s, error=%v", got, err)
			}
			if strings.Join(hosts, ",") != "app.example.com:8443,first.example.com:8443" {
				t.Fatalf("hosts=%v", hosts)
			}
		})
	}
}

func TestReachableURLNoWorkingDomain(t *testing.T) {
	c, _ := New("https://api.example.com", time.Second, false)
	c.Discovery = &fallbackList{}
	c.HTTPClient.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return nil, errors.New("offline")
	})
	got, err := c.ReachableURL(context.Background(), "https://app.example.com/oauth/authorize")
	if err == nil || got != "" {
		t.Fatalf("URL=%s, error=%v", got, err)
	}
}
