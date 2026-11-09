package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// ReachableURL selects a reachable browser URL without sending API credentials.
// The app health endpoint is checked; the authorization URL itself is not requested.
func (c *Client) ReachableURL(ctx context.Context, rawURL string) (string, error) {
	original, err := url.Parse(rawURL)
	if err != nil || original.Host == "" || (original.Scheme != "http" && original.Scheme != "https") {
		return "", fmt.Errorf("invalid browser authorization URL")
	}
	probeClient := *c.HTTPClient
	if probeClient.Timeout <= 0 || probeClient.Timeout > defaultDialTimeout {
		probeClient.Timeout = defaultDialTimeout
	}
	probeClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	candidate := *original
	tried := make(map[string]bool)
	var alternatives []string
	loaded := false
	if hosts := c.cachedDomains(original); len(hosts) > 0 {
		candidate.Host = hosts[0]
		if port := original.Port(); port != "" {
			candidate.Host = net.JoinHostPort(hosts[0], port)
		}
	}
	var lastErr error
	for {
		tried[strings.ToLower(candidate.Hostname())] = true
		probeURL := candidate
		probeURL.Path = "/api/v1/healthcheck"
		probeURL.RawPath = ""
		probeURL.RawQuery = ""
		probeURL.Fragment = ""
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL.String(), nil)
		if err != nil {
			return "", err
		}
		request.Header.Set("Accept", "application/json")
		response, err := probeClient.Do(request)
		if err == nil {
			if response.StatusCode == http.StatusOK {
				var health struct {
					Status string `json:"status"`
				}
				body, readErr := io.ReadAll(io.LimitReader(response.Body, 4097))
				err = readErr
				if err == nil {
					if len(body) > 4096 {
						err = errors.New("health response exceeds 4 KiB")
					} else {
						err = json.Unmarshal(body, &health)
					}
				}
				if err == nil && health.Status != "OK" {
					err = errors.New("app health check did not report OK")
				}
			} else {
				err = fmt.Errorf("HTTP status %d", response.StatusCode)
			}
			response.Body.Close()
			if err == nil {
				c.recordDomain(original, candidate.String(), true)
				return candidate.String(), nil
			}
		}
		lastErr = err
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		c.recordDomain(original, candidate.String(), false)
		if !loaded && c.Discovery != nil {
			alternatives = append([]string{original.Hostname()}, c.Discovery.Fallbacks(ctx, original.Hostname())...)
			if c.DomainState != nil {
				alternatives = c.DomainState.order(original.Scheme+"://"+original.Host, alternatives)
			}
			loaded = true
		}
		found := false
		for len(alternatives) > 0 {
			host := alternatives[0]
			alternatives = alternatives[1:]
			if tried[strings.ToLower(host)] {
				continue
			}
			candidate = *original
			candidate.Host = host
			if port := original.Port(); port != "" {
				candidate.Host = net.JoinHostPort(host, port)
			}
			found = true
			break
		}
		if !found {
			return "", fmt.Errorf("no reachable authorization page: %w", lastErr)
		}
	}
}
