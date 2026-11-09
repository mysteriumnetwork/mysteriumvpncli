package client

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"strings"
)

type domainRouting struct {
	// DomainState optionally persists endpoint availability across CLI runs.
	DomainState *DomainState

	// Discovery supplies domain alternatives after the primary endpoint fails.
	Discovery interface {
		Fallbacks(context.Context, string) []string
	}

	preferredHosts map[string]string
}

type domainAttempts struct {
	client       *Client
	original     *url.URL
	requestURL   *string
	alternatives []string
	loaded       bool
	tried        map[string]bool
}

// newDomainAttempts selects from local state only. Network discovery is deferred
// until next is called after an endpoint failure.
func (c *Client) newDomainAttempts(requestURL *string) *domainAttempts {
	original, _ := url.Parse(*requestURL)
	c.mu.RLock()
	preferred := c.preferredHosts[strings.ToLower(original.Host)]
	c.mu.RUnlock()
	if c.Discovery != nil && preferred != "" {
		replacement := *original
		replacement.Host = preferred
		*requestURL = replacement.String()
	}
	if hosts := c.cachedDomains(original); len(hosts) > 0 {
		*requestURL = replaceDomain(original, hosts[0])
	}
	initial, _ := url.Parse(*requestURL)
	return &domainAttempts{client: c, original: original, requestURL: requestURL, tried: map[string]bool{strings.ToLower(initial.Hostname()): true}}
}

func (d *domainAttempts) next(ctx context.Context) bool {
	c := d.client
	if c.Discovery == nil || ctx.Err() != nil {
		return false
	}
	if !d.loaded {
		d.alternatives = append([]string{d.original.Hostname()}, c.Discovery.Fallbacks(ctx, d.original.Hostname())...)
		if c.DomainState != nil {
			d.alternatives = c.DomainState.order(d.original.Scheme+"://"+d.original.Host, d.alternatives)
		}
		d.loaded = true
	}
	for len(d.alternatives) > 0 {
		host := d.alternatives[0]
		d.alternatives = d.alternatives[1:]
		if d.tried[strings.ToLower(host)] {
			continue
		}
		d.tried[strings.ToLower(host)] = true
		*d.requestURL = replaceDomain(d.original, host)
		return true
	}
	return false
}

func replaceDomain(original *url.URL, host string) string {
	replacement := *original
	replacement.Host = host
	if port := original.Port(); port != "" {
		replacement.Host = net.JoinHostPort(host, port)
	}
	return replacement.String()
}

func (d *domainAttempts) record(success bool) {
	d.client.recordDomain(d.original, *d.requestURL, success)
}

func unavailableStatus(status int) bool {
	return status >= 500 || status == http.StatusForbidden || status == http.StatusUnavailableForLegalReasons
}

func (d *domainAttempts) recordStatus(status int) { d.record(!unavailableStatus(status)) }

func (d *domainAttempts) remember() {
	c := d.client
	if c.Discovery == nil {
		return
	}
	working, _ := url.Parse(*d.requestURL)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.preferredHosts == nil {
		c.preferredHosts = make(map[string]string)
	}
	c.preferredHosts[strings.ToLower(d.original.Host)] = working.Host
}

// recordDomain stores only host availability, never request paths or credentials.
func (c *Client) recordDomain(original *url.URL, requestURL string, success bool) {
	if c.DomainState == nil {
		return
	}
	current, err := url.Parse(requestURL)
	if err != nil {
		return
	}
	c.DomainState.record(original.Scheme+"://"+original.Host, current.Hostname(), success)
}

// cachedDomains selects only locally cached alternatives. Refreshes belong on
// the failure path so discovery outages cannot delay a working endpoint.
func (c *Client) cachedDomains(original *url.URL) []string {
	if c.DomainState == nil || !c.DomainState.known(original.Scheme+"://"+original.Host) {
		return nil
	}
	cache, ok := c.Discovery.(interface{ CachedFallbacks(string) []string })
	if !ok {
		return nil
	}
	hosts := append([]string{original.Hostname()}, cache.CachedFallbacks(original.Hostname())...)
	return c.DomainState.order(original.Scheme+"://"+original.Host, hosts)
}
