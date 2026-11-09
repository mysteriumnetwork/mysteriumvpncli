package client

import (
	"errors"
	"net/http"
	"net/url"
)

// Do sends a public GET or HEAD request with domain failover. It never attaches
// this client's API credentials. The caller owns the returned response body.
func (c *Client) Do(request *http.Request) (*http.Response, error) {
	if request == nil || request.URL == nil {
		return nil, errors.New("public domain failover requires a request URL")
	}
	if (request.Method != http.MethodGet && request.Method != http.MethodHead) || request.Body != nil {
		return nil, errors.New("public domain failover requires a bodyless GET or HEAD")
	}
	requestURL := request.URL.String()
	domains := c.newDomainAttempts(&requestURL)
	for {
		attempt := request.Clone(request.Context())
		attempt.URL, _ = url.Parse(requestURL)
		attempt.Host = ""
		response, err := c.HTTPClient.Do(attempt)
		if request.Context().Err() != nil {
			if response != nil {
				response.Body.Close()
			}
			return nil, request.Context().Err()
		}
		if err != nil {
			domains.record(false)
			if domains.next(request.Context()) {
				continue
			}
			return nil, err
		}
		domains.recordStatus(response.StatusCode)
		if unavailableStatus(response.StatusCode) && domains.next(request.Context()) {
			response.Body.Close()
			continue
		}
		if response.StatusCode >= 200 && response.StatusCode < 300 {
			domains.remember()
		}
		return response, nil
	}
}
