// Package client provides the shared JSON HTTP client used by CLI commands.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	defaultMaxRetries   = 3
	defaultRetryDelay   = 100 * time.Millisecond
	maxResponseBodySize = 1 << 20
)

// APIError describes a non-successful response from the API.
type APIError struct {
	StatusCode int    `json:"-"`
	Message    string `json:"message"`
	Details    any    `json:"details,omitempty"`
}

func (e *APIError) Error() string {
	return fmt.Sprintf("api request failed with status %d: %s", e.StatusCode, e.Message)
}

// Client sends JSON requests to an API endpoint.
type Client struct {
	BaseURL    string
	HTTPClient *http.Client
	Debug      bool
	Logger     *log.Logger

	mu         sync.RWMutex
	token      string
	maxRetries int
	retryDelay time.Duration
}

// New creates a Client configured with the supplied base URL and timeout.
func New(baseURL string, timeout time.Duration, debug bool) (*Client, error) {
	baseURL = strings.TrimRight(baseURL, "/")
	parsedURL, err := url.Parse(baseURL)
	if err != nil || parsedURL.Scheme == "" || parsedURL.Host == "" {
		return nil, fmt.Errorf("invalid API base URL %q", baseURL)
	}
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return nil, fmt.Errorf("invalid API base URL scheme %q", parsedURL.Scheme)
	}
	if timeout <= 0 {
		return nil, errors.New("http client timeout must be positive")
	}

	return &Client{
		BaseURL:    baseURL,
		HTTPClient: &http.Client{Timeout: timeout},
		Debug:      debug,
		Logger:     log.Default(),
		maxRetries: defaultMaxRetries,
		retryDelay: defaultRetryDelay,
	}, nil
}

// SetToken sets the bearer token included in subsequent requests. Passing an
// empty token removes the Authorization header.
func (c *Client) SetToken(token string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.token = strings.TrimSpace(token)
}

// Get sends a GET request and decodes its JSON response into responseBody.
func (c *Client) Get(ctx context.Context, endpoint string, responseBody any) error {
	return c.do(ctx, http.MethodGet, endpoint, nil, responseBody)
}

// Post sends a POST request with a JSON body and decodes its JSON response.
func (c *Client) Post(ctx context.Context, endpoint string, requestBody, responseBody any) error {
	return c.do(ctx, http.MethodPost, endpoint, requestBody, responseBody)
}

// Delete sends a DELETE request and decodes its JSON response into responseBody.
func (c *Client) Delete(ctx context.Context, endpoint string, responseBody any) error {
	return c.do(ctx, http.MethodDelete, endpoint, nil, responseBody)
}

func (c *Client) do(ctx context.Context, method, endpoint string, requestBody, responseBody any) error {
	requestURL, err := c.resolveURL(endpoint)
	if err != nil {
		return err
	}

	var encodedBody []byte
	if requestBody != nil {
		encodedBody, err = json.Marshal(requestBody)
		if err != nil {
			return fmt.Errorf("encode request body: %w", err)
		}
	}

	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		request, err := http.NewRequestWithContext(ctx, method, requestURL, bytes.NewReader(encodedBody))
		if err != nil {
			return fmt.Errorf("create request: %w", err)
		}
		request.Header.Set("Accept", "application/json")
		if requestBody != nil {
			request.Header.Set("Content-Type", "application/json")
		}
		if token := c.bearerToken(); token != "" {
			request.Header.Set("Authorization", "Bearer "+token)
		}

		c.debugf("%s %s (attempt %d)", method, requestURL, attempt+1)
		response, err := c.HTTPClient.Do(request)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if attempt < c.maxRetries {
				if err := c.waitForRetry(ctx, attempt); err != nil {
					return err
				}
				continue
			}
			return fmt.Errorf("send request: %w", err)
		}

		body, readErr := readResponseBody(response.Body)
		if readErr != nil {
			return readErr
		}
		c.debugf("%s %s returned %s", method, requestURL, response.Status)

		if shouldRetry(response.StatusCode) && attempt < c.maxRetries {
			if err := c.waitForRetry(ctx, attempt); err != nil {
				return err
			}
			continue
		}
		if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
			return newAPIError(response.StatusCode, body)
		}
		if responseBody == nil || len(body) == 0 {
			return nil
		}
		if err := json.Unmarshal(body, responseBody); err != nil {
			return fmt.Errorf("decode response body: %w", err)
		}
		return nil
	}

	return errors.New("request attempts exhausted")
}

func (c *Client) resolveURL(endpoint string) (string, error) {
	requestURL, err := url.Parse(c.BaseURL + "/" + strings.TrimLeft(endpoint, "/"))
	if err != nil {
		return "", fmt.Errorf("resolve request URL: %w", err)
	}
	return requestURL.String(), nil
}

func (c *Client) bearerToken() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.token
}

func (c *Client) waitForRetry(ctx context.Context, attempt int) error {
	delay := c.retryDelay * time.Duration(1<<attempt)
	c.debugf("retrying request in %s", delay)
	timer := time.NewTimer(delay)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (c *Client) debugf(format string, args ...any) {
	if c.Debug && c.Logger != nil {
		c.Logger.Printf("mystvpn: "+format, args...)
	}
}

func readResponseBody(body io.ReadCloser) ([]byte, error) {
	defer body.Close()

	data, err := io.ReadAll(io.LimitReader(body, maxResponseBodySize+1))
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}
	if len(data) > maxResponseBodySize {
		return nil, errors.New("response body exceeds 1 MiB limit")
	}
	return data, nil
}

func shouldRetry(statusCode int) bool {
	return statusCode == http.StatusTooManyRequests || statusCode >= http.StatusInternalServerError
}

func newAPIError(statusCode int, body []byte) *APIError {
	apiErr := &APIError{StatusCode: statusCode}
	_ = json.Unmarshal(body, apiErr)
	if apiErr.Message == "" {
		switch {
		case statusCode == http.StatusUnauthorized:
			apiErr.Message = "unauthorized"
		case statusCode == http.StatusTooManyRequests:
			apiErr.Message = "too many requests"
		case statusCode >= http.StatusInternalServerError:
			apiErr.Message = "server error"
		default:
			apiErr.Message = strings.ToLower(http.StatusText(statusCode))
			if apiErr.Message == "" {
				apiErr.Message = "request failed"
			}
		}
	}
	return apiErr
}
