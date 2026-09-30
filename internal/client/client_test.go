package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestClientRequests(t *testing.T) {
	tests := []struct {
		name        string
		method      string
		call        func(*Client, any) error
		wantRequest map[string]string
	}{
		{
			name:   "get",
			method: http.MethodGet,
			call: func(client *Client, response any) error {
				return client.Get(context.Background(), "/resource", response)
			},
		},
		{
			name:   "post",
			method: http.MethodPost,
			call: func(client *Client, response any) error {
				return client.Post(context.Background(), "/resource", map[string]string{"name": "mystvpn"}, response)
			},
			wantRequest: map[string]string{"name": "mystvpn"},
		},
		{
			name:   "delete",
			method: http.MethodDelete,
			call: func(client *Client, response any) error {
				return client.Delete(context.Background(), "/resource", response)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				if request.Method != test.method {
					t.Errorf("method = %s, want %s", request.Method, test.method)
				}
				if request.URL.Path != "/api/v1/resource" {
					t.Errorf("path = %q, want /api/v1/resource", request.URL.Path)
				}
				if got := request.Header.Get("Accept"); got != "application/json" {
					t.Errorf("Accept = %q, want application/json", got)
				}
				if got := request.Header.Get("Authorization"); got != "Bearer test-token" {
					t.Errorf("Authorization = %q, want bearer token", got)
				}
				if test.wantRequest != nil {
					if got := request.Header.Get("Content-Type"); got != "application/json" {
						t.Errorf("Content-Type = %q, want application/json", got)
					}
					var requestBody map[string]string
					if err := json.NewDecoder(request.Body).Decode(&requestBody); err != nil {
						t.Errorf("decode request body: %v", err)
					}
					if requestBody["name"] != test.wantRequest["name"] {
						t.Errorf("request name = %q, want %q", requestBody["name"], test.wantRequest["name"])
					}
				}

				writer.Header().Set("Content-Type", "application/json")
				_, _ = writer.Write([]byte(`{"ok":true}`))
			}))
			defer server.Close()

			apiClient, err := New(server.URL+"/api/v1/", time.Second, false)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			apiClient.SetToken("test-token")

			var response struct {
				OK bool `json:"ok"`
			}
			if err := test.call(apiClient, &response); err != nil {
				t.Fatalf("request error = %v", err)
			}
			if !response.OK {
				t.Error("response OK = false, want true")
			}
		})
	}
}

func TestClientReturnsAPIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusUnauthorized)
		_, _ = writer.Write([]byte(`{"details":{"reason":"expired"}}`))
	}))
	defer server.Close()

	apiClient, err := New(server.URL, time.Second, false)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	err = apiClient.Get(context.Background(), "/resource", nil)
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error = %v, want *APIError", err)
	}
	if apiErr.StatusCode != http.StatusUnauthorized {
		t.Errorf("StatusCode = %d, want %d", apiErr.StatusCode, http.StatusUnauthorized)
	}
	if apiErr.Message != "unauthorized" {
		t.Errorf("Message = %q, want unauthorized", apiErr.Message)
	}
	if apiErr.Details == nil {
		t.Error("Details = nil, want response details")
	}
}

func TestPostWithStatusDebugLogsRequestAndFailureResponse(t *testing.T) {
	const responseBody = `{"error":"invalid activation request"}`
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusBadRequest)
		_, _ = writer.Write([]byte(responseBody))
	}))
	defer server.Close()

	var output bytes.Buffer
	apiClient, err := New(server.URL+"/api/v1", time.Second, true)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	apiClient.Logger = log.New(&output, "", 0)
	requestBody := struct {
		ID string `json:"id"`
	}{ID: "223e4567-e89b-42d3-a456-426614174000"}

	statusCode, err := apiClient.PostWithStatusDebug(context.Background(), "/auth/activation", requestBody, nil)
	if statusCode != http.StatusBadRequest || err == nil {
		t.Fatalf("PostWithStatusDebug() = status %d, error %v; want 400 error", statusCode, err)
	}

	logOutput := output.String()
	for _, expected := range []string{
		"POST " + server.URL + "/api/v1/auth/activation",
		`request body: {"id":"223e4567-e89b-42d3-a456-426614174000"}`,
		"response status: 400",
		"response body: " + responseBody,
	} {
		if !strings.Contains(logOutput, expected) {
			t.Errorf("debug output = %q, want %q", logOutput, expected)
		}
	}
}

func TestPostWithStatusDoesNotLogSensitiveBodies(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusBadRequest)
		_, _ = writer.Write([]byte(`{"error":"secret-response-detail"}`))
	}))
	defer server.Close()

	var output bytes.Buffer
	apiClient, err := New(server.URL, time.Second, true)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	apiClient.Logger = log.New(&output, "", 0)
	_, _ = apiClient.PostWithStatus(
		context.Background(),
		"/oauth/token",
		map[string]string{"code_verifier": "secret-verifier"},
		nil,
	)

	for _, secret := range []string{"secret-verifier", "secret-response-detail"} {
		if strings.Contains(output.String(), secret) {
			t.Errorf("standard debug output exposed %q: %q", secret, output.String())
		}
	}
}

func TestClientRetriesTransientResponses(t *testing.T) {
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		if attempts.Add(1) < 3 {
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = writer.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	apiClient, err := New(server.URL, time.Second, false)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	apiClient.retryDelay = time.Millisecond

	var response struct {
		OK bool `json:"ok"`
	}
	if err := apiClient.Get(context.Background(), "/resource", &response); err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got := attempts.Load(); got != 3 {
		t.Errorf("attempts = %d, want 3", got)
	}
	if !response.OK {
		t.Error("response OK = false, want true")
	}
}

func TestClientRefreshesTokenAfterUnauthorized(t *testing.T) {
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		attempts.Add(1)
		if request.Header.Get("Authorization") != "Bearer refreshed-token" {
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = writer.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	apiClient, err := New(server.URL, time.Second, false)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	apiClient.SetToken("expired-token")
	apiClient.SetUnauthorizedHandler(func(context.Context) (string, error) {
		return "refreshed-token", nil
	})

	var response struct {
		OK bool `json:"ok"`
	}
	if err := apiClient.Get(context.Background(), "/resource", &response); err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got := attempts.Load(); got != 2 {
		t.Errorf("attempts = %d, want 2", got)
	}
	if !response.OK {
		t.Error("response OK = false, want true")
	}
}

func TestShouldRetry(t *testing.T) {
	tests := []struct {
		statusCode int
		want       bool
	}{
		{http.StatusUnauthorized, false},
		{http.StatusTooManyRequests, true},
		{http.StatusInternalServerError, true},
		{http.StatusBadGateway, true},
	}

	for _, test := range tests {
		if got := shouldRetry(test.statusCode); got != test.want {
			t.Errorf("shouldRetry(%d) = %v, want %v", test.statusCode, got, test.want)
		}
	}
}
