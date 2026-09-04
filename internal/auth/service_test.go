package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mysteriumnetwork/mysteriumvpncli/internal/client"
)

func TestLoginSendsSentinelRequestAndStoresTokens(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", request.Method)
		}
		if request.URL.Path != passwordAuthEndpoint {
			t.Errorf("path = %q, want %q", request.URL.Path, passwordAuthEndpoint)
		}

		var body map[string]string
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if body["username"] != "alice" || body["password"] != "secret" || body["pool"] != "paid" {
			t.Errorf("request body = %v, want expected credentials and pool", body)
		}

		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"auth_token":"auth-value","refresh_token":"refresh-value"}`))
	}))
	defer server.Close()

	store := &memoryTokenStore{}
	service := newTestService(t, server.URL, store, "paid")
	if err := service.Login(context.Background(), "alice", "secret"); err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	if store.authToken != "auth-value" || store.refreshToken != "refresh-value" {
		t.Errorf("stored tokens = %q, %q", store.authToken, store.refreshToken)
	}
}

func TestLoginReturnsStatusOnly(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusUnauthorized)
		_, _ = writer.Write([]byte(`{"message":"credentials rejected","details":{"internal":"secret"}}`))
	}))
	defer server.Close()

	service := newTestService(t, server.URL, &memoryTokenStore{}, "default")
	err := service.Login(context.Background(), "alice", "wrong")
	var statusErr *HTTPStatusError
	if !errors.As(err, &statusErr) {
		t.Fatalf("Login() error = %v, want *HTTPStatusError", err)
	}
	if statusErr.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", statusErr.StatusCode, http.StatusUnauthorized)
	}
	if err.Error() != "HTTP status 401" {
		t.Errorf("error = %q, want status only", err)
	}
}

func TestLoginRequiresExactlyOK(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusCreated)
		_, _ = writer.Write([]byte(`{"auth_token":"auth-value","refresh_token":"refresh-value"}`))
	}))
	defer server.Close()

	service := newTestService(t, server.URL, &memoryTokenStore{}, "default")
	err := service.Login(context.Background(), "alice", "secret")
	var statusErr *HTTPStatusError
	if !errors.As(err, &statusErr) || statusErr.StatusCode != http.StatusCreated {
		t.Fatalf("Login() error = %v, want HTTP status 201", err)
	}
}

func TestRefreshReturnsStatusOnly(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusUnauthorized)
		_, _ = writer.Write([]byte(`{"message":"refresh token expired"}`))
	}))
	defer server.Close()

	store := &memoryTokenStore{refreshToken: "expired-refresh"}
	service := newTestService(t, server.URL, store, "default")
	_, err := service.Refresh(context.Background())
	var statusErr *HTTPStatusError
	if !errors.As(err, &statusErr) || statusErr.StatusCode != http.StatusUnauthorized {
		t.Fatalf("Refresh() error = %v, want HTTP status 401", err)
	}
	if err.Error() != "HTTP status 401" {
		t.Errorf("error = %q, want status only", err)
	}
}

func TestConfiguredClientRefreshesAndReplacesStoredTokens(t *testing.T) {
	var refreshCalls atomic.Int32
	sentinel := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		refreshCalls.Add(1)
		if request.URL.Path != refreshTokenEndpoint {
			t.Errorf("path = %q, want %q", request.URL.Path, refreshTokenEndpoint)
		}
		var body refreshRequest
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatalf("decode refresh request: %v", err)
		}
		if body.Token != "old-refresh" {
			t.Errorf("refresh token = %q, want old-refresh", body.Token)
		}
		_, _ = writer.Write([]byte(`{"auth_token":"new-auth","refresh_token":"new-refresh"}`))
	}))
	defer sentinel.Close()

	var apiCalls atomic.Int32
	api := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		apiCalls.Add(1)
		if request.Header.Get("Authorization") != "Bearer new-auth" {
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = writer.Write([]byte(`{"ok":true}`))
	}))
	defer api.Close()

	store := &memoryTokenStore{authToken: "old-auth", refreshToken: "old-refresh"}
	service := newTestService(t, sentinel.URL, store, "default")
	apiClient, err := client.New(api.URL, time.Second, false)
	if err != nil {
		t.Fatalf("client.New() error = %v", err)
	}
	if err := service.ConfigureClient(apiClient); err != nil {
		t.Fatalf("ConfigureClient() error = %v", err)
	}

	var response struct {
		OK bool `json:"ok"`
	}
	if err := apiClient.Get(context.Background(), "/protected", &response); err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if !response.OK {
		t.Error("response OK = false, want true")
	}
	if apiCalls.Load() != 2 || refreshCalls.Load() != 1 {
		t.Errorf("api calls = %d, refresh calls = %d; want 2 and 1", apiCalls.Load(), refreshCalls.Load())
	}
	if store.authToken != "new-auth" || store.refreshToken != "new-refresh" {
		t.Errorf("stored tokens = %q, %q; want refreshed values", store.authToken, store.refreshToken)
	}
}

func newTestService(t *testing.T, sentinelURL string, store TokenStore, pool string) *Service {
	t.Helper()

	sentinelClient, err := client.New(sentinelURL, time.Second, false)
	if err != nil {
		t.Fatalf("client.New() error = %v", err)
	}
	return NewService(sentinelClient, store, pool)
}

type memoryTokenStore struct {
	mu           sync.Mutex
	authToken    string
	refreshToken string
}

func (s *memoryTokenStore) SaveAuthToken(token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.authToken = token
	return nil
}

func (s *memoryTokenStore) SaveRefreshToken(token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshToken = token
	return nil
}

func (s *memoryTokenStore) LoadAuthToken() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.authToken == "" {
		return "", ErrTokenNotFound
	}
	return s.authToken, nil
}

func (s *memoryTokenStore) LoadRefreshToken() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.refreshToken == "" {
		return "", ErrTokenNotFound
	}
	return s.refreshToken, nil
}

func (s *memoryTokenStore) ClearTokens() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.authToken = ""
	s.refreshToken = ""
	return nil
}
