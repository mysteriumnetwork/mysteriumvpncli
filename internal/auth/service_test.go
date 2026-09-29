package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mysteriumnetwork/mysteriumvpncli/internal/client"
)

func TestStartCreatesActivationForOKAndNoContent(t *testing.T) {
	for _, statusCode := range []int{http.StatusOK, http.StatusNoContent} {
		t.Run(http.StatusText(statusCode), func(t *testing.T) {
			fixedNow := time.Date(2026, time.September, 29, 10, 0, 0, 0, time.UTC)
			var body map[string]string
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				if request.Method != http.MethodPost || request.URL.Path != "/api/v1/auth/activation" {
					t.Errorf("request = %s %s, want POST /api/v1/auth/activation", request.Method, request.URL.Path)
				}
				if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
					t.Fatalf("decode request: %v", err)
				}
				writer.WriteHeader(statusCode)
			}))
			defer server.Close()

			store := &memoryCredentialStore{}
			service := newTestService(t, server.URL, store)
			service.now = func() time.Time { return fixedNow }
			result, err := service.Start(context.Background())
			if err != nil {
				t.Fatalf("Start() error = %v", err)
			}

			if len(body) != 1 || body["id"] == "" || !isUUID(body["id"]) {
				t.Errorf("request body = %v, want only a UUID id", body)
			}
			if result.Pending.ActivationID != body["id"] {
				t.Errorf("pending activation ID = %q, want %q", result.Pending.ActivationID, body["id"])
			}
			if want := fixedNow.Add(5 * time.Minute); !result.Pending.ExpiresAt.Equal(want) {
				t.Errorf("expiry = %v, want %v", result.Pending.ExpiresAt, want)
			}
			parsed, err := url.Parse(result.AuthorizationURL)
			if err != nil {
				t.Fatalf("parse authorization URL: %v", err)
			}
			if parsed.Scheme != "https" || parsed.Host != "app.mysteriumvpn.com" || parsed.Path != "/oauth/authorize" {
				t.Errorf("authorization URL = %q", result.AuthorizationURL)
			}
			if parsed.Query().Get("response_type") != "activation_none" || parsed.Query().Get("client_id") != "cli" || parsed.Query().Get("request_id") != body["id"] {
				t.Errorf("authorization query = %v", parsed.Query())
			}
			stored, err := store.LoadPendingAuth()
			if err != nil || stored != result.Pending {
				t.Errorf("stored pending auth = %+v, error = %v", stored, err)
			}
		})
	}
}

func TestStartGeneratesUniqueActivationIDs(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {}))
	defer server.Close()
	store := &memoryCredentialStore{}
	service := newTestService(t, server.URL, store)

	first, err := service.Start(context.Background())
	if err != nil {
		t.Fatalf("first Start() error = %v", err)
	}
	second, err := service.Start(context.Background())
	if err != nil {
		t.Fatalf("second Start() error = %v", err)
	}
	if first.Pending.ActivationID == second.Pending.ActivationID {
		t.Errorf("activation IDs are identical: %q", first.Pending.ActivationID)
	}
}

func TestStartFailureClearsPendingAuthAndReportsStatusOnly(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusBadRequest)
		_, _ = writer.Write([]byte(`{"message":"internal detail"}`))
	}))
	defer server.Close()

	store := &memoryCredentialStore{}
	service := newTestService(t, server.URL, store)
	_, err := service.Start(context.Background())
	var statusErr *HTTPStatusError
	if !errors.As(err, &statusErr) || statusErr.StatusCode != http.StatusBadRequest {
		t.Fatalf("Start() error = %v, want HTTP status 400", err)
	}
	if err.Error() != "HTTP status 400" {
		t.Errorf("error = %q, want status only", err)
	}
	assertPendingCleared(t, store)
}

func TestPollContinuesUntilActivationHasTokens(t *testing.T) {
	pending := testPendingAuth()
	store := &memoryCredentialStore{pending: &pending}
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		call := calls.Add(1)
		if request.Method != http.MethodGet || request.URL.Path != "/api/v1/auth/activation/"+pending.ActivationID {
			t.Errorf("request = %s %s", request.Method, request.URL.Path)
		}
		writer.Header().Set("Content-Type", "application/json")
		switch call {
		case 1:
			_, _ = writer.Write([]byte(`{"id":"` + pending.ActivationID + `","valid":true,"token":null}`))
		case 2:
			_, _ = writer.Write([]byte(`{"id":"` + pending.ActivationID + `","valid":true,"token":{"access_token":"not-ready"}}`))
		default:
			_, _ = writer.Write([]byte(`{"id":"` + pending.ActivationID + `","valid":true,"token":{"access_token":"access-value","refresh_token":"refresh-value","token_type":"Bearer","expires_in":3600,"user_id":"user-123"}}`))
		}
	}))
	defer server.Close()

	service := newTestService(t, server.URL, store)
	if err := service.Poll(context.Background()); err != nil {
		t.Fatalf("Poll() error = %v", err)
	}
	if calls.Load() != 3 {
		t.Errorf("poll calls = %d, want 3", calls.Load())
	}
	if store.accessToken != "access-value" || store.refreshToken != "refresh-value" {
		t.Errorf("stored tokens = %q, %q", store.accessToken, store.refreshToken)
	}
	assertPendingCleared(t, store)
}

func TestPollRejectsInvalidActivation(t *testing.T) {
	pending := testPendingAuth()
	store := &memoryCredentialStore{pending: &pending}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte(`{"id":"` + pending.ActivationID + `","valid":false,"token":null}`))
	}))
	defer server.Close()

	service := newTestService(t, server.URL, store)
	if err := service.Poll(context.Background()); !errors.Is(err, ErrActivationInvalid) {
		t.Fatalf("Poll() error = %v, want ErrActivationInvalid", err)
	}
	assertPendingCleared(t, store)
}

func TestPollRejectsMalformedCompletedToken(t *testing.T) {
	pending := testPendingAuth()
	store := &memoryCredentialStore{pending: &pending}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte(`{"id":"` + pending.ActivationID + `","valid":true,"token":{"access_token":"access","refresh_token":"refresh","token_type":"mac","expires_in":3600}}`))
	}))
	defer server.Close()

	service := newTestService(t, server.URL, store)
	err := service.Poll(context.Background())
	if err == nil || err.Error() != "authentication response contained an unsupported token type" {
		t.Fatalf("Poll() error = %v, want unsupported token type", err)
	}
	if store.accessToken != "" || store.refreshToken != "" {
		t.Error("malformed response saved tokens")
	}
	assertPendingCleared(t, store)
}

func TestPollTimesOutAndClearsPendingAuth(t *testing.T) {
	pending := testPendingAuth()
	pending.ExpiresAt = time.Now().Add(30 * time.Millisecond)
	store := &memoryCredentialStore{pending: &pending}
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		_, _ = writer.Write([]byte(`{"id":"` + pending.ActivationID + `","valid":true,"token":null}`))
	}))
	defer server.Close()

	service := newTestService(t, server.URL, store)
	if err := service.Poll(context.Background()); !errors.Is(err, ErrAuthenticationTimedOut) {
		t.Fatalf("Poll() error = %v, want timeout", err)
	}
	if calls.Load() < 2 {
		t.Errorf("poll calls = %d, want at least 2", calls.Load())
	}
	assertPendingCleared(t, store)
}

func TestPollReportsHTTPFailureAndClearsPendingAuth(t *testing.T) {
	pending := testPendingAuth()
	store := &memoryCredentialStore{pending: &pending}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusUnauthorized)
		_, _ = writer.Write([]byte(`{"message":"do not expose"}`))
	}))
	defer server.Close()

	service := newTestService(t, server.URL, store)
	err := service.Poll(context.Background())
	var statusErr *HTTPStatusError
	if !errors.As(err, &statusErr) || statusErr.StatusCode != http.StatusUnauthorized || strings.Contains(err.Error(), "do not expose") {
		t.Fatalf("Poll() error = %v, want status-only 401", err)
	}
	assertPendingCleared(t, store)
}

func TestConfiguredClientRefreshesUsingRefreshTokenContract(t *testing.T) {
	var refreshCalls atomic.Int32
	authServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		refreshCalls.Add(1)
		if request.URL.Path != "/api/v1/oauth/token" {
			t.Errorf("path = %q", request.URL.Path)
		}
		var body map[string]any
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatalf("decode refresh request: %v", err)
		}
		if len(body) != 3 || body["grant_type"] != "refresh_token" || body["refresh_token"] != "old-refresh" || body["client_id"] != "cli" {
			t.Errorf("refresh request = %+v", body)
		}
		_, _ = writer.Write([]byte(`{"access_token":"new-access","refresh_token":"new-refresh","token_type":"Bearer","expires_in":3600}`))
	}))
	defer authServer.Close()

	var apiCalls atomic.Int32
	api := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		apiCalls.Add(1)
		if request.Header.Get("Authorization") != "Bearer new-access" {
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = writer.Write([]byte(`{"ok":true}`))
	}))
	defer api.Close()

	store := &memoryCredentialStore{accessToken: "old-access", refreshToken: "old-refresh"}
	service := newTestService(t, authServer.URL, store)
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
	if !response.OK || apiCalls.Load() != 2 || refreshCalls.Load() != 1 {
		t.Errorf("OK = %v, API calls = %d, refresh calls = %d", response.OK, apiCalls.Load(), refreshCalls.Load())
	}
	if store.accessToken != "new-access" || store.refreshToken != "new-refresh" {
		t.Errorf("stored tokens = %q, %q", store.accessToken, store.refreshToken)
	}
}

func newTestService(t *testing.T, authURL string, store CredentialStore) *Service {
	t.Helper()
	authClient, err := client.New(authURL+"/api/v1", time.Second, false)
	if err != nil {
		t.Fatalf("client.New() error = %v", err)
	}
	return NewService(authClient, store, Options{
		ClientID:         "cli",
		AuthorizationURL: "https://app.mysteriumvpn.com/oauth/authorize",
		PollInterval:     time.Millisecond,
		AuthTimeout:      5 * time.Minute,
	})
}

func testPendingAuth() PendingAuth {
	return PendingAuth{
		ActivationID: "223e4567-e89b-42d3-a456-426614174000",
		ExpiresAt:    time.Now().UTC().Add(5 * time.Minute),
	}
}

func assertPendingCleared(t *testing.T, store CredentialStore) {
	t.Helper()
	if _, err := store.LoadPendingAuth(); !errors.Is(err, ErrPendingAuthNotFound) {
		t.Errorf("LoadPendingAuth() error = %v, want cleared state", err)
	}
}

type memoryCredentialStore struct {
	mu           sync.Mutex
	accessToken  string
	refreshToken string
	pending      *PendingAuth
}

func (s *memoryCredentialStore) SaveAccessToken(token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.accessToken = token
	return nil
}

func (s *memoryCredentialStore) SaveRefreshToken(token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshToken = token
	return nil
}

func (s *memoryCredentialStore) LoadAccessToken() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.accessToken == "" {
		return "", ErrTokenNotFound
	}
	return s.accessToken, nil
}

func (s *memoryCredentialStore) LoadRefreshToken() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.refreshToken == "" {
		return "", ErrTokenNotFound
	}
	return s.refreshToken, nil
}

func (s *memoryCredentialStore) ClearTokens() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.accessToken = ""
	s.refreshToken = ""
	return nil
}

func (s *memoryCredentialStore) SavePendingAuth(pending PendingAuth) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pending = &pending
	return nil
}

func (s *memoryCredentialStore) LoadPendingAuth() (PendingAuth, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pending == nil {
		return PendingAuth{}, ErrPendingAuthNotFound
	}
	return *s.pending, nil
}

func (s *memoryCredentialStore) ClearPendingAuth() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pending = nil
	return nil
}
