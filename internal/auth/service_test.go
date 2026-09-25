package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
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

func TestGeneratePKCE(t *testing.T) {
	verifier, challenge, err := GeneratePKCE()
	if err != nil {
		t.Fatalf("GeneratePKCE() error = %v", err)
	}
	if len(verifier) < 43 || len(verifier) > 128 {
		t.Errorf("verifier length = %d, want RFC 7636 range", len(verifier))
	}
	if _, err := base64.RawURLEncoding.DecodeString(verifier); err != nil {
		t.Errorf("verifier is not unpadded base64url: %v", err)
	}
	digest := sha256.Sum256([]byte(verifier))
	wantChallenge := base64.RawURLEncoding.EncodeToString(digest[:])
	if challenge != wantChallenge {
		t.Errorf("challenge = %q, want SHA-256 challenge %q", challenge, wantChallenge)
	}

	secondVerifier, _, err := GeneratePKCE()
	if err != nil {
		t.Fatalf("second GeneratePKCE() error = %v", err)
	}
	if secondVerifier == verifier {
		t.Error("two generated PKCE verifiers are identical")
	}
}

func TestStartSendsMagicLinkRequestAndStoresPendingAuth(t *testing.T) {
	fixedNow := time.Date(2026, time.September, 25, 10, 0, 0, 0, time.UTC)
	var requestBody startAuthRequest
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", request.Method)
		}
		if request.URL.Path != "/api/v1/magic-link" {
			t.Errorf("path = %q, want /api/v1/magic-link", request.URL.Path)
		}
		if err := json.NewDecoder(request.Body).Decode(&requestBody); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusAccepted)
		_, _ = writer.Write([]byte(`{"auth_url":"https://auth.example.com/continue"}`))
	}))
	defer server.Close()

	store := &memoryCredentialStore{}
	service := newTestService(t, server.URL, store)
	service.now = func() time.Time { return fixedNow }
	result, err := service.Start(context.Background(), "alice@example.com", "http://127.0.0.1:54321/auth/callback")
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	if requestBody.Email != "alice@example.com" || requestBody.ClientID != "dvpn" {
		t.Errorf("request identity = %+v", requestBody)
	}
	if result.AuthURL != "https://auth.example.com/continue" {
		t.Errorf("auth URL = %q", result.AuthURL)
	}
	if requestBody.CodeChallenge == "" {
		t.Errorf("request is missing generated security fields: %+v", requestBody)
	}
	if requestBody.CodeChallengeMethod != "S256" {
		t.Errorf("challenge method = %q, want S256", requestBody.CodeChallengeMethod)
	}
	pending := result.Pending
	if pending.CodeVerifier == "" || pending.CodeVerifier == pending.CodeChallenge {
		t.Error("pending auth does not contain a distinct PKCE verifier")
	}
	continueTo, err := url.Parse(requestBody.ContinueTo)
	if err != nil {
		t.Fatalf("parse continue_to: %v", err)
	}
	if continueTo.Scheme != "http" || continueTo.Host != "127.0.0.1:54321" || continueTo.Path != "/auth/callback" {
		t.Errorf("continue_to = %q, want loopback callback", requestBody.ContinueTo)
	}
	if continueTo.Query().Get("state") != pending.State || continueTo.Query().Get("nonce") != pending.Nonce || pending.CodeChallenge != requestBody.CodeChallenge {
		t.Error("stored pending auth does not match start request")
	}
	if want := fixedNow.Add(10 * time.Minute); !pending.ExpiresAt.Equal(want) {
		t.Errorf("expiry = %v, want %v", pending.ExpiresAt, want)
	}
	stored, err := store.LoadPendingAuth()
	if err != nil || stored != pending {
		t.Errorf("stored pending auth = %+v, error = %v", stored, err)
	}
}

func TestStartFailureClearsPendingAuthAndReportsStatusOnly(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusTooManyRequests)
		_, _ = writer.Write([]byte(`{"message":"internal detail"}`))
	}))
	defer server.Close()

	store := &memoryCredentialStore{}
	service := newTestService(t, server.URL, store)
	_, err := service.Start(context.Background(), "alice@example.com", "http://127.0.0.1:54321/auth/callback")
	var statusErr *HTTPStatusError
	if !errors.As(err, &statusErr) || statusErr.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("Start() error = %v, want HTTP status 429", err)
	}
	if err.Error() != "HTTP status 429" {
		t.Errorf("error = %q, want status only", err)
	}
	if _, err := store.LoadPendingAuth(); !errors.Is(err, ErrPendingAuthNotFound) {
		t.Errorf("LoadPendingAuth() error = %v, want cleared state", err)
	}
}

func TestStartWithoutCallbackOmitsContinueTo(t *testing.T) {
	var requestBody startAuthRequest
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if err := json.NewDecoder(request.Body).Decode(&requestBody); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		writer.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	store := &memoryCredentialStore{}
	service := newTestService(t, server.URL, store)
	result, err := service.Start(context.Background(), "alice@example.com", "")
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if requestBody.ContinueTo != "" || result.Pending.CallbackURL != "" {
		t.Errorf("callback URL = %q, continue_to = %q; want both omitted", result.Pending.CallbackURL, requestBody.ContinueTo)
	}
	if result.Pending.CodeVerifier == "" || result.Pending.State == "" || result.Pending.Nonce == "" {
		t.Errorf("pending fallback authentication is incomplete: %+v", result.Pending)
	}
}

func TestCompleteCallbackStoresAuthorizationCode(t *testing.T) {
	pending := testPendingAuth()
	store := &memoryCredentialStore{pending: &pending}
	service := newTestService(t, "http://127.0.0.1:1", store)
	service.now = func() time.Time { return pending.ExpiresAt.Add(-time.Minute) }

	err := service.CompleteCallback(CallbackResult{
		AuthorizationCode: "authorization-code",
		State:             pending.State,
		Nonce:             pending.Nonce,
	})
	if err != nil {
		t.Fatalf("CompleteCallback() error = %v", err)
	}
	stored, err := store.LoadPendingAuth()
	if err != nil {
		t.Fatalf("LoadPendingAuth() error = %v", err)
	}
	if stored.AuthorizationCode != "authorization-code" {
		t.Errorf("authorization code = %q, want saved code", stored.AuthorizationCode)
	}
}

func TestCompleteCodeStoresTrimmedAuthorizationCode(t *testing.T) {
	pending := testPendingAuth()
	store := &memoryCredentialStore{pending: &pending}
	service := newTestService(t, "http://127.0.0.1:1", store)
	service.now = func() time.Time { return pending.ExpiresAt.Add(-time.Minute) }

	if err := service.CompleteCode("  pasted-authorization-code  "); err != nil {
		t.Fatalf("CompleteCode() error = %v", err)
	}
	stored, err := store.LoadPendingAuth()
	if err != nil {
		t.Fatalf("LoadPendingAuth() error = %v", err)
	}
	if stored.AuthorizationCode != "pasted-authorization-code" {
		t.Errorf("authorization code = %q, want trimmed pasted code", stored.AuthorizationCode)
	}
}

func TestExchangeUsesPendingPKCEAndStoresTokens(t *testing.T) {
	pending := testPendingAuth()
	pending.AuthorizationCode = "authorization-code"
	store := &memoryCredentialStore{pending: &pending}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", request.Method)
		}
		if request.URL.Path != "/api/v1/oauth/token" {
			t.Errorf("path = %q, want /api/v1/oauth/token", request.URL.Path)
		}
		var body tokenRequest
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatalf("decode token request: %v", err)
		}
		if body.GrantType != authorizationGrant || body.Code != pending.AuthorizationCode || body.ClientID != "dvpn" || body.CodeVerifier != pending.CodeVerifier || body.Device != "test-device" {
			t.Errorf("token request = %+v, want authorization-code grant and saved PKCE context", body)
		}
		if body.RefreshToken != "" {
			t.Errorf("token request unexpectedly contains refresh token")
		}
		_, _ = writer.Write([]byte(`{"access_token":"access-value","refresh_token":"refresh-value","token_type":"Bearer","expires_in":3600,"user_id":"user-123"}`))
	}))
	defer server.Close()

	service := newTestService(t, server.URL, store)
	service.now = func() time.Time { return pending.ExpiresAt.Add(-time.Minute) }
	if err := service.Exchange(context.Background()); err != nil {
		t.Fatalf("Exchange() error = %v", err)
	}
	if store.accessToken != "access-value" || store.refreshToken != "refresh-value" {
		t.Errorf("stored tokens = %q, %q", store.accessToken, store.refreshToken)
	}
	if _, err := store.LoadPendingAuth(); !errors.Is(err, ErrPendingAuthNotFound) {
		t.Errorf("LoadPendingAuth() error = %v, want cleared state", err)
	}
}

func TestExchangeRejectsExpiredPendingAuth(t *testing.T) {
	pending := testPendingAuth()
	pending.AuthorizationCode = "authorization-code"
	store := &memoryCredentialStore{pending: &pending}
	service := newTestService(t, "http://127.0.0.1:1", store)
	service.now = func() time.Time { return pending.ExpiresAt }

	err := service.Exchange(context.Background())
	if !errors.Is(err, ErrPendingAuthExpired) {
		t.Fatalf("Exchange() error = %v, want ErrPendingAuthExpired", err)
	}
	if _, err := store.LoadPendingAuth(); !errors.Is(err, ErrPendingAuthNotFound) {
		t.Errorf("LoadPendingAuth() error = %v, want cleared state", err)
	}
}

func TestExchangeRejectsInvalidTokenResponseWithoutSavingTokens(t *testing.T) {
	pending := testPendingAuth()
	pending.AuthorizationCode = "authorization-code"
	store := &memoryCredentialStore{pending: &pending}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte(`{"access_token":"access-value","refresh_token":"refresh-value","token_type":"mac","expires_in":3600}`))
	}))
	defer server.Close()

	service := newTestService(t, server.URL, store)
	service.now = func() time.Time { return pending.ExpiresAt.Add(-time.Minute) }
	err := service.Exchange(context.Background())
	if err == nil || err.Error() != "authentication response contained an unsupported token type" {
		t.Fatalf("Exchange() error = %v, want unsupported token type", err)
	}
	if store.accessToken != "" || store.refreshToken != "" {
		t.Errorf("invalid response saved tokens = %q, %q", store.accessToken, store.refreshToken)
	}
}

func TestExchangeReportsHTTPFailureWithoutResponseDetails(t *testing.T) {
	pending := testPendingAuth()
	pending.AuthorizationCode = "authorization-code"
	store := &memoryCredentialStore{pending: &pending}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusUnauthorized)
		_, _ = writer.Write([]byte(`{"message":"authorization code detail must remain private"}`))
	}))
	defer server.Close()

	service := newTestService(t, server.URL, store)
	service.now = func() time.Time { return pending.ExpiresAt.Add(-time.Minute) }
	err := service.Exchange(context.Background())
	var statusErr *HTTPStatusError
	if !errors.As(err, &statusErr) || statusErr.StatusCode != http.StatusUnauthorized {
		t.Fatalf("Exchange() error = %v, want HTTP status 401", err)
	}
	if err.Error() != "HTTP status 401" {
		t.Errorf("error = %q, want status only", err)
	}
}

func TestConfiguredClientRefreshesUsingRefreshTokenContract(t *testing.T) {
	var refreshCalls atomic.Int32
	authServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		refreshCalls.Add(1)
		if request.URL.Path != "/api/v1/oauth/token" {
			t.Errorf("path = %q, want /api/v1/oauth/token", request.URL.Path)
		}
		var body tokenRequest
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatalf("decode refresh request: %v", err)
		}
		if body.GrantType != refreshTokenGrant || body.RefreshToken != "old-refresh" || body.ClientID != "dvpn" {
			t.Errorf("refresh request = %+v, want refresh-token grant", body)
		}
		if body.Code != "" || body.CodeVerifier != "" || body.Device != "" {
			t.Errorf("refresh request unexpectedly contains authorization-code fields")
		}
		_, _ = writer.Write([]byte(`{"access_token":"new-access","refresh_token":"new-refresh","token_type":"Bearer","expires_in":3600,"user_id":"user-123"}`))
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
		t.Errorf("response OK = %v, API calls = %d, refresh calls = %d", response.OK, apiCalls.Load(), refreshCalls.Load())
	}
	if store.accessToken != "new-access" || store.refreshToken != "new-refresh" {
		t.Errorf("stored tokens = %q, %q", store.accessToken, store.refreshToken)
	}
}

func TestConfiguredClientReportsInvalidRefreshWithoutLeakingResponse(t *testing.T) {
	authServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusUnauthorized)
		_, _ = writer.Write([]byte(`{"message":"refresh token detail must remain private"}`))
	}))
	defer authServer.Close()

	api := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusUnauthorized)
	}))
	defer api.Close()

	store := &memoryCredentialStore{accessToken: "expired-access", refreshToken: "invalid-refresh"}
	service := newTestService(t, authServer.URL, store)
	apiClient, err := client.New(api.URL, time.Second, false)
	if err != nil {
		t.Fatalf("client.New() error = %v", err)
	}
	if err := service.ConfigureClient(apiClient); err != nil {
		t.Fatalf("ConfigureClient() error = %v", err)
	}

	err = apiClient.Get(context.Background(), "/protected", nil)
	var statusErr *HTTPStatusError
	if !errors.As(err, &statusErr) || statusErr.StatusCode != http.StatusUnauthorized {
		t.Fatalf("Get() error = %v, want refresh HTTP status 401", err)
	}
	if strings.Contains(err.Error(), "refresh token detail") || strings.Contains(err.Error(), "invalid-refresh") {
		t.Errorf("Get() error exposed sensitive response data: %q", err)
	}
}

func newTestService(t *testing.T, authURL string, store CredentialStore) *Service {
	t.Helper()
	authClient, err := client.New(authURL+"/api/v1", time.Second, false)
	if err != nil {
		t.Fatalf("client.New() error = %v", err)
	}
	return NewService(authClient, store, Options{
		ClientID:       "dvpn",
		Device:         "test-device",
		PendingAuthTTL: 10 * time.Minute,
	})
}

func testPendingAuth() PendingAuth {
	return PendingAuth{
		Email:         "alice@example.com",
		State:         "state-value",
		Nonce:         "nonce-value",
		CodeVerifier:  "verifier-value",
		CodeChallenge: "challenge-value",
		CallbackURL:   "http://127.0.0.1:53682/auth/callback",
		ExpiresAt:     time.Date(2026, time.September, 25, 10, 10, 0, 0, time.UTC),
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
