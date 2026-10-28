package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mysteriumnetwork/mysteriumvpncli/internal/auth"
	"github.com/mysteriumnetwork/mysteriumvpncli/internal/client"
	"github.com/mysteriumnetwork/mysteriumvpncli/internal/config"
)

type testTokenRequest struct {
	GrantType    string `json:"grant_type"`
	ClientID     string `json:"client_id"`
	RefreshToken string `json:"refresh_token"`
}

func TestRunWithoutArgumentsPrintsUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer

	exitCode := run(nil, nil, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("run() exit code = %d, want 0", exitCode)
	}
	if !strings.Contains(stdout.String(), "Usage:") {
		t.Errorf("stdout = %q, want usage", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr = %q, want empty", stderr.String())
	}
}

func TestRunVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer

	exitCode := run([]string{"version"}, nil, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("run() exit code = %d, want 0", exitCode)
	}
	if got, want := stdout.String(), "mystvpn "+version+"\n"; got != want {
		t.Errorf("stdout = %q, want %q", got, want)
	}
}

func TestRunHelpListsCommands(t *testing.T) {
	var stdout, stderr bytes.Buffer

	exitCode := run([]string{"help"}, nil, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("run() exit code = %d, want 0", exitCode)
	}
	for _, expected := range []string{"auth", "Sign in through browser approval.", "config", "View or change connection settings and profiles.", "countries", "List country codes and full names", "connect", "Connect to a country", "refresh", "status", "disconnect", "logout", "help", "version", "Examples:", `mystvpn help <command>`, "-h, --help"} {
		if !strings.Contains(stdout.String(), expected) {
			t.Errorf("help output does not contain %q: %q", expected, stdout.String())
		}
	}
	if strings.Contains(stdout.String(), "\n  profile ") {
		t.Errorf("help advertises a top-level profile command: %q", stdout.String())
	}
	for _, hidden := range []string{"api-url", "sentinel", "pool", "debug"} {
		if strings.Contains(strings.ToLower(stdout.String()), hidden) {
			t.Errorf("help output contains internal option %q: %q", hidden, stdout.String())
		}
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr = %q, want empty", stderr.String())
	}
}

func TestRunRejectsUnknownCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer

	exitCode := run([]string{"unknown"}, nil, &stdout, &stderr)

	if exitCode != 2 {
		t.Fatalf("run() exit code = %d, want 2", exitCode)
	}
	if !strings.Contains(stderr.String(), `unknown command "unknown"`) {
		t.Errorf("stderr = %q, want unknown-command error", stderr.String())
	}
}

func TestRunRejectsRootFlags(t *testing.T) {
	for _, option := range []string{"--version", "--api-url", "--sentinel-url", "--pool", "--debug"} {
		t.Run(option, func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			exitCode := run([]string{option, "value"}, nil, &stdout, &stderr)

			if exitCode != 2 {
				t.Fatalf("run() exit code = %d, want 2", exitCode)
			}
			if !strings.Contains(stderr.String(), "unknown command") {
				t.Errorf("stderr = %q, want unknown-command error", stderr.String())
			}
		})
	}
}

func TestRunAuth(t *testing.T) {
	configureTestHome(t)
	var activationID string
	var pollCalls atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch {
		case request.Method == http.MethodPost && request.URL.Path == "/api/v1/auth/activation":
			var body map[string]string
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Fatalf("decode request: %v", err)
			}
			activationID = body["id"]
			if len(body) != 1 || activationID == "" {
				t.Errorf("request body = %v, want only activation id", body)
			}
			writer.WriteHeader(http.StatusOK)
		case request.Method == http.MethodGet && request.URL.Path == "/api/v1/auth/activation/"+activationID:
			call := pollCalls.Add(1)
			if call < 2 {
				_, _ = writer.Write([]byte(`{"id":"` + activationID + `","valid":true,"token":null}`))
				return
			}
			_, _ = writer.Write([]byte(`{"id":"` + activationID + `","valid":true,"token":{"access_token":"test-access-token","refresh_token":"test-refresh-token","token_type":"Bearer","expires_in":3600,"user_id":"user-123"}}`))
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	var stdout, stderr bytes.Buffer
	cfg := config.Load()
	cfg.APIURL = server.URL + "/api/v1"
	cfg.AuthPollInterval = time.Millisecond
	cfg.AuthTimeout = time.Second
	exitCode := runWithConfig(
		[]string{"auth"},
		nil,
		&stdout,
		&stderr,
		cfg,
	)

	if exitCode != 0 {
		t.Fatalf("run() exit code = %d, want 0; stderr = %q", exitCode, stderr.String())
	}
	wantOutput := "Open this URL in your browser to authenticate:\n" +
		"https://app.mysteriumvpn.com/oauth/authorize?client_id=cli&request_id=" + activationID + "&response_type=activation_none\n" +
		"Waiting for authentication approval...\n" +
		"[SUCCESS] Authentication successful.\n"
	if stdout.String() != wantOutput {
		t.Errorf("stdout = %q, want %q", stdout.String(), wantOutput)
	}
	if pollCalls.Load() != 2 {
		t.Errorf("poll calls = %d, want 2", pollCalls.Load())
	}
	store, err := auth.NewDefaultFileStore()
	if err != nil {
		t.Fatalf("NewDefaultFileStore() error = %v", err)
	}
	if _, err := store.LoadPendingAuth(); !errors.Is(err, auth.ErrPendingAuthNotFound) {
		t.Errorf("LoadPendingAuth() error = %v, want cleared pending state", err)
	}
	accessToken, err := store.LoadAccessToken()
	if err != nil || accessToken != "test-access-token" {
		t.Errorf("LoadAccessToken() = %q, %v; want test-access-token", accessToken, err)
	}
	refreshToken, err := store.LoadRefreshToken()
	if err != nil || refreshToken != "test-refresh-token" {
		t.Errorf("LoadRefreshToken() = %q, %v; want test-refresh-token", refreshToken, err)
	}
}

func TestRunAuthTimesOutAndClearsPendingState(t *testing.T) {
	configureTestHome(t)
	var pollCalls atomic.Int32
	var activationID string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch {
		case request.Method == http.MethodPost && request.URL.Path == "/api/v1/auth/activation":
			var body map[string]string
			_ = json.NewDecoder(request.Body).Decode(&body)
			activationID = body["id"]
			writer.WriteHeader(http.StatusNoContent)
		case request.Method == http.MethodGet && request.URL.Path == "/api/v1/auth/activation/"+activationID:
			pollCalls.Add(1)
			_, _ = writer.Write([]byte(`{"id":"` + activationID + `","valid":true,"token":null}`))
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	var stdout, stderr bytes.Buffer
	cfg := config.Load()
	cfg.APIURL = server.URL + "/api/v1"
	cfg.AuthPollInterval = 5 * time.Millisecond
	cfg.AuthTimeout = 25 * time.Millisecond
	exitCode := runWithConfig(
		[]string{"auth"},
		nil,
		&stdout,
		&stderr,
		cfg,
	)

	if exitCode != 1 {
		t.Fatalf("run() exit code = %d, want 1", exitCode)
	}
	if !strings.Contains(stdout.String(), "Open this URL in your browser to authenticate:\n") || !strings.Contains(stdout.String(), "client_id=cli") || !strings.Contains(stdout.String(), "Waiting for authentication approval...\n") {
		t.Errorf("stdout = %q, want browser activation instructions", stdout.String())
	}
	if got, want := stderr.String(), "[ERROR] mystvpn auth: authentication timed out; run \"mystvpn auth\" again and approve the browser prompt before it expires\n"; got != want {
		t.Errorf("stderr = %q, want %q", got, want)
	}
	if pollCalls.Load() < 2 {
		t.Errorf("poll calls = %d, want at least 2", pollCalls.Load())
	}
	store := defaultTestStore(t)
	if _, err := store.LoadPendingAuth(); !errors.Is(err, auth.ErrPendingAuthNotFound) {
		t.Errorf("LoadPendingAuth() error = %v, want cleared pending state", err)
	}
}

func TestRunAuthReportsInvalidActivationAndClearsPendingState(t *testing.T) {
	configureTestHome(t)
	var activationID string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch {
		case request.Method == http.MethodPost && request.URL.Path == "/api/v1/auth/activation":
			var body map[string]string
			_ = json.NewDecoder(request.Body).Decode(&body)
			activationID = body["id"]
		case request.Method == http.MethodGet && request.URL.Path == "/api/v1/auth/activation/"+activationID:
			_, _ = writer.Write([]byte(`{"id":"` + activationID + `","valid":false,"token":null}`))
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	var stdout, stderr bytes.Buffer
	cfg := config.Load()
	cfg.APIURL = server.URL + "/api/v1"
	cfg.AuthPollInterval = time.Millisecond
	cfg.AuthTimeout = time.Second
	exitCode := runWithConfig([]string{"auth"}, nil, &stdout, &stderr, cfg)

	if exitCode != 1 {
		t.Fatalf("run() exit code = %d, want 1", exitCode)
	}
	if got, want := stderr.String(), "[ERROR] mystvpn auth: activation expired or was rejected; run \"mystvpn auth\" again to request a new approval link\n"; got != want {
		t.Errorf("stderr = %q, want %q", got, want)
	}
	if !strings.Contains(stdout.String(), "client_id=cli") {
		t.Errorf("stdout = %q, want cli authorization URL", stdout.String())
	}
	store := defaultTestStore(t)
	if _, err := store.LoadPendingAuth(); !errors.Is(err, auth.ErrPendingAuthNotFound) {
		t.Errorf("LoadPendingAuth() error = %v, want cleared pending state", err)
	}
}

func TestRunAuthRejectsEmailFlag(t *testing.T) {
	var stdout, stderr bytes.Buffer

	exitCode := run([]string{"auth", "--email", "alice@example.com"}, nil, &stdout, &stderr)

	if exitCode != 2 {
		t.Fatalf("run() exit code = %d, want 2", exitCode)
	}
	if !strings.Contains(stderr.String(), `unexpected argument "--email"`) {
		t.Errorf("stderr = %q, want rejected email flag", stderr.String())
	}
}

func TestRunAuthExplainsHTTPFailureWithoutResponseBody(t *testing.T) {
	configureTestHome(t)

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusUnauthorized)
		_, _ = writer.Write([]byte(`{"message":"do not print this"}`))
	}))
	defer server.Close()

	var stdout, stderr bytes.Buffer
	cfg := config.Load()
	cfg.APIURL = server.URL + "/api/v1"
	exitCode := runWithConfig(
		[]string{"auth"},
		nil,
		&stdout,
		&stderr,
		cfg,
	)

	if exitCode != 1 {
		t.Fatalf("run() exit code = %d, want 1", exitCode)
	}
	if got, want := stderr.String(), "[ERROR] mystvpn auth: HTTP status 401 (Unauthorized): authentication expired or was rejected; run \"mystvpn auth\" to sign in again\n"; got != want {
		t.Errorf("stderr = %q, want %q", got, want)
	}
}

func TestRunCountries(t *testing.T) {
	for _, ipType := range []string{"residential", "hosting"} {
		t.Run(ipType, func(t *testing.T) {
			configureTestHome(t)
			store := defaultTestStore(t)
			if err := store.SaveAccessToken("auth-value"); err != nil {
				t.Fatalf("SaveAccessToken() error = %v", err)
			}

			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				if request.Method != http.MethodGet {
					t.Errorf("method = %s, want GET", request.Method)
				}
				if request.URL.Path != "/api/v1/connection/config" {
					t.Errorf("path = %q, want connection config endpoint", request.URL.Path)
				}
				if got := request.URL.Query().Get("ip_type"); got != ipType {
					t.Errorf("ip_type = %q, want %q", got, ipType)
				}
				if got := request.Header.Get("Authorization"); got != "Bearer auth-value" {
					t.Errorf("Authorization = %q, want stored auth token", got)
				}
				_, _ = writer.Write([]byte(`{"countries":["DE","MX","SE"],"top_countries":["SE"]}`))
			}))
			defer server.Close()

			cfg := config.Load()
			cfg.APIURL = server.URL + "/api/v1"
			var stdout, stderr bytes.Buffer
			exitCode := runWithConfig(
				[]string{"countries", "--ip-type", ipType},
				nil,
				&stdout,
				&stderr,
				cfg,
			)

			if exitCode != 0 {
				t.Fatalf("run() exit code = %d, want 0; stderr = %q", exitCode, stderr.String())
			}
			want := fmt.Sprintf("[SUCCESS] Available countries (3) for IP type: %s\n\nCODE  COUNTRY    CODE  COUNTRY\nDE    Germany    SE    Sweden\nMX    Mexico\n", ipType)
			if got := stdout.String(); got != want {
				t.Errorf("stdout = %q, want %q", got, want)
			}
		})
	}
}

func TestRunCountriesValidatesIPType(t *testing.T) {
	configureTestHome(t)
	tests := []struct {
		name     string
		args     []string
		wantText string
	}{
		{name: "explicit empty", args: []string{"countries", "--ip-type="}, wantText: `ip type must be "residential" or "hosting"`},
		{name: "invalid", args: []string{"countries", "--ip-type", "mobile"}, wantText: `ip type must be "residential" or "hosting"`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			exitCode := run(test.args, nil, &stdout, &stderr)

			if exitCode != 2 {
				t.Fatalf("run() exit code = %d, want 2", exitCode)
			}
			if !strings.Contains(stderr.String(), test.wantText) {
				t.Errorf("stderr = %q, want %q", stderr.String(), test.wantText)
			}
		})
	}
}

func TestRunCountriesRequiresAuthentication(t *testing.T) {
	configureTestHome(t)
	var stdout, stderr bytes.Buffer

	exitCode := run([]string{"countries", "--ip-type", "residential"}, nil, &stdout, &stderr)

	if exitCode != 1 {
		t.Fatalf("run() exit code = %d, want 1", exitCode)
	}
	if !strings.Contains(stderr.String(), "authentication required") {
		t.Errorf("stderr = %q, want authentication-required error", stderr.String())
	}
}

func TestRunCountriesReportsHTTPStatus(t *testing.T) {
	configureTestHome(t)
	store := defaultTestStore(t)
	if err := store.SaveAccessToken("auth-value"); err != nil {
		t.Fatalf("SaveAccessToken() error = %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusForbidden)
		_, _ = writer.Write([]byte(`{"message":"do not print this"}`))
	}))
	defer server.Close()

	cfg := config.Load()
	cfg.APIURL = server.URL
	var stdout, stderr bytes.Buffer
	exitCode := runWithConfig(
		[]string{"countries", "--ip-type", "hosting"},
		nil,
		&stdout,
		&stderr,
		cfg,
	)

	if exitCode != 1 {
		t.Fatalf("run() exit code = %d, want 1", exitCode)
	}
	if got, want := stderr.String(), "[ERROR] mystvpn countries: HTTP status 403 (Forbidden): access denied; check your VPN account permissions and subscription\n"; got != want {
		t.Errorf("stderr = %q, want %q", got, want)
	}
}

func TestWriteCountriesErrorExplainsCommonHTTPStatuses(t *testing.T) {
	for _, test := range []struct {
		status int
		action string
	}{
		{http.StatusUnauthorized, `run "mystvpn auth"`},
		{http.StatusForbidden, "check your VPN account permissions and subscription"},
		{http.StatusNotFound, "check for a CLI update"},
		{http.StatusTooManyRequests, "wait a moment"},
		{http.StatusInternalServerError, "try again later"},
	} {
		t.Run(http.StatusText(test.status), func(t *testing.T) {
			var output bytes.Buffer

			writeCountriesError(&output, &client.APIError{StatusCode: test.status, Message: "secret response body"})

			prefix := fmt.Sprintf("[ERROR] mystvpn countries: HTTP status %d (%s): ", test.status, http.StatusText(test.status))
			if !strings.HasPrefix(output.String(), prefix) || !strings.Contains(output.String(), test.action) || strings.Contains(output.String(), "secret") {
				t.Errorf("output = %q, want prefix %q and action %q without response details", output.String(), prefix, test.action)
			}
		})
	}
}

func TestRunCountriesRefreshesExpiredToken(t *testing.T) {
	configureTestHome(t)
	store := defaultTestStore(t)
	if err := store.SaveAccessToken("old-auth"); err != nil {
		t.Fatalf("SaveAccessToken() error = %v", err)
	}
	if err := store.SaveRefreshToken("old-refresh"); err != nil {
		t.Fatalf("SaveRefreshToken() error = %v", err)
	}

	var refreshCalls atomic.Int32
	var apiCalls atomic.Int32
	apiServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/api/v1/oauth/token":
			refreshCalls.Add(1)
			var body testTokenRequest
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Fatalf("decode refresh request: %v", err)
			}
			if body.GrantType != "refresh_token" || body.RefreshToken != "old-refresh" || body.ClientID != "cli" {
				t.Errorf("refresh request = %v, want refresh-token grant", body)
			}
			_, _ = writer.Write([]byte(`{"access_token":"new-auth","refresh_token":"new-refresh","token_type":"Bearer","expires_in":3600}`))
		case "/api/v1/connection/config":
			apiCalls.Add(1)
			if request.Header.Get("Authorization") != "Bearer new-auth" {
				writer.WriteHeader(http.StatusUnauthorized)
				return
			}
			_, _ = writer.Write([]byte(`{"countries":["CA"],"top_countries":["CA"]}`))
		default:
			http.NotFound(writer, request)
		}
	}))
	defer apiServer.Close()

	cfg := config.Load()
	cfg.APIURL = apiServer.URL + "/api/v1"
	var stdout, stderr bytes.Buffer
	exitCode := runWithConfig(
		[]string{"countries", "--ip-type", "residential"},
		nil,
		&stdout,
		&stderr,
		cfg,
	)

	if exitCode != 0 {
		t.Fatalf("run() exit code = %d, want 0; stderr = %q", exitCode, stderr.String())
	}
	if got, want := stdout.String(), "[SUCCESS] Available countries (1) for IP type: residential\n\nCODE  COUNTRY\nCA    Canada\n"; got != want {
		t.Errorf("stdout = %q, want %q", got, want)
	}
	if apiCalls.Load() != 2 || refreshCalls.Load() != 1 {
		t.Errorf("api calls = %d, refresh calls = %d; want 2 and 1", apiCalls.Load(), refreshCalls.Load())
	}
	authToken, err := store.LoadAccessToken()
	if err != nil || authToken != "new-auth" {
		t.Errorf("stored auth token = %q, error = %v", authToken, err)
	}
	refreshToken, err := store.LoadRefreshToken()
	if err != nil || refreshToken != "new-refresh" {
		t.Errorf("stored refresh token = %q, error = %v", refreshToken, err)
	}
}

func TestRunLogoutClearsTokens(t *testing.T) {
	configureTestHome(t)
	store, err := auth.NewDefaultFileStore()
	if err != nil {
		t.Fatalf("NewDefaultFileStore() error = %v", err)
	}
	if err := store.SaveAccessToken("auth-value"); err != nil {
		t.Fatalf("SaveAccessToken() error = %v", err)
	}
	if err := store.SaveRefreshToken("refresh-value"); err != nil {
		t.Fatalf("SaveRefreshToken() error = %v", err)
	}

	var stdout, stderr bytes.Buffer
	exitCode := run([]string{"logout"}, nil, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("run() exit code = %d, want 0; stderr = %q", exitCode, stderr.String())
	}
	if stdout.String() != "[SUCCESS] Logout successful.\n" {
		t.Errorf("stdout = %q, want logout success message", stdout.String())
	}
	if _, err := store.LoadAccessToken(); !errors.Is(err, auth.ErrTokenNotFound) {
		t.Errorf("LoadAccessToken() error = %v, want ErrTokenNotFound", err)
	}
	if _, err := store.LoadRefreshToken(); !errors.Is(err, auth.ErrTokenNotFound) {
		t.Errorf("LoadRefreshToken() error = %v, want ErrTokenNotFound", err)
	}
}

func configureTestHome(t *testing.T) {
	t.Helper()

	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", home)
}

func defaultTestStore(t *testing.T) *auth.FileStore {
	t.Helper()

	store, err := auth.NewDefaultFileStore()
	if err != nil {
		t.Fatalf("NewDefaultFileStore() error = %v", err)
	}
	return store
}
