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

	"github.com/mysteriumnetwork/mysteriumvpncli/internal/auth"
	"github.com/mysteriumnetwork/mysteriumvpncli/internal/client"
	"github.com/mysteriumnetwork/mysteriumvpncli/internal/config"
)

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
	for _, expected := range []string{"help", "version", "auth --username <name>", "countries --ip-type <residential|hosting>", "disconnect"} {
		if !strings.Contains(stdout.String(), expected) {
			t.Errorf("help output does not contain %q: %q", expected, stdout.String())
		}
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
	for _, option := range []string{"--help", "-h", "--version", "--api-url", "--sentinel-url", "--pool", "--debug"} {
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

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/v1/auth/password" {
			t.Errorf("path = %q, want password auth endpoint", request.URL.Path)
		}
		var body map[string]string
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if body["username"] != "alice" || body["password"] != "secret" || body["pool"] != "default" {
			t.Errorf("request body = %v, want credentials and default pool", body)
		}
		_, _ = writer.Write([]byte(`{"auth_token":"auth-value","refresh_token":"refresh-value"}`))
	}))
	defer server.Close()

	var stdout, stderr bytes.Buffer
	cfg := config.Load()
	cfg.SentinelURL = server.URL
	exitCode := runWithConfig(
		[]string{"auth", "--username", "alice", "--password", "secret"},
		nil,
		&stdout,
		&stderr,
		cfg,
	)

	if exitCode != 0 {
		t.Fatalf("run() exit code = %d, want 0; stderr = %q", exitCode, stderr.String())
	}
	if stdout.String() != "Authentication successful.\n" {
		t.Errorf("stdout = %q, want success message", stdout.String())
	}
	store, err := auth.NewDefaultFileStore()
	if err != nil {
		t.Fatalf("NewDefaultFileStore() error = %v", err)
	}
	authToken, err := store.LoadAuthToken()
	if err != nil || authToken != "auth-value" {
		t.Errorf("stored auth token = %q, error = %v", authToken, err)
	}
	refreshToken, err := store.LoadRefreshToken()
	if err != nil || refreshToken != "refresh-value" {
		t.Errorf("stored refresh token = %q, error = %v", refreshToken, err)
	}
}

func TestRunAuthRequiresPasswordForNonInteractiveInput(t *testing.T) {
	var stdout, stderr bytes.Buffer

	exitCode := run([]string{"auth", "--username", "alice"}, nil, &stdout, &stderr)

	if exitCode != 2 {
		t.Fatalf("run() exit code = %d, want 2", exitCode)
	}
	if !strings.Contains(stderr.String(), "provide --password when standard input is not interactive") {
		t.Errorf("stderr = %q, want non-interactive password error", stderr.String())
	}
}

func TestRunAuthReportsOnlyHTTPStatus(t *testing.T) {
	configureTestHome(t)

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusUnauthorized)
		_, _ = writer.Write([]byte(`{"message":"do not print this"}`))
	}))
	defer server.Close()

	var stdout, stderr bytes.Buffer
	cfg := config.Load()
	cfg.SentinelURL = server.URL
	exitCode := runWithConfig(
		[]string{"auth", "--username", "alice", "--password", "wrong"},
		nil,
		&stdout,
		&stderr,
		cfg,
	)

	if exitCode != 1 {
		t.Fatalf("run() exit code = %d, want 1", exitCode)
	}
	if got, want := stderr.String(), "mystvpn auth: HTTP status 401\n"; got != want {
		t.Errorf("stderr = %q, want %q", got, want)
	}
}

func TestRunAuthRejectsNonAuthFlags(t *testing.T) {
	var stdout, stderr bytes.Buffer

	exitCode := run([]string{"auth", "--username", "alice", "--pool", "other"}, nil, &stdout, &stderr)

	if exitCode != 2 {
		t.Fatalf("run() exit code = %d, want 2", exitCode)
	}
	if !strings.Contains(stderr.String(), "flag provided but not defined: -pool") {
		t.Errorf("stderr = %q, want unknown auth flag error", stderr.String())
	}
}

func TestRunAuthRejectsHelpFlags(t *testing.T) {
	for _, option := range []string{"--help", "-h"} {
		t.Run(option, func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			exitCode := run([]string{"auth", option}, nil, &stdout, &stderr)

			if exitCode != 2 {
				t.Fatalf("run() exit code = %d, want 2", exitCode)
			}
			if !strings.Contains(stderr.String(), "help flags are not supported") {
				t.Errorf("stderr = %q, want unsupported-help error", stderr.String())
			}
		})
	}
}

func TestRunCountries(t *testing.T) {
	for _, ipType := range []string{"residential", "hosting"} {
		t.Run(ipType, func(t *testing.T) {
			configureTestHome(t)
			store := defaultTestStore(t)
			if err := store.SaveAuthToken("auth-value"); err != nil {
				t.Fatalf("SaveAuthToken() error = %v", err)
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
			if got, want := stdout.String(), "Available countries (3):\n\nDE  MX  SE\n"; got != want {
				t.Errorf("stdout = %q, want %q", got, want)
			}
		})
	}
}

func TestRunCountriesValidatesIPType(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantText string
	}{
		{name: "missing", args: []string{"countries"}, wantText: "--ip-type is required"},
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
	if err := store.SaveAuthToken("auth-value"); err != nil {
		t.Fatalf("SaveAuthToken() error = %v", err)
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
	if got, want := stderr.String(), "mystvpn countries: HTTP status 403\n"; got != want {
		t.Errorf("stderr = %q, want %q", got, want)
	}
}

func TestWriteCountriesErrorReportsCommonHTTPStatuses(t *testing.T) {
	for _, statusCode := range []int{
		http.StatusUnauthorized,
		http.StatusForbidden,
		http.StatusNotFound,
		http.StatusTooManyRequests,
		http.StatusInternalServerError,
	} {
		t.Run(http.StatusText(statusCode), func(t *testing.T) {
			var output bytes.Buffer

			writeCountriesError(&output, &client.APIError{StatusCode: statusCode})

			want := fmt.Sprintf("mystvpn countries: HTTP status %d\n", statusCode)
			if output.String() != want {
				t.Errorf("output = %q, want %q", output.String(), want)
			}
		})
	}
}

func TestRunCountriesRefreshesExpiredToken(t *testing.T) {
	configureTestHome(t)
	store := defaultTestStore(t)
	if err := store.SaveAuthToken("old-auth"); err != nil {
		t.Fatalf("SaveAuthToken() error = %v", err)
	}
	if err := store.SaveRefreshToken("old-refresh"); err != nil {
		t.Fatalf("SaveRefreshToken() error = %v", err)
	}

	var refreshCalls atomic.Int32
	authServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		refreshCalls.Add(1)
		if request.URL.Path != "/api/v1/token/refresh" {
			t.Errorf("refresh path = %q", request.URL.Path)
		}
		var body map[string]string
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatalf("decode refresh request: %v", err)
		}
		if body["token"] != "old-refresh" {
			t.Errorf("refresh token = %q, want old-refresh", body["token"])
		}
		_, _ = writer.Write([]byte(`{"auth_token":"new-auth","refresh_token":"new-refresh"}`))
	}))
	defer authServer.Close()

	var apiCalls atomic.Int32
	apiServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		apiCalls.Add(1)
		if request.Header.Get("Authorization") != "Bearer new-auth" {
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = writer.Write([]byte(`{"countries":["CA"],"top_countries":["CA"]}`))
	}))
	defer apiServer.Close()

	cfg := config.Load()
	cfg.APIURL = apiServer.URL
	cfg.SentinelURL = authServer.URL
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
	if got, want := stdout.String(), "Available countries (1):\n\nCA\n"; got != want {
		t.Errorf("stdout = %q, want %q", got, want)
	}
	if apiCalls.Load() != 2 || refreshCalls.Load() != 1 {
		t.Errorf("api calls = %d, refresh calls = %d; want 2 and 1", apiCalls.Load(), refreshCalls.Load())
	}
	authToken, err := store.LoadAuthToken()
	if err != nil || authToken != "new-auth" {
		t.Errorf("stored auth token = %q, error = %v", authToken, err)
	}
	refreshToken, err := store.LoadRefreshToken()
	if err != nil || refreshToken != "new-refresh" {
		t.Errorf("stored refresh token = %q, error = %v", refreshToken, err)
	}
}

func TestWriteCountriesUsesTenSortedColumns(t *testing.T) {
	countries := []string{
		"MX", "AR", "JP", "DE", "US", "BR", "CA", "FR", "GB", "AU",
		"SE", "CH", "ES", "DK", "AT", "BE", "CL", "CO", "CZ", "EE",
		"FI", "GR", "HR",
	}
	var output bytes.Buffer

	writeCountries(&output, countries)

	want := "Available countries (23):\n\n" +
		"AR  AT  AU  BE  BR  CA  CH  CL  CO  CZ\n" +
		"DE  DK  EE  ES  FI  FR  GB  GR  HR  JP\n" +
		"MX  SE  US\n"
	if output.String() != want {
		t.Errorf("output = %q, want %q", output.String(), want)
	}
}

func TestWriteCountriesHandlesEmptyList(t *testing.T) {
	var output bytes.Buffer

	writeCountries(&output, nil)

	if got, want := output.String(), "Available countries (0):\n"; got != want {
		t.Errorf("output = %q, want %q", got, want)
	}
}

func TestRunLogoutClearsTokens(t *testing.T) {
	configureTestHome(t)
	store, err := auth.NewDefaultFileStore()
	if err != nil {
		t.Fatalf("NewDefaultFileStore() error = %v", err)
	}
	if err := store.SaveAuthToken("auth-value"); err != nil {
		t.Fatalf("SaveAuthToken() error = %v", err)
	}
	if err := store.SaveRefreshToken("refresh-value"); err != nil {
		t.Fatalf("SaveRefreshToken() error = %v", err)
	}

	var stdout, stderr bytes.Buffer
	exitCode := run([]string{"logout"}, nil, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("run() exit code = %d, want 0; stderr = %q", exitCode, stderr.String())
	}
	if stdout.String() != "Logout successful.\n" {
		t.Errorf("stdout = %q, want logout success message", stdout.String())
	}
	if _, err := store.LoadAuthToken(); !errors.Is(err, auth.ErrTokenNotFound) {
		t.Errorf("LoadAuthToken() error = %v, want ErrTokenNotFound", err)
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
