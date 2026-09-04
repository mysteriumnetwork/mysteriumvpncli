package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mysteriumnetwork/mysteriumvpncli/internal/auth"
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
	for _, expected := range []string{"help", "version", "auth --username <name>", "disconnect"} {
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

func TestRunPlaceholderCommands(t *testing.T) {
	for _, command := range commands {
		if command == "auth" || command == "logout" || command == "help" || command == "version" {
			continue
		}
		t.Run(command, func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			exitCode := run([]string{command}, nil, &stdout, &stderr)

			if exitCode != 0 {
				t.Fatalf("run() exit code = %d, want 0; stderr = %q", exitCode, stderr.String())
			}
			if got, want := stdout.String(), "mystvpn "+command+": not implemented yet\n"; got != want {
				t.Errorf("stdout = %q, want %q", got, want)
			}
		})
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
