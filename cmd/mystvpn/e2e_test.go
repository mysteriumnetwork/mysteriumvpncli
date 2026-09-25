package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mysteriumnetwork/mysteriumvpncli/internal/auth"
	"github.com/mysteriumnetwork/mysteriumvpncli/internal/config"
	"github.com/mysteriumnetwork/mysteriumvpncli/internal/mockserver"
	"github.com/mysteriumnetwork/mysteriumvpncli/internal/proxy"
	"github.com/mysteriumnetwork/mysteriumvpncli/internal/state"
	"github.com/mysteriumnetwork/mysteriumvpncli/internal/wireguard"
)

func TestCLILifecycleEndToEnd(t *testing.T) {
	configureTestHome(t)
	server := mockserver.New()
	defer server.Close()

	cfg := config.Load()
	cfg.APIURL = server.APIURL()
	cfg.SentinelURL = server.SentinelURL()
	runner := &endToEndTunnelRunner{}
	var allOutput strings.Builder

	execute := func(args ...string) commandResult {
		result := executeCLI(args, cfg, runner)
		allOutput.WriteString(result.stdout)
		allOutput.WriteString(result.stderr)
		return result
	}

	assertCommandResult(t, execute("status"), 0, "connected: no\n", "")
	assertCommandResult(t, execute("auth", "--email", "alice@example.com"), 0, "Authentication link sent. Check your email.\nAuthentication successful.\n", "")

	credentialsDirectory := filepath.Join(testConfigDirectory(t), "mystvpn", "credentials")
	assertFileMode(t, filepath.Join(credentialsDirectory, "access_token"), 0o600)
	assertFileMode(t, filepath.Join(credentialsDirectory, "refresh_token"), 0o600)
	assertFileMode(t, credentialsDirectory, 0o700)

	server.RejectNextProxyRequest()
	assertCommandResult(t, execute("countries", "--ip-type", "residential"), 0, "Available countries (3):\n\nCA  DE  SE\n", "")
	assertCommandResult(t, execute("connect", "--country", "de", "--ip-type", "residential"), 0, "exit_ip: 1.2.3.4\ncountry: DE\ncity: berlin\n", "")

	connectedSession := loadEndToEndSession(t)
	if connectedSession.PublicKey == "" || connectedSession.PrivateKey == "" {
		t.Fatal("connect did not save the WireGuard keypair in session state")
	}
	assertFileMode(t, filepath.Join(testConfigDirectory(t), "mystvpn", "session.json"), 0o600)
	assertFileMode(t, filepath.Join(testConfigDirectory(t), "mystvpn", "wireguard", "keypair.json"), 0o600)
	assertFileMode(t, connectedSession.ConfigPath, 0o600)

	assertCommandResult(t, execute("status"), 0, "connected: yes\nIP address: 1.2.3.4\ncountry: DE\ncity: berlin\n", "")
	assertCommandResult(t, execute("refresh"), 0, "exit_ip: 2.3.4.5\ncountry: DE\ncity: hamburg\n", "")
	assertCommandResult(t, execute("status"), 0, "connected: yes\nIP address: 2.3.4.5\ncountry: DE\ncity: hamburg\n", "")

	refreshedSession := loadEndToEndSession(t)
	if refreshedSession.PublicKey != connectedSession.PublicKey || refreshedSession.PrivateKey != connectedSession.PrivateKey {
		t.Error("refresh did not reuse the saved WireGuard keypair")
	}
	if refreshedSession.ConfigPath != connectedSession.ConfigPath {
		t.Error("refresh changed the managed WireGuard config path")
	}
	if refreshedSession.ExitIP != "2.3.4.5" || refreshedSession.City != "hamburg" {
		t.Errorf("refreshed session = %+v, want updated metadata", refreshedSession)
	}

	assertCommandResult(t, execute("disconnect"), 0, "Disconnected successfully\n", "")
	assertCommandResult(t, execute("status"), 0, "connected: no\n", "")

	if _, err := os.Stat(refreshedSession.ConfigPath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("WireGuard config Stat() error = %v, want removed", err)
	}
	store, err := state.NewDefaultStore()
	if err != nil {
		t.Fatalf("state.NewDefaultStore() error = %v", err)
	}
	if _, err := store.Load(); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("session Load() error = %v, want removed", err)
	}

	assertCommandResult(t, execute("logout"), 0, "Logout successful.\n", "")
	tokenStore, err := auth.NewDefaultFileStore()
	if err != nil {
		t.Fatalf("auth.NewDefaultFileStore() error = %v", err)
	}
	if _, err := tokenStore.LoadAccessToken(); !errors.Is(err, auth.ErrTokenNotFound) {
		t.Errorf("LoadAccessToken() error = %v, want ErrTokenNotFound", err)
	}
	if _, err := tokenStore.LoadRefreshToken(); !errors.Is(err, auth.ErrTokenNotFound) {
		t.Errorf("LoadRefreshToken() error = %v, want ErrTokenNotFound", err)
	}

	snapshot := server.Snapshot()
	if snapshot.AuthCalls != 1 || snapshot.TokenExchangeCalls != 1 || snapshot.TokenRefreshCalls != 1 || len(snapshot.CountryQueries) != 1 {
		t.Errorf("mock calls = %+v, want one auth, token exchange, token refresh, and countries call", snapshot)
	}
	if len(snapshot.ConnectRequests) != 2 {
		t.Fatalf("connect requests = %d, want 2", len(snapshot.ConnectRequests))
	}
	for index, request := range snapshot.ConnectRequests {
		if request.PublicKey != connectedSession.PublicKey || request.Country != "DE" || request.IPType != "residential" || request.OSType != proxy.OSTypeLinux || !request.ResetConnection {
			t.Errorf("connect request %d = %+v, want saved connection context", index, request)
		}
	}
	if len(snapshot.DisconnectRequests) != 1 || snapshot.DisconnectRequests[0].PublicKey != connectedSession.PublicKey {
		t.Errorf("disconnect requests = %+v, want saved public key", snapshot.DisconnectRequests)
	}
	if got, want := strings.Join(runner.actions, ","), "up,down,up,down"; got != want {
		t.Errorf("WireGuard actions = %q, want %q", got, want)
	}

	for _, secret := range []string{
		connectedSession.PrivateKey,
		connectedSession.SessionID,
		refreshedSession.SessionID,
		"test-auth-token",
		"test-refresh-token",
		"secret",
	} {
		if strings.Contains(allOutput.String(), secret) {
			t.Errorf("CLI output exposed sensitive value %q", secret)
		}
	}
}

func TestCLIConnectReplacesActiveSession(t *testing.T) {
	configureTestHome(t)
	server := mockserver.New()
	defer server.Close()
	cfg := config.Load()
	cfg.APIURL = server.APIURL()
	cfg.SentinelURL = server.SentinelURL()
	runner := &endToEndTunnelRunner{}

	assertCommandResult(t, executeCLI([]string{"auth", "--email", "alice@example.com"}, cfg, runner), 0, "Authentication link sent. Check your email.\nAuthentication successful.\n", "")
	assertCommandResult(
		t,
		executeCLI([]string{"connect", "--country", "DE", "--ip-type", "residential"}, cfg, runner),
		0,
		"exit_ip: 1.2.3.4\ncountry: DE\ncity: berlin\n",
		"",
	)
	firstSession := loadEndToEndSession(t)

	assertCommandResult(
		t,
		executeCLI([]string{"connect", "--country", "CA", "--ip-type", "hosting"}, cfg, runner),
		0,
		"exit_ip: 2.3.4.5\ncountry: CA\ncity: hamburg\n",
		"",
	)
	secondSession := loadEndToEndSession(t)
	if secondSession.PublicKey != firstSession.PublicKey || secondSession.PrivateKey != firstSession.PrivateKey {
		t.Error("replacement connect did not reuse the app-owned keypair")
	}
	if secondSession.Country != "CA" || secondSession.IPType != "hosting" {
		t.Errorf("replacement session = %+v, want CA hosting", secondSession)
	}
	if secondSession.ConfigPath != firstSession.ConfigPath {
		t.Errorf("replacement config path = %q, want reused path %q", secondSession.ConfigPath, firstSession.ConfigPath)
	}
	if _, err := os.Stat(firstSession.ConfigPath); err != nil {
		t.Errorf("reused config Stat() error = %v", err)
	}
	if got, want := strings.Join(runner.actions, ","), "up,down,up"; got != want {
		t.Errorf("WireGuard actions = %q, want %q", got, want)
	}

	snapshot := server.Snapshot()
	if len(snapshot.ConnectRequests) != 2 || len(snapshot.DisconnectRequests) != 0 {
		t.Fatalf("API requests = %+v, want two connects and no disconnect", snapshot)
	}
	if request := snapshot.ConnectRequests[1]; request.PublicKey != firstSession.PublicKey || request.Country != "CA" || request.IPType != proxy.IPTypeHosting || !request.ResetConnection {
		t.Errorf("replacement request = %+v, want saved key and new target", request)
	}
}

func TestCLILogoutDisconnectsActiveSession(t *testing.T) {
	configureTestHome(t)
	server := mockserver.New()
	defer server.Close()
	cfg := config.Load()
	cfg.APIURL = server.APIURL()
	cfg.SentinelURL = server.SentinelURL()
	runner := &endToEndTunnelRunner{}

	assertCommandResult(t, executeCLI([]string{"auth", "--email", "alice@example.com"}, cfg, runner), 0, "Authentication link sent. Check your email.\nAuthentication successful.\n", "")
	assertCommandResult(
		t,
		executeCLI([]string{"connect", "--country", "DE", "--ip-type", "residential"}, cfg, runner),
		0,
		"exit_ip: 1.2.3.4\ncountry: DE\ncity: berlin\n",
		"",
	)
	session := loadEndToEndSession(t)

	assertCommandResult(t, executeCLI([]string{"logout"}, cfg, runner), 0, "Logout successful.\n", "")
	assertCommandResult(t, executeCLI([]string{"status"}, cfg, runner), 0, "connected: no\n", "")
	if got, want := strings.Join(runner.actions, ","), "up,down"; got != want {
		t.Errorf("WireGuard actions = %q, want %q", got, want)
	}
	if _, err := os.Stat(session.ConfigPath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("config Stat() error = %v, want removed", err)
	}
	if len(server.Snapshot().DisconnectRequests) != 1 {
		t.Error("logout did not close the remote connection")
	}
	tokenStore, err := auth.NewDefaultFileStore()
	if err != nil {
		t.Fatalf("auth.NewDefaultFileStore() error = %v", err)
	}
	if _, err := tokenStore.LoadAccessToken(); !errors.Is(err, auth.ErrTokenNotFound) {
		t.Errorf("LoadAccessToken() error = %v, want ErrTokenNotFound", err)
	}
}

func TestCLIAuthenticationFailureEndToEnd(t *testing.T) {
	configureTestHome(t)
	server := mockserver.New()
	defer server.Close()
	server.SetAuthStatus(401)

	cfg := config.Load()
	cfg.SentinelURL = server.SentinelURL()
	result := executeCLI([]string{"auth", "--email", "alice@example.com"}, cfg, &endToEndTunnelRunner{})

	assertCommandResult(t, result, 1, "", "mystvpn auth: HTTP status 401\n")
	store, err := auth.NewDefaultFileStore()
	if err != nil {
		t.Fatalf("auth.NewDefaultFileStore() error = %v", err)
	}
	if _, err := store.LoadAccessToken(); !errors.Is(err, auth.ErrTokenNotFound) {
		t.Errorf("LoadAccessToken() error = %v, want ErrTokenNotFound", err)
	}
}

func TestCLIProxyFailuresEndToEnd(t *testing.T) {
	configureTestHome(t)
	server := mockserver.New()
	defer server.Close()
	cfg := config.Load()
	cfg.APIURL = server.APIURL()
	cfg.SentinelURL = server.SentinelURL()
	runner := &endToEndTunnelRunner{}

	assertCommandResult(t, executeCLI([]string{"auth", "--email", "alice@example.com"}, cfg, runner), 0, "Authentication link sent. Check your email.\nAuthentication successful.\n", "")

	server.SetConnectStatus(http.StatusForbidden)
	assertCommandResult(
		t,
		executeCLI([]string{"connect", "--country", "DE", "--ip-type", "hosting"}, cfg, runner),
		1,
		"",
		"mystvpn connect: HTTP status 403\n",
	)
	if len(runner.actions) != 0 {
		t.Errorf("tunnel actions after failed connect = %v, want none", runner.actions)
	}
	store, err := state.NewDefaultStore()
	if err != nil {
		t.Fatalf("state.NewDefaultStore() error = %v", err)
	}
	if _, err := store.Load(); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("session Load() error = %v, want no session after failed connect", err)
	}

	server.SetConnectStatus(0)
	assertCommandResult(
		t,
		executeCLI([]string{"connect", "--country", "DE", "--ip-type", "hosting"}, cfg, runner),
		0,
		"exit_ip: 1.2.3.4\ncountry: DE\ncity: berlin\n",
		"",
	)
	session := loadEndToEndSession(t)

	server.SetConnectStatus(http.StatusForbidden)
	assertCommandResult(
		t,
		executeCLI([]string{"connect", "--country", "CA", "--ip-type", "residential"}, cfg, runner),
		1,
		"",
		"mystvpn connect: HTTP status 403\n",
	)
	if got := loadEndToEndSession(t); got.SessionID != session.SessionID || got.ConfigPath != session.ConfigPath {
		t.Error("failed replacement connect changed the active session")
	}
	if got, want := strings.Join(runner.actions, ","), "up"; got != want {
		t.Errorf("tunnel actions = %q, want %q", got, want)
	}
	if got := len(server.Snapshot().DisconnectRequests); got != 0 {
		t.Errorf("disconnect requests = %d, want zero", got)
	}

	assertCommandResult(t, executeCLI([]string{"refresh"}, cfg, runner), 1, "", "mystvpn refresh: HTTP status 403\n")
	if got := loadEndToEndSession(t); got.SessionID != session.SessionID || got.ConfigPath != session.ConfigPath {
		t.Error("failed refresh changed the active session")
	}
	if got, want := strings.Join(runner.actions, ","), "up"; got != want {
		t.Errorf("tunnel actions = %q, want %q", got, want)
	}

	server.SetConnectStatus(0)
	server.SetDisconnectStatus(http.StatusForbidden)
	assertCommandResult(t, executeCLI([]string{"disconnect"}, cfg, runner), 1, "", "mystvpn disconnect: HTTP status 403\n")
	_ = loadEndToEndSession(t)
	if _, err := os.Stat(session.ConfigPath); err != nil {
		t.Errorf("config Stat() error = %v, want preserved after failed disconnect", err)
	}
}

type commandResult struct {
	exitCode int
	stdout   string
	stderr   string
}

func executeCLI(args []string, cfg config.Config, runner wireguard.TunnelRunner) commandResult {
	var stdout, stderr bytes.Buffer
	exitCode := runWithDependencies(args, nil, &stdout, &stderr, cfg, runner)
	return commandResult{exitCode: exitCode, stdout: stdout.String(), stderr: stderr.String()}
}

func assertCommandResult(t *testing.T, got commandResult, wantExit int, wantStdout, wantStderr string) {
	t.Helper()
	if got.exitCode != wantExit || got.stdout != wantStdout || got.stderr != wantStderr {
		t.Errorf(
			"command result = exit %d, stdout %q, stderr %q; want exit %d, stdout %q, stderr %q",
			got.exitCode,
			got.stdout,
			got.stderr,
			wantExit,
			wantStdout,
			wantStderr,
		)
	}
}

func loadEndToEndSession(t *testing.T) state.Session {
	t.Helper()
	store, err := state.NewDefaultStore()
	if err != nil {
		t.Fatalf("state.NewDefaultStore() error = %v", err)
	}
	session, err := store.Load()
	if err != nil {
		t.Fatalf("session Load() error = %v", err)
	}
	return session
}

func testConfigDirectory(t *testing.T) string {
	t.Helper()
	directory, err := os.UserConfigDir()
	if err != nil {
		t.Fatalf("os.UserConfigDir() error = %v", err)
	}
	return directory
}

func assertFileMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(%q) error = %v", path, err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Errorf("permissions for %q = %o, want %o", path, got, want)
	}
}

type endToEndTunnelRunner struct {
	actions []string
}

func (r *endToEndTunnelRunner) Up(_ context.Context, configPath string) error {
	r.actions = append(r.actions, "up")
	info, err := os.Stat(configPath)
	if err != nil {
		return fmt.Errorf("inspect config: %w", err)
	}
	if info.Mode().Perm() != 0o600 {
		return fmt.Errorf("config permissions are %o", info.Mode().Perm())
	}
	config, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}
	if strings.Contains(string(config), "%private_key%") || !strings.Contains(string(config), "PrivateKey=") {
		return errors.New("config private-key substitution failed")
	}
	return nil
}

func (r *endToEndTunnelRunner) Down(_ context.Context, configPath string) error {
	r.actions = append(r.actions, "down")
	if _, err := os.Stat(configPath); err != nil {
		return fmt.Errorf("inspect config: %w", err)
	}
	return nil
}
