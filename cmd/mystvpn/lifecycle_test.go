package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mysteriumnetwork/mysteriumvpncli/internal/auth"
	"github.com/mysteriumnetwork/mysteriumvpncli/internal/config"
	"github.com/mysteriumnetwork/mysteriumvpncli/internal/proxy"
	"github.com/mysteriumnetwork/mysteriumvpncli/internal/state"
	"github.com/mysteriumnetwork/mysteriumvpncli/internal/wireguard"
)

func TestRunRefresh(t *testing.T) {
	configureTestHome(t)
	saveTestAuthToken(t)
	original := saveTestSession(t)

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/api/v1/connection/connect" {
			t.Errorf("request = %s %s, want connect endpoint", request.Method, request.URL.Path)
		}
		if got := request.Header.Get("Authorization"); got != "Bearer auth-value" {
			t.Errorf("Authorization = %q, want stored token", got)
		}
		var body proxy.ConnectRequest
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if body.PublicKey != original.PublicKey || body.Country != original.Country || string(body.IPType) != original.IPType || body.OSType != proxy.OSTypeLinux || !body.ResetConnection {
			t.Errorf("request body = %+v, want saved session context", body)
		}
		_, _ = writer.Write([]byte(`{
			"id":"conn-refreshed",
			"wg_config":"[Interface]\nPrivateKey=%private_key%\nAddress=10.20.0.2/24\n",
			"exit_ip":"2.3.4.5",
			"ip_type":"residential",
			"country":"DE",
			"city":"hamburg"
		}`))
	}))
	defer server.Close()

	runner := &recordingTunnelRunner{}
	runner.down = func(path string) error {
		if path != original.ConfigPath {
			t.Errorf("down path = %q, want saved config path", path)
		}
		return nil
	}
	runner.up = func(path string) error {
		if path != original.ConfigPath {
			t.Errorf("up path = %q, want saved config path", path)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if !strings.Contains(string(data), "Address=10.20.0.2/24") || strings.Contains(string(data), "%private_key%") {
			t.Errorf("refreshed config = %q", data)
		}
		return nil
	}

	cfg := config.Load()
	cfg.APIURL = server.URL + "/api/v1"
	var stdout, stderr bytes.Buffer
	exitCode := runRefresh(nil, cfg, &stdout, &stderr, runner)

	if exitCode != 0 {
		t.Fatalf("runRefresh() exit code = %d, want 0; stderr = %q", exitCode, stderr.String())
	}
	if got, want := stdout.String(), "exit_ip: 2.3.4.5\ncountry: DE\ncity: hamburg\n"; got != want {
		t.Errorf("stdout = %q, want %q", got, want)
	}
	if got, want := strings.Join(runner.actions, ","), "down,up"; got != want {
		t.Errorf("tunnel actions = %q, want %q", got, want)
	}

	updated := loadTestSession(t)
	if updated.SessionID != "conn-refreshed" || updated.ExitIP != "2.3.4.5" || updated.City != "hamburg" {
		t.Errorf("updated session = %+v", updated)
	}
	if updated.PublicKey != original.PublicKey || updated.PrivateKey != original.PrivateKey || updated.ConfigPath != original.ConfigPath {
		t.Error("refresh did not preserve keys and config path")
	}
	if !updated.Timestamp.After(original.Timestamp) {
		t.Errorf("updated timestamp = %v, want after %v", updated.Timestamp, original.Timestamp)
	}
	if strings.Contains(stdout.String(), updated.SessionID) || strings.Contains(stdout.String(), updated.PrivateKey) {
		t.Error("refresh output contains secret or session ID")
	}
}

func TestRunStatus(t *testing.T) {
	t.Run("not connected", func(t *testing.T) {
		configureTestHome(t)
		var stdout, stderr bytes.Buffer

		exitCode := runStatus(nil, &stdout, &stderr)

		if exitCode != 0 || stdout.String() != "connected: no\n" || stderr.Len() != 0 {
			t.Errorf("exit=%d stdout=%q stderr=%q", exitCode, stdout.String(), stderr.String())
		}
	})

	t.Run("connected", func(t *testing.T) {
		configureTestHome(t)
		session := saveTestSession(t)
		var stdout, stderr bytes.Buffer

		exitCode := runStatus(nil, &stdout, &stderr)

		want := "connected: yes\nIP address: 1.2.3.4\ncountry: DE\ncity: berlin\n"
		if exitCode != 0 || stdout.String() != want || stderr.Len() != 0 {
			t.Errorf("exit=%d stdout=%q stderr=%q", exitCode, stdout.String(), stderr.String())
		}
		if strings.Contains(stdout.String(), session.SessionID) || strings.Contains(stdout.String(), session.PrivateKey) {
			t.Error("status output contains secret or session ID")
		}
	})
}

func TestRunDisconnect(t *testing.T) {
	configureTestHome(t)
	saveTestAuthToken(t)
	session := saveTestSession(t)

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/api/v1/connection/disconnect" {
			t.Errorf("request = %s %s, want disconnect endpoint", request.Method, request.URL.Path)
		}
		if got := request.Header.Get("Authorization"); got != "Bearer auth-value" {
			t.Errorf("Authorization = %q, want stored token", got)
		}
		var body proxy.DisconnectRequest
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if body.PublicKey != session.PublicKey {
			t.Errorf("public key = %q, want saved public key", body.PublicKey)
		}
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	runner := &recordingTunnelRunner{}
	cfg := config.Load()
	cfg.APIURL = server.URL + "/api/v1"
	var stdout, stderr bytes.Buffer
	exitCode := runDisconnect(nil, cfg, &stdout, &stderr, runner)

	if exitCode != 0 {
		t.Fatalf("runDisconnect() exit code = %d, want 0; stderr = %q", exitCode, stderr.String())
	}
	if stdout.String() != "Disconnected successfully\n" {
		t.Errorf("stdout = %q", stdout.String())
	}
	if got := strings.Join(runner.actions, ","); got != "down" {
		t.Errorf("tunnel actions = %q, want down", got)
	}
	if _, err := os.Stat(session.ConfigPath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("config Stat() error = %v, want not exist", err)
	}
	store, err := state.NewDefaultStore()
	if err != nil {
		t.Fatalf("state.NewDefaultStore() error = %v", err)
	}
	if _, err := store.Load(); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("session Load() error = %v, want not exist", err)
	}
}

func TestLifecycleCommandsWithoutSession(t *testing.T) {
	for _, command := range []string{"refresh", "disconnect"} {
		t.Run(command, func(t *testing.T) {
			configureTestHome(t)
			var stdout, stderr bytes.Buffer
			var exitCode int
			if command == "refresh" {
				exitCode = runRefresh(nil, config.Load(), &stdout, &stderr, &recordingTunnelRunner{})
			} else {
				exitCode = runDisconnect(nil, config.Load(), &stdout, &stderr, &recordingTunnelRunner{})
			}
			if exitCode == 0 || stderr.String() != "no active session\n" {
				t.Errorf("exit=%d stderr=%q", exitCode, stderr.String())
			}
		})
	}
}

func TestDisconnectHTTPFailurePreservesLocalSession(t *testing.T) {
	configureTestHome(t)
	saveTestAuthToken(t)
	session := saveTestSession(t)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	cfg := config.Load()
	cfg.APIURL = server.URL
	runner := &recordingTunnelRunner{}
	var stdout, stderr bytes.Buffer
	exitCode := runDisconnect(nil, cfg, &stdout, &stderr, runner)

	if exitCode != 1 || stderr.String() != "mystvpn disconnect: HTTP status 403\n" {
		t.Errorf("exit=%d stderr=%q", exitCode, stderr.String())
	}
	if len(runner.actions) != 0 {
		t.Errorf("tunnel actions = %v, want none", runner.actions)
	}
	if _, err := os.Stat(session.ConfigPath); err != nil {
		t.Errorf("config Stat() error = %v, want preserved", err)
	}
	_ = loadTestSession(t)
}

func TestLifecycleCommandsRejectArguments(t *testing.T) {
	configureTestHome(t)
	for _, command := range []string{"refresh", "status", "disconnect"} {
		t.Run(command, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			var exitCode int
			switch command {
			case "refresh":
				exitCode = runRefresh([]string{"extra"}, config.Load(), &stdout, &stderr, &recordingTunnelRunner{})
			case "status":
				exitCode = runStatus([]string{"extra"}, &stdout, &stderr)
			case "disconnect":
				exitCode = runDisconnect([]string{"extra"}, config.Load(), &stdout, &stderr, &recordingTunnelRunner{})
			}
			if exitCode != 2 || !strings.Contains(stderr.String(), "unexpected argument") {
				t.Errorf("exit=%d stderr=%q", exitCode, stderr.String())
			}
		})
	}
}

func saveTestAuthToken(t *testing.T) {
	t.Helper()
	store, err := auth.NewDefaultFileStore()
	if err != nil {
		t.Fatalf("auth.NewDefaultFileStore() error = %v", err)
	}
	if err := store.SaveAccessToken("auth-value"); err != nil {
		t.Fatalf("SaveAccessToken() error = %v", err)
	}
}

func saveTestSession(t *testing.T) state.Session {
	t.Helper()
	directory, err := wireguard.DefaultConfigDirectory()
	if err != nil {
		t.Fatalf("wireguard.DefaultConfigDirectory() error = %v", err)
	}
	configPath, err := wireguard.WriteConfig(directory, "[Interface]\nPrivateKey=%private_key%\nAddress=10.10.0.2/24\n", "private-value")
	if err != nil {
		t.Fatalf("wireguard.WriteConfig() error = %v", err)
	}
	session := state.Session{
		SessionID:  "conn-original",
		PublicKey:  "public-value",
		PrivateKey: "private-value",
		Country:    "DE",
		IPType:     "residential",
		ExitIP:     "1.2.3.4",
		City:       "berlin",
		ConfigPath: configPath,
		Timestamp:  time.Now().Add(-time.Hour).UTC(),
	}
	store, err := state.NewDefaultStore()
	if err != nil {
		t.Fatalf("state.NewDefaultStore() error = %v", err)
	}
	if err := store.Save(session); err != nil {
		t.Fatalf("session Save() error = %v", err)
	}
	return session
}

func loadTestSession(t *testing.T) state.Session {
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

type recordingTunnelRunner struct {
	actions []string
	up      func(string) error
	down    func(string) error
}

func (r *recordingTunnelRunner) Up(_ context.Context, path string) error {
	r.actions = append(r.actions, "up")
	if r.up != nil {
		return r.up(path)
	}
	return nil
}

func (r *recordingTunnelRunner) Down(_ context.Context, path string) error {
	r.actions = append(r.actions, "down")
	if r.down != nil {
		return r.down(path)
	}
	return nil
}
