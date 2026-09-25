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

	"github.com/mysteriumnetwork/mysteriumvpncli/internal/auth"
	"github.com/mysteriumnetwork/mysteriumvpncli/internal/client"
	"github.com/mysteriumnetwork/mysteriumvpncli/internal/config"
	"github.com/mysteriumnetwork/mysteriumvpncli/internal/proxy"
	"github.com/mysteriumnetwork/mysteriumvpncli/internal/state"
)

func TestRunConnect(t *testing.T) {
	configureTestHome(t)
	tokenStore := defaultTestStore(t)
	if err := tokenStore.SaveAccessToken("auth-value"); err != nil {
		t.Fatalf("SaveAccessToken() error = %v", err)
	}

	var requestedPublicKey string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", request.Method)
		}
		if request.URL.Path != "/api/v1/connection/connect" {
			t.Errorf("path = %q, want connect endpoint", request.URL.Path)
		}
		if got := request.Header.Get("Authorization"); got != "Bearer auth-value" {
			t.Errorf("Authorization = %q, want stored token", got)
		}

		var body proxy.ConnectRequest
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		requestedPublicKey = body.PublicKey
		if body.Country != "DE" || body.IPType != proxy.IPTypeResidential || body.OSType != proxy.OSTypeLinux || !body.ResetConnection {
			t.Errorf("request body = %+v, want normalized connect parameters", body)
		}

		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{
			"id":"conn-abc123",
			"wg_config":"[Interface]\nPrivateKey=%private_key%\nAddress=10.10.0.2/24\n\n[Peer]\nPublicKey=peer-value\nEndpoint=1.2.3.4:51820\nAllowedIPs=0.0.0.0/0\n",
			"exit_ip":"1.2.3.4",
			"ip_type":"residential",
			"country":"DE",
			"city":"berlin"
		}`))
	}))
	defer server.Close()

	var configPath string
	runner := tunnelRunnerFunc(func(_ context.Context, path string) error {
		configPath = path
		info, err := os.Stat(path)
		if err != nil {
			return err
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Errorf("config permissions = %o, want 600", got)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(data), "%private_key%") {
			t.Error("config contains private-key placeholder")
		}
		return nil
	})

	cfg := config.Load()
	cfg.APIURL = server.URL + "/api/v1"
	var stdout, stderr bytes.Buffer
	exitCode := runConnect(
		[]string{"--country", "de", "--ip-type", "residential"},
		cfg,
		&stdout,
		&stderr,
		runner,
	)

	if exitCode != 0 {
		t.Fatalf("runConnect() exit code = %d, want 0; stderr = %q", exitCode, stderr.String())
	}
	wantOutput := "exit_ip: 1.2.3.4\ncountry: DE\ncity: berlin\n"
	if stdout.String() != wantOutput {
		t.Errorf("stdout = %q, want %q", stdout.String(), wantOutput)
	}
	if strings.Contains(stdout.String(), "conn-abc123") {
		t.Error("stdout contains session ID")
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr = %q, want empty", stderr.String())
	}

	sessionStore, err := state.NewDefaultStore()
	if err != nil {
		t.Fatalf("state.NewDefaultStore() error = %v", err)
	}
	session, err := sessionStore.Load()
	if err != nil {
		t.Fatalf("session Load() error = %v", err)
	}
	if session.SessionID != "conn-abc123" || session.PublicKey != requestedPublicKey || session.PrivateKey == "" {
		t.Errorf("session keys or ID are incomplete")
	}
	if session.Country != "DE" || session.IPType != "residential" || session.ExitIP != "1.2.3.4" || session.City != "berlin" {
		t.Errorf("session metadata = %+v, want response metadata", session)
	}
	if session.ConfigPath != configPath || session.Timestamp.IsZero() {
		t.Errorf("session config path or timestamp is incomplete")
	}
	if strings.Contains(stdout.String(), session.PrivateKey) || strings.Contains(stderr.String(), session.PrivateKey) {
		t.Error("private key was printed")
	}
}

func TestRunConnectValidatesFlags(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantText string
	}{
		{name: "missing country", args: []string{"--ip-type", "residential"}, wantText: "--country is required"},
		{name: "invalid country", args: []string{"--country", "Germany", "--ip-type", "residential"}, wantText: "country must be a two-letter code"},
		{name: "missing ip type", args: []string{"--country", "DE"}, wantText: "--ip-type is required"},
		{name: "invalid ip type", args: []string{"--country", "DE", "--ip-type", "mobile"}, wantText: `ip type must be "residential" or "hosting"`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			exitCode := runConnect(test.args, config.Load(), &stdout, &stderr, tunnelRunnerFunc(nil))

			if exitCode != 2 {
				t.Fatalf("runConnect() exit code = %d, want 2", exitCode)
			}
			if !strings.Contains(stderr.String(), test.wantText) {
				t.Errorf("stderr = %q, want %q", stderr.String(), test.wantText)
			}
		})
	}
}

func TestWriteConnectRequestErrorReportsHTTPStatus(t *testing.T) {
	for _, err := range []error{
		&client.APIError{StatusCode: http.StatusForbidden},
		&auth.HTTPStatusError{StatusCode: http.StatusUnauthorized},
	} {
		var output bytes.Buffer

		writeConnectRequestError(&output, err)

		if !strings.Contains(output.String(), "HTTP status") {
			t.Errorf("output = %q, want HTTP status", output.String())
		}
	}
}

func TestRunConnectCleansStateWhenTunnelFails(t *testing.T) {
	configureTestHome(t)
	tokenStore := defaultTestStore(t)
	if err := tokenStore.SaveAccessToken("auth-value"); err != nil {
		t.Fatalf("SaveAccessToken() error = %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte(`{
			"id":"conn-abc123",
			"wg_config":"[Interface]\nPrivateKey=%private_key%\n",
			"exit_ip":"1.2.3.4",
			"ip_type":"hosting",
			"country":"DE",
			"city":"berlin"
		}`))
	}))
	defer server.Close()

	var configPath string
	runner := tunnelRunnerFunc(func(_ context.Context, path string) error {
		configPath = path
		return errors.New("wg-quick up failed")
	})
	cfg := config.Load()
	cfg.APIURL = server.URL
	var stdout, stderr bytes.Buffer

	exitCode := runConnect(
		[]string{"--country", "DE", "--ip-type", "hosting"},
		cfg,
		&stdout,
		&stderr,
		runner,
	)

	if exitCode != 1 {
		t.Fatalf("runConnect() exit code = %d, want 1", exitCode)
	}
	if _, err := os.Stat(configPath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("config Stat() error = %v, want os.ErrNotExist", err)
	}
	sessionStore, err := state.NewDefaultStore()
	if err != nil {
		t.Fatalf("state.NewDefaultStore() error = %v", err)
	}
	if _, err := sessionStore.Load(); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("session Load() error = %v, want os.ErrNotExist", err)
	}
}

type tunnelRunnerFunc func(context.Context, string) error

func (function tunnelRunnerFunc) Up(ctx context.Context, configPath string) error {
	return function(ctx, configPath)
}

func (tunnelRunnerFunc) Down(context.Context, string) error {
	return nil
}
