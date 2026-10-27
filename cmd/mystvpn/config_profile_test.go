package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/mysteriumnetwork/mysteriumvpncli/internal/config"
	"github.com/mysteriumnetwork/mysteriumvpncli/internal/mockserver"
)

func TestCLIProfilesReadWrite(t *testing.T) {
	configureTestHome(t)
	cfg := config.Load()
	execute := func(args ...string) commandResult { return executeCLI(args, cfg, nil) }
	assertCommandResult(t, execute("config", "profile"), 0, "* default\n", "")
	assertCommandResult(t, execute("config", "profile", "current"), 0, "default\n", "")
	assertCommandResult(t, execute("config", "effective"), 0, "{\n  \"country\": \"DE\",\n  \"ip_type\": \"residential\"\n}\n", "")
	path := filepath.Join(testConfigDirectory(t), "mystvpn", "config.json")
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("reading implicit default profile created a config file")
	}
	assertCommandResult(t, execute("config", "set", "country", "DE"), 0, "", "")
	assertCommandResult(t, execute("config", "profile", "create", "us-1"), 0, "", "")
	assertCommandResult(t, execute("config", "--profile", "us-1", "set", "country", "US"), 0, "", "")
	assertCommandResult(t, execute("config", "--profile", "us-1", "set", "ip_type", "hosting"), 0, "", "")
	assertCommandResult(t, execute("config", "profile", "current"), 0, "default\n", "")
	assertCommandResult(t, execute("config", "profile", "list"), 0, "* default\n  us-1\n", "")
	assertCommandResult(t, execute("config", "profile", "use", "us-1"), 0, "Active profile: us-1\n", "")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var saved map[string]json.RawMessage
	if err := json.Unmarshal(data, &saved); err != nil || string(saved["active_profile"]) != `"us-1"` {
		t.Fatalf("selection was not persisted in config JSON: %s, %v", data, err)
	}
	assertCommandResult(t, execute("config", "profile", "current"), 0, "us-1\n", "")
	assertCommandResult(t, execute("config", "profile", "list"), 0, "  default\n* us-1\n", "")
	assertCommandResult(t, execute("config", "get", "country"), 0, "US\n", "")
	assertCommandResult(t, execute("config", "--profile", "default", "get", "country"), 0, "DE\n", "")
	assertCommandResult(t, execute("config", "profile", "use", "default"), 0, "Active profile: default\n", "")
	assertCommandResult(t, execute("config", "profile", "delete", "us-1"), 0, "", "")
	assertCommandResult(t, execute("config", "profile"), 0, "* default\n", "")
	assertFileMode(t, path, 0o600)
}

func TestCLIProfilesRejectInvalidOperationsWithoutWriting(t *testing.T) {
	configureTestHome(t)
	store, err := config.NewDefaultStore()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveDocument(config.DefaultDocument()); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(store.Path())
	if err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"profile", "list"},
		{"config", "profile", "create"}, {"config", "profile", "create", "bad name"},
		{"config", "profile", "create", "default"}, {"config", "profile", "use", "missing"},
		{"config", "profile", "delete", "default"}, {"config", "profile", "delete", "missing"},
		{"config", "profile", "current", "extra"}, {"config", "profile", "list", "extra"}, {"config", "profile", "unknown"},
		{"config", "--profile", "missing", "set", "country", "US"},
		{"config", "--profile", "missing", "get"},
		{"config", "--profile"},
		{"config", "--profile", "default", "profile", "use", "default"},
		{"connect", "--profile", "missing", "--country", "DE", "--ip-type", "hosting"},
	} {
		result := executeCLI(args, config.Load(), nil)
		if result.exitCode != 2 || result.stderr == "" {
			t.Errorf("%v = %+v, want argument error", args, result)
		}
		after, err := os.ReadFile(store.Path())
		if err != nil || !bytes.Equal(before, after) {
			t.Fatalf("%v changed the file: %s, %v", args, after, err)
		}
	}
}

func TestCLIConnectUsesBuiltInDefaultsWithoutConfig(t *testing.T) {
	configureTestHome(t)
	server := mockserver.New()
	defer server.Close()
	cfg := config.Load()
	cfg.APIURL = server.APIURL()
	runner := &endToEndTunnelRunner{}
	assertAuthCommandSuccess(t, executeCLI([]string{"auth"}, cfg, runner))
	assertCommandResult(t, executeCLI([]string{"connect"}, cfg, runner), 0, "exit_ip: 1.2.3.4\ncountry: DE\ncity: berlin\n", "")
	requests := server.Snapshot().ConnectRequests
	if len(requests) != 1 || requests[0].Country != "DE" || requests[0].IPType != "residential" {
		t.Fatalf("requests = %+v, want built-in DE/residential defaults", requests)
	}
	path := filepath.Join(testConfigDirectory(t), "mystvpn", "config.json")
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("connect materialized built-in defaults in config.json")
	}
}

func TestCLIProfileSwitchingAppliesToConnectAndRefresh(t *testing.T) {
	configureTestHome(t)
	server := mockserver.New()
	defer server.Close()
	cfg := config.Load()
	cfg.APIURL = server.APIURL()
	runner := &endToEndTunnelRunner{}
	execute := func(args ...string) commandResult { return executeCLI(args, cfg, runner) }
	assertCommandResult(t, execute("config", "set", "country", "DE"), 0, "", "")
	assertCommandResult(t, execute("config", "set", "ip_type", "residential"), 0, "", "")
	assertCommandResult(t, execute("config", "profile", "create", "us-1"), 0, "", "")
	assertCommandResult(t, execute("config", "--profile", "us-1", "set", "country", "US"), 0, "", "")
	assertCommandResult(t, execute("config", "--profile", "us-1", "set", "ip_type", "hosting"), 0, "", "")
	assertAuthCommandSuccess(t, execute("auth"))
	assertCommandResult(t, execute("connect"), 0, "exit_ip: 1.2.3.4\ncountry: DE\ncity: berlin\n", "")
	original := loadEndToEndSession(t)

	assertCommandResult(t, execute("config", "profile", "use", "us-1"), 0, "Active profile: us-1\n", "")
	if len(server.Snapshot().ConnectRequests) != 1 || strings.Join(runner.actions, ",") != "up" {
		t.Fatal("profile selection changed the running VPN")
	}
	assertCommandResult(t, execute("refresh"), 0, "exit_ip: 2.3.4.5\ncountry: US\ncity: hamburg\n", "")
	updated := loadEndToEndSession(t)
	if updated.Country != "US" || updated.IPType != "hosting" || updated.PublicKey != original.PublicKey || updated.PrivateKey != original.PrivateKey || updated.ConfigPath != original.ConfigPath {
		t.Fatal("refresh did not apply profile while preserving the tunnel keys and path")
	}

	// A one-connection profile and targeting flag do not change selection or presets.
	result := execute("connect", "--profile", "default", "--country", "CA")
	if result.exitCode != 0 || result.stderr != "" {
		t.Fatalf("one-off profile connect: %+v", result)
	}
	assertCommandResult(t, execute("config", "profile", "current"), 0, "us-1\n", "")
	assertCommandResult(t, execute("config", "--profile", "default", "get", "country"), 0, "DE\n", "")
	if result := execute("refresh"); result.exitCode != 0 || result.stderr != "" {
		t.Fatalf("refresh after one-off override: %+v", result)
	}
	requests := server.Snapshot().ConnectRequests
	want := [][2]string{{"DE", "residential"}, {"US", "hosting"}, {"CA", "residential"}, {"US", "hosting"}}
	if len(requests) != len(want) {
		t.Fatalf("requests = %v, want %v", requests, want)
	}
	for i, request := range requests {
		if request.Country != want[i][0] || string(request.IPType) != want[i][1] {
			t.Errorf("request %d = %+v, want %v", i, request, want[i])
		}
	}
	assertCommandResult(t, execute("logout"), 0, "Logout successful.\n", "")
	assertCommandResult(t, execute("config", "profile", "current"), 0, "us-1\n", "")
}

func TestCLIProfileRefreshFailurePreservesRunningSession(t *testing.T) {
	configureTestHome(t)
	server := mockserver.New()
	defer server.Close()
	cfg := config.Load()
	cfg.APIURL = server.APIURL()
	runner := &endToEndTunnelRunner{}
	execute := func(args ...string) commandResult { return executeCLI(args, cfg, runner) }
	assertAuthCommandSuccess(t, execute("auth"))
	assertCommandResult(t, execute("connect", "--country", "DE", "--ip-type", "residential"), 0, "exit_ip: 1.2.3.4\ncountry: DE\ncity: berlin\n", "")
	original := loadEndToEndSession(t)
	assertCommandResult(t, execute("config", "profile", "create", "us-1"), 0, "", "")
	assertCommandResult(t, execute("config", "profile", "use", "us-1"), 0, "Active profile: us-1\n", "")
	assertCommandResult(t, execute("config", "set", "country", "US"), 0, "", "")
	assertCommandResult(t, execute("config", "set", "ip_type", "hosting"), 0, "", "")
	server.SetConnectStatus(http.StatusForbidden)
	assertCommandResult(t, execute("refresh"), 1, "", "mystvpn refresh: HTTP status 403\n")
	if got := loadEndToEndSession(t); !reflect.DeepEqual(got, original) {
		t.Fatal("failed profile refresh modified the saved session")
	}
	if strings.Join(runner.actions, ",") != "up" {
		t.Fatal("failed profile refresh tore down the tunnel")
	}
	assertCommandResult(t, execute("config", "profile", "current"), 0, "us-1\n", "")
}
