package main

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/mysteriumnetwork/mysteriumvpncli/internal/config"
	"github.com/mysteriumnetwork/mysteriumvpncli/internal/mockserver"
)

func TestCLIConfigReadWrite(t *testing.T) {
	configureTestHome(t)
	cfg := config.Load()
	execute := func(args ...string) commandResult {
		return executeCLI(append([]string{"config"}, args...), cfg, nil)
	}
	path := filepath.Join(testConfigDirectory(t), "mystvpn", "config.json")
	assertCommandResult(t, execute(), 0, "{}\n", "")
	assertCommandResult(t, execute("path"), 0, path+"\n", "")
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("reading config created a file: %v", err)
	}
	assertCommandResult(t, execute("get", "country"), 0, "DE\n", "")
	assertCommandResult(t, execute("set", "country", " de "), 0, "[SUCCESS] Saved country for profile \"default\". Changes apply on the next connect or refresh.\n", "")
	assertCommandResult(t, execute("set", "ip_type", "residential"), 0, "[SUCCESS] Saved ip_type for profile \"default\". Changes apply on the next connect or refresh.\n", "")
	assertCommandResult(t, execute("get", "country"), 0, "DE\n", "")
	assertCommandResult(t, execute("get", "ip_type"), 0, "residential\n", "")
	assertCommandResult(t, execute("get"), 0, "{\n  \"country\": \"DE\",\n  \"ip_type\": \"residential\"\n}\n", "")
	assertCommandResult(t, execute("unset", "country"), 0, "[SUCCESS] Reset country to its built-in default for profile \"default\". Changes apply on the next connect or refresh.\n", "")
	assertCommandResult(t, execute("get", "country"), 0, "DE\n", "")
	assertCommandResult(t, execute(), 0, "{\n  \"ip_type\": \"residential\"\n}\n", "")
	assertCommandResult(t, execute("unset", "ip_type"), 0, "[SUCCESS] Reset ip_type to its built-in default for profile \"default\". Changes apply on the next connect or refresh.\n", "")
	assertCommandResult(t, execute("get", "ip_type"), 0, "residential\n", "")
	assertCommandResult(t, execute("unset", "ip_type"), 0, "[SUCCESS] Reset ip_type to its built-in default for profile \"default\". Changes apply on the next connect or refresh.\n", "")
	assertCommandResult(t, execute(), 0, "{}\n", "")
	assertFileMode(t, path, 0o600)
	assertFileMode(t, filepath.Dir(path), 0o700)
}

func TestCLIConfigRejectsInvalidUpdates(t *testing.T) {
	configureTestHome(t)
	store, err := config.NewDefaultStore()
	if err != nil {
		t.Fatal(err)
	}
	want := config.Settings{Country: "DE", IPType: "hosting"}
	document := config.DefaultDocument()
	if err := document.Set("", "ip_type", "hosting"); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveDocument(document); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"set"}, {"set", "country"}, {"set", "country", "DE", "extra"},
		{"set", "country", "Germany"}, {"set", "country", ""}, {"set", "country", "df"},
		{"set", "ip_type", "mobile"}, {"set", "ip_type", ""},
		{"set", "unknown", "value"}, {"get", "unknown"}, {"unset", "unknown"},
		{"get", "country", "extra"}, {"unset"}, {"unset", "country", "extra"},
		{"path", "extra"}, {"unknown"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			result := executeCLI(append([]string{"config"}, args...), config.Load(), nil)
			if result.exitCode != 2 || result.stderr == "" || result.stdout != "" {
				t.Errorf("invalid command result = %+v", result)
			}
			if got, err := store.Load(); err != nil || !reflect.DeepEqual(got, want) {
				t.Errorf("config changed: %+v, %v", got, err)
			}
		})
	}
}

func TestCLIBrokenConfig(t *testing.T) {
	configureTestHome(t)
	store, err := config.NewDefaultStore()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveDocument(config.DefaultDocument()); err != nil {
		t.Fatal(err)
	}
	broken := []byte(`{"country":`)
	if err := os.WriteFile(store.Path(), broken, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"config"}, {"config", "set", "country", "DE"}, {"connect", "--country", "DE", "--ip-type", "hosting"}} {
		result := executeCLI(args, config.Load(), nil)
		if result.exitCode != 1 || !strings.Contains(result.stderr, "decode config") || !strings.Contains(result.stderr, store.Path()) {
			t.Errorf("%v result = %+v, want config error with path", args, result)
		}
	}
	if data, err := os.ReadFile(store.Path()); err != nil || !bytes.Equal(data, broken) {
		t.Errorf("broken config overwritten: %q, %v", data, err)
	}
	assertCommandResult(t, executeCLI([]string{"config", "path"}, config.Load(), nil), 0, store.Path()+"\n", "")
	assertCommandResult(t, executeCLI([]string{"status"}, config.Load(), nil), 0, "connected: no\n", "")
	assertCommandResult(t, executeCLI([]string{"disconnect"}, config.Load(), nil), 1, "", "[ERROR] mystvpn disconnect: no active session; run \"mystvpn connect\" first\n")
	for _, command := range []string{"help", "version"} {
		if result := executeCLI([]string{command}, config.Load(), nil); result.exitCode != 0 {
			t.Errorf("%s failed with broken config: %+v", command, result)
		}
	}
}

func TestCLIConnectDefaultsAndOverrides(t *testing.T) {
	tests := []struct {
		name     string
		settings config.Settings
		args     []string
		country  string
		ipType   string
		wantErr  string
	}{
		{name: "all saved", settings: config.Settings{Country: "DE", IPType: "residential"}, country: "DE", ipType: "residential"},
		{name: "country override", settings: config.Settings{Country: "DE", IPType: "residential"}, args: []string{"--country", "ca"}, country: "CA", ipType: "residential"},
		{name: "ip type override", settings: config.Settings{Country: "DE", IPType: "residential"}, args: []string{"--ip-type", "hosting"}, country: "DE", ipType: "hosting"},
		{name: "both override", settings: config.Settings{Country: "DE", IPType: "residential"}, args: []string{"--country", "CA", "--ip-type", "hosting"}, country: "CA", ipType: "hosting"},
		{name: "partial file", settings: config.Settings{Country: "DE"}, args: []string{"--ip-type", "hosting"}, country: "DE", ipType: "hosting"},
		{name: "inherited country", settings: config.Settings{IPType: "hosting"}, country: "DE", ipType: "hosting"},
		{name: "inherited ip type", settings: config.Settings{Country: "US"}, country: "US", ipType: "residential"},
		{name: "explicit empty country", settings: config.Settings{Country: "DE", IPType: "hosting"}, args: []string{"--country="}, wantErr: "--country is required"},
		{name: "explicit empty ip type", settings: config.Settings{Country: "DE", IPType: "hosting"}, args: []string{"--ip-type="}, wantErr: "--ip-type is required"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			configureTestHome(t)
			store, err := config.NewDefaultStore()
			if err != nil {
				t.Fatal(err)
			}
			document := config.DefaultDocument()
			if test.settings.Country != "" {
				if err := document.Set("", "country", test.settings.Country); err != nil {
					t.Fatal(err)
				}
			}
			if test.settings.IPType != "" {
				if err := document.Set("", "ip_type", test.settings.IPType); err != nil {
					t.Fatal(err)
				}
			}
			if err := store.SaveDocument(document); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(store.Path())
			if err != nil {
				t.Fatal(err)
			}
			server := mockserver.New()
			defer server.Close()
			cfg := config.Load()
			cfg.APIURL = server.APIURL()
			runner := &endToEndTunnelRunner{}
			assertAuthCommandSuccess(t, executeCLI([]string{"auth"}, cfg, runner))
			result := executeCLI(append([]string{"connect"}, test.args...), cfg, runner)
			requests := server.Snapshot().ConnectRequests
			if test.wantErr != "" {
				if result.exitCode != 2 || !strings.Contains(result.stderr, test.wantErr) || len(requests) != 0 || len(runner.actions) != 0 {
					t.Fatalf("result = %+v, requests = %+v, actions = %v; want validation failure", result, requests, runner.actions)
				}
				return
			}
			if result.exitCode != 0 || result.stderr != "" || len(requests) != 1 {
				t.Fatalf("result = %+v, requests = %+v; want successful connect", result, requests)
			}
			if requests[0].Country != test.country || string(requests[0].IPType) != test.ipType {
				t.Errorf("request = %+v, want %s/%s", requests[0], test.country, test.ipType)
			}
			if after, err := os.ReadFile(store.Path()); err != nil || !bytes.Equal(before, after) {
				t.Errorf("connect modified saved overrides: %s, %v", after, err)
			}
		})
	}
}

func TestCLIConfigDefaultsLifecycle(t *testing.T) {
	configureTestHome(t)
	server := mockserver.New()
	defer server.Close()
	cfg := config.Load()
	cfg.APIURL = server.APIURL()
	runner := &endToEndTunnelRunner{}
	execute := func(args ...string) commandResult { return executeCLI(args, cfg, runner) }

	assertCommandResult(t, execute("config", "set", "country", "DE"), 0, "[SUCCESS] Saved country for profile \"default\". Changes apply on the next connect or refresh.\n", "")
	assertCommandResult(t, execute("config", "set", "ip_type", "residential"), 0, "[SUCCESS] Saved ip_type for profile \"default\". Changes apply on the next connect or refresh.\n", "")
	assertAuthCommandSuccess(t, execute("auth"))
	assertCommandResult(t, execute("connect"), 0, "[SUCCESS] Connected to VPN.\nexit_ip: 1.2.3.4\ncountry: DE\ncity: berlin\n", "")

	// Both refresh and connect apply the selected profile's current overrides.
	assertCommandResult(t, execute("config", "set", "country", "CA"), 0, "[SUCCESS] Saved country for profile \"default\". Changes apply on the next connect or refresh.\n", "")
	assertCommandResult(t, execute("config", "set", "ip_type", "hosting"), 0, "[SUCCESS] Saved ip_type for profile \"default\". Changes apply on the next connect or refresh.\n", "")
	assertCommandResult(t, execute("refresh"), 0, "[SUCCESS] VPN connection refreshed.\nexit_ip: 2.3.4.5\ncountry: CA\ncity: hamburg\n", "")
	assertCommandResult(t, execute("disconnect"), 0, "[SUCCESS] Disconnected successfully.\n", "")
	result := execute("connect")
	if result.exitCode != 0 || result.stderr != "" {
		t.Fatalf("connect with updated defaults failed: %+v", result)
	}
	requests := server.Snapshot().ConnectRequests
	if len(requests) != 3 {
		t.Fatalf("requests = %+v, want three connections", requests)
	}
	for index, request := range requests {
		country, ipType := "DE", "residential"
		if index >= 1 {
			country, ipType = "CA", "hosting"
		}
		if request.Country != country || string(request.IPType) != ipType {
			t.Errorf("request %d = %+v, want %s/%s", index, request, country, ipType)
		}
	}
	assertCommandResult(t, execute("logout"), 0, "[SUCCESS] Logout successful.\n", "")
	assertCommandResult(t, execute("config", "get", "country"), 0, "CA\n", "")
	assertCommandResult(t, execute("config", "get", "ip_type"), 0, "hosting\n", "")
}
