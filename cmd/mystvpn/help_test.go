package main

import (
	"bytes"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/mysteriumnetwork/mysteriumvpncli/internal/config"
)

func TestHelpForEveryCommandWithoutValidConfig(t *testing.T) {
	configureTestHome(t)
	store := writeTestConfigJSON(t, "invalid JSON")
	before, err := os.ReadFile(store.Path())
	if err != nil {
		t.Fatal(err)
	}
	paths := []string{
		"", "auth", "countries", "cities", "connect", "refresh", "status", "disconnect", "logout", "version", "help",
		"config", "config get", "config effective", "config set", "config unset", "config path",
		"config profile", "config profile list", "config profile current", "config profile create",
		"config profile use", "config profile delete",
	}
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			words := strings.Fields(path)
			var want string
			forms := [][]string{append([]string{"help"}, words...), append(strings.Fields(path), "--help"), append(strings.Fields(path), "-h")}
			for _, args := range forms {
				var stdout, stderr bytes.Buffer
				// A nil tunnel runner also catches accidental execution of VPN commands.
				code := runWithDependencies(args, nil, &stdout, &stderr, config.Load(), nil)
				if code != 0 || stderr.Len() != 0 {
					t.Fatalf("%v: code %d, stderr %q", args, code, stderr.String())
				}
				if !strings.Contains(stdout.String(), "Usage:\n  mystvpn "+path) || !strings.Contains(stdout.String(), "Examples:") {
					t.Fatalf("%v: missing usage or examples: %s", args, stdout.String())
				}
				if want != "" && stdout.String() != want {
					t.Fatalf("%v produced different help:\n%s\nwant:\n%s", args, stdout.String(), want)
				}
				want = stdout.String()
			}
		})
	}
	after, err := os.ReadFile(store.Path())
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("help changed the configuration: %q, %v", after, err)
	}
}

func TestCommandHelpExplainsBehavior(t *testing.T) {
	tests := []struct {
		path string
		want []string
	}{
		{"connect", []string{"--profile <name>", "--country <code>", "--ip-type <type>", "residential or hosting", "case-insensitive", "built-in default: " + config.DefaultSettings().Country, "override the profile", "Requires authentication"}},
		{"cities", []string{"--country <code>", "--ip-type <type>", "city/state", "Requires authentication"}},
		{"countries", []string{"Optional: residential or hosting", "active profile's IP type", "heading shows the IP type", "Requires authentication"}},
		{"config", []string{"get", "effective", "set", "unset", "path", "profile", "saved overrides as JSON", "Place this flag before", "country", "ip_type"}},
		{"config get", []string{"get [key]", "built-in", "--profile"}},
		{"config profile", []string{"list", "current", "create", "use", "delete", "asterisk (*)", "--profile is not supported"}},
		{"config profile create", []string{"create <name>", "without selecting it", "64 characters"}},
		{"status", []string{"without an API request or a live connectivity check", "no saved session"}},
		{"refresh", []string{"Requires an active session", "active profile's current country and IP type"}},
	}
	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			var output bytes.Buffer
			if code := runHelp(strings.Fields(test.path), &output, &output); code != 0 {
				t.Fatal(output.String())
			}
			for _, want := range test.want {
				if !strings.Contains(output.String(), want) {
					t.Errorf("missing %q in help:\n%s", want, output.String())
				}
			}
		})
	}
}

func TestHelpRejectsUnknownTargets(t *testing.T) {
	for _, args := range [][]string{
		{"help", "unknown"}, {"help", "config", "unknown"}, {"help", "connect", "extra"},
		{"config", "profile", "unknown", "--help"}, {"unknown", "--help"},
	} {
		var stdout, stderr bytes.Buffer
		if code := run(args, nil, &stdout, &stderr); code != 2 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "unknown command") {
			t.Errorf("%v: code %d, stdout %q, stderr %q", args, code, stdout.String(), stderr.String())
		}
	}
}

func TestHelpRespectsFlagValuesAndTerminator(t *testing.T) {
	tests := []struct {
		args []string
		path []string
		want bool
	}{
		{[]string{"connect", "--country", "US", "--help"}, []string{"connect"}, true},
		{[]string{"config", "--profile", "work", "set", "--help"}, []string{"config", "set"}, true},
		{[]string{"config", "--profile=work", "profile", "create", "-h"}, []string{"config", "profile", "create"}, true},
		{[]string{"connect", "--country", "--help"}, []string{"connect"}, false},
		{[]string{"connect", "--country=--help"}, []string{"connect"}, false},
		{[]string{"config", "--profile", "-h"}, []string{"config"}, false},
		{[]string{"connect", "--", "--help"}, []string{"connect"}, false},
	}
	for _, test := range tests {
		path, got := helpRequest(test.args)
		if got != test.want || !reflect.DeepEqual(path, test.path) {
			t.Errorf("helpRequest(%v) = %v, %v; want %v, %v", test.args, path, got, test.path, test.want)
		}
	}
}
