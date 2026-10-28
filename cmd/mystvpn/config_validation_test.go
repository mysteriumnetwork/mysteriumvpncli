package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/mysteriumnetwork/mysteriumvpncli/internal/config"
)

func TestCLIInvalidSavedTargetingIsRejectedAndRepairable(t *testing.T) {
	for _, key := range []string{"country", "ip_type"} {
		for _, value := range []string{`""`, `null`, `42`} {
			t.Run(key+"="+value, func(t *testing.T) {
				configureTestHome(t)
				original := saveTestSession(t)
				body := fmt.Sprintf(`{"profiles":{"default":{%q:%s,"future":null}}}`, key, value)
				store := writeTestConfigJSON(t, body)
				cfg := config.Load()
				cfg.APIURL = "invalid-api-url" // No requests, even if validation regresses.
				runner := &recordingTunnelRunner{}
				for _, args := range [][]string{{"config", "effective"}, {"connect"}, {"refresh"}} {
					result := executeCLI(args, cfg, runner)
					if result.exitCode == 0 || !strings.Contains(result.stderr, key) || !strings.Contains(result.stderr, `profile "default"`) {
						t.Errorf("%v = %+v, want an explicit profile setting error", args, result)
					}
				}
				if len(runner.actions) != 0 || !reflect.DeepEqual(loadTestSession(t), original) {
					t.Fatal("invalid targeting changed the running session")
				}
				if data, err := os.ReadFile(store.Path()); err != nil || string(data) != body {
					t.Fatalf("failed commands changed config: %s, %v", data, err)
				}
				// Raw values remain inspectable before repair.
				if result := executeCLI([]string{"config"}, cfg, runner); result.exitCode != 0 || !strings.Contains(result.stdout, key) {
					t.Fatalf("could not inspect invalid saved settings: %+v", result)
				}
				assertCommandResult(t, executeCLI([]string{"config", "unset", key}, cfg, runner), 0, "", "")
				if settings, err := store.Load(); err != nil || !reflect.DeepEqual(settings, config.DefaultSettings()) {
					t.Fatalf("unset did not restore built-in defaults: %+v, %v", settings, err)
				}
				document, err := store.LoadDocument()
				if err != nil {
					t.Fatal(err)
				}
				if string(document.Profiles[config.DefaultProfile]["future"]) != "null" {
					t.Fatal("repair discarded an unknown property")
				}
			})
		}
	}
}

func TestCLIProfilesCanBeRepairedIndependently(t *testing.T) {
	configureTestHome(t)
	store := writeTestConfigJSON(t, `{
		"active_profile":"broken",
		"profiles":{
			"default":{},
			"broken":{"country":"Germany","ip_type":null,"future":123},
			"bad-ip":{"ip_type":"mobile"}
		}
	}`)
	execute := func(args ...string) commandResult { return executeCLI(args, config.Load(), nil) }
	assertCommandResult(t, execute("config", "profile", "current"), 0, "broken\n", "")
	assertCommandResult(t, execute("config", "profile", "use", "default"), 0, "Active profile: default\n", "")
	if settings, err := store.Load(); err != nil || !reflect.DeepEqual(settings, config.DefaultSettings()) {
		t.Fatalf("invalid inactive profile blocked healthy selection: %+v, %v", settings, err)
	}
	// Fix one of two bad values without losing the other values along the way.
	assertCommandResult(t, execute("config", "--profile", "broken", "set", "country", "US"), 0, "", "")
	document, err := store.LoadDocument()
	if err != nil {
		t.Fatal(err)
	}
	if string(document.Profiles["broken"]["country"]) != `"US"` || string(document.Profiles["broken"]["ip_type"]) != "null" || string(document.Profiles["broken"]["future"]) != "123" {
		t.Fatal("partial repair changed unrelated properties")
	}
	assertCommandResult(t, execute("config", "--profile", "broken", "unset", "ip_type"), 0, "", "")
	assertCommandResult(t, execute("config", "--profile", "broken", "get", "country"), 0, "US\n", "")
	assertCommandResult(t, execute("config", "--profile", "broken", "get", "ip_type"), 0, "residential\n", "")

	before, err := os.ReadFile(store.Path())
	if err != nil {
		t.Fatal(err)
	}
	result := execute("config", "profile", "use", "bad-ip")
	if result.exitCode != 2 || !strings.Contains(result.stderr, `profile "bad-ip"`) {
		t.Fatalf("selected invalid profile: %+v", result)
	}
	if after, err := os.ReadFile(store.Path()); err != nil || !bytes.Equal(before, after) {
		t.Fatal("failed selection changed persisted configuration")
	}
	assertCommandResult(t, execute("config", "profile", "delete", "bad-ip"), 0, "", "")
	assertCommandResult(t, execute("config", "profile", "use", "broken"), 0, "Active profile: broken\n", "")
}

func writeTestConfigJSON(t *testing.T, body string) *config.Store {
	t.Helper()
	store, err := config.NewDefaultStore()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(store.Path()), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(store.Path(), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return store
}
