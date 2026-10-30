package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/mysteriumnetwork/mysteriumvpncli/internal/config"
	"github.com/mysteriumnetwork/mysteriumvpncli/internal/mockserver"
)

func TestCitiesDiscovery(t *testing.T) {
	for _, test := range []struct {
		name, document, country, ipType string
		args                            []string
	}{
		{"defaults", `{}`, "DE", "residential", nil},
		{"profile ignores invalid saved city", `{"active_profile":"work","profiles":{"work":{"country":"US","ip_type":"hosting","city":42}}}`, "US", "hosting", nil},
		{"explicit overrides bypass broken config", `invalid`, "US", "hosting", []string{"--country", "us", "--ip-type", "hosting"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			configureTestHome(t)
			saveTestAuthToken(t)
			writeTestConfigJSON(t, test.document)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" || r.URL.Path != "/api/v1/connection/config/locations" || r.URL.Query().Get("ip_type") != test.ipType || r.Header.Get("Authorization") == "" {
					t.Errorf("unexpected request: %s %s", r.Method, r.URL)
				}
				_, _ = w.Write([]byte(`[{"country":"` + test.country + `","cities":[{"city":"zürich","is_available":true},{"city":"unavailable","is_available":false},{"city":"New York"}]},{"country":"CA","cities":[{"city":"other-country"}]}]`))
			}))
			defer server.Close()
			cfg := config.Load()
			cfg.APIURL = server.URL + "/api/v1"
			result := executeCLI(append([]string{"cities"}, test.args...), cfg, nil)
			assertCommandResult(t, result, 0, "[SUCCESS] Available cities/states (2) in "+test.country+" for IP type: "+test.ipType+"\n\nNew York    zürich\n", "")
		})
	}
}

func TestUnavailableCityStopsConnectAndRefreshBeforeChangingTunnel(t *testing.T) {
	for _, command := range []string{"connect", "refresh"} {
		for _, test := range []struct {
			name, body       string
			status, exitCode int
			wantError        string
		}{
			{"removed city", `[{"country":"DE","cities":[{"city":"hamburg","is_available":true}]}]`, 200, 2, `city/state "berlin" is not currently available in DE for IP type hosting for your account`},
			{"unavailable city", `[{"country":"DE","cities":[{"city":"berlin","is_available":false}]}]`, 200, 2, `city/state "berlin" is not currently available`},
			{"unavailable country", `[{"country":"DE","is_available":false,"cities":[{"city":"berlin","is_available":true}]}]`, 200, 2, `city/state "berlin" is not currently available`},
			{"different country", `[{"country":"US","cities":[{"city":"berlin","is_available":true}]}]`, 200, 2, `city/state "berlin" is not currently available`},
			{"lookup failed", `{}`, 403, 1, `could not validate city/state "berlin"`},
			{"invalid catalogue", `{`, 200, 1, `the VPN service returned an invalid response`},
		} {
			t.Run(command+"/"+test.name, func(t *testing.T) {
				configureTestHome(t)
				saveTestAuthToken(t)
				original := saveTestSession(t)
				originalConfig, err := os.ReadFile(original.ConfigPath)
				if err != nil {
					t.Fatal(err)
				}
				writeTestConfigJSON(t, `{"active_profile":"work","profiles":{"work":{"country":"DE","city":"berlin","ip_type":"hosting"}}}`)
				var posts int
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method == http.MethodPost {
						posts++
						w.WriteHeader(500)
						return
					}
					if r.URL.Path != "/api/v1/connection/config/locations" || r.URL.Query().Get("ip_type") != "hosting" || r.Header.Get("Authorization") == "" {
						t.Errorf("unexpected validation request: %s %s", r.Method, r.URL)
					}
					w.WriteHeader(test.status)
					_, _ = w.Write([]byte(test.body))
				}))
				defer server.Close()
				cfg := config.Load()
				cfg.APIURL = server.URL + "/api/v1"
				runner := &endToEndTunnelRunner{}
				result := executeCLI([]string{command}, cfg, runner)
				if result.exitCode != test.exitCode || result.stdout != "" || !strings.Contains(result.stderr, test.wantError) {
					t.Fatalf("unexpected result: %+v", result)
				}
				if test.exitCode == 2 && !strings.Contains(result.stderr, `mystvpn cities --country DE --ip-type hosting`) {
					t.Fatalf("missing discovery instructions: %s", result.stderr)
				}
				if posts != 0 || len(runner.actions) != 0 {
					t.Fatalf("validation failure changed connection: %d POSTs, %v", posts, runner.actions)
				}
				if got := loadTestSession(t); !reflect.DeepEqual(got, original) {
					t.Fatal("validation changed the saved session")
				}
				currentConfig, err := os.ReadFile(original.ConfigPath)
				if err != nil || string(currentConfig) != string(originalConfig) {
					t.Fatalf("validation changed WireGuard config: %v", err)
				}
				assertCommandResult(t, executeCLI([]string{"config", "get", "city"}, cfg, nil), 0, "berlin\n", "")
			})
		}
	}
}

func TestCityTargetsAcrossProfilesOverridesAndRefresh(t *testing.T) {
	configureTestHome(t)
	server := mockserver.New()
	defer server.Close()
	cfg := config.Load()
	cfg.APIURL = server.APIURL()
	runner := &endToEndTunnelRunner{}
	execute := func(args ...string) commandResult { return executeCLI(args, cfg, runner) }
	ok := func(args ...string) {
		t.Helper()
		if result := execute(args...); result.exitCode != 0 || result.stderr != "" {
			t.Fatalf("%v: %+v", args, result)
		}
	}
	assertAuthCommandSuccess(t, execute("auth"))
	ok("config", "set", "city", " berlin ")
	assertCommandResult(t, execute("config", "get", "city"), 0, "berlin\n", "")
	ok("connect")
	ok("connect", "--city", "hamburg")
	assertCommandResult(t, execute("config", "get", "city"), 0, "berlin\n", "")
	ok("refresh")
	ok("connect", "--city=")
	ok("config", "profile", "create", "states")
	ok("config", "--profile", "states", "set", "country", "US")
	ok("config", "--profile", "states", "set", "city", "New York")
	ok("connect", "--profile", "states")
	if got := loadEndToEndSession(t).City; got != "New York" {
		t.Fatalf("session city = %q", got)
	}
	ok("config", "profile", "use", "states")
	ok("refresh")
	ok("config", "unset", "city")
	ok("refresh")
	want := []struct{ country, city string }{{"DE", "berlin"}, {"DE", "hamburg"}, {"DE", "berlin"}, {"DE", ""}, {"US", "New York"}, {"US", "New York"}, {"US", ""}}
	requests := server.Snapshot().ConnectRequests
	if len(requests) != len(want) {
		t.Fatalf("requests = %+v", requests)
	}
	for i, target := range want {
		if requests[i].Country != target.country || requests[i].City != target.city {
			t.Errorf("request %d = %+v, want %+v", i, requests[i], target)
		}
	}
}

func TestCitiesValidationAndAuthentication(t *testing.T) {
	configureTestHome(t)
	for _, args := range [][]string{{"--country="}, {"--country", "DF"}, {"--ip-type="}, {"--ip-type", "mobile"}, {"--unknown"}, {"extra"}} {
		if result := executeCLI(append([]string{"cities"}, args...), config.Load(), nil); result.exitCode != 2 || result.stderr == "" {
			t.Errorf("%v: %+v", args, result)
		}
	}
	if result := executeCLI([]string{"cities"}, config.Load(), nil); result.exitCode != 1 || result.stderr == "" {
		t.Fatalf("unauthenticated cities: %+v", result)
	}
}
