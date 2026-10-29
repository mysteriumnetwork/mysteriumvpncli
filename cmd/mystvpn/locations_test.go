package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"unicode/utf8"

	"github.com/mysteriumnetwork/mysteriumvpncli/internal/config"
	"github.com/mysteriumnetwork/mysteriumvpncli/internal/proxy"
	"github.com/mysteriumnetwork/mysteriumvpncli/internal/state"
)

func TestCountriesUseSelectedIPTypeWithoutChangingConfig(t *testing.T) {
	for _, test := range []struct {
		name   string
		config string
		args   []string
		want   string
	}{
		{name: "built-in default", want: "residential"},
		{name: "saved active default", config: `{"profiles":{"default":{"ip_type":"hosting"}}}`, want: "hosting"},
		{name: "selected profile", config: `{"active_profile":"work","profiles":{"default":{"ip_type":"residential"},"work":{"ip_type":"hosting"}}}`, want: "hosting"},
		{name: "explicit override", config: `{"profiles":{"default":{"ip_type":"hosting"}}}`, args: []string{"--ip-type", "residential"}, want: "residential"},
		{name: "invalid country does not block discovery", config: `{"profiles":{"default":{"country":"DF","ip_type":"hosting"}}}`, want: "hosting"},
		{name: "invalid country type does not block discovery", config: `{"profiles":{"default":{"country":42,"ip_type":"hosting","city":{"future":"setting"}}}}`, want: "hosting"},
		{name: "default IP type with invalid country", config: `{"profiles":{"default":{"country":null}}}`, want: "residential"},
		{name: "explicit override bypasses broken config", config: `invalid JSON`, args: []string{"--ip-type", "hosting"}, want: "hosting"},
		{name: "explicit override bypasses invalid saved value", config: `{"profiles":{"default":{"ip_type":"mobile"}}}`, args: []string{"--ip-type", "hosting"}, want: "hosting"},
	} {
		t.Run(test.name, func(t *testing.T) {
			configureTestHome(t)
			saveTestAuthToken(t)
			store, err := config.NewDefaultStore()
			if err != nil {
				t.Fatal(err)
			}
			if test.config != "" {
				writeTestConfigJSON(t, test.config)
			}
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				requests.Add(1)
				if got := request.URL.Query().Get("ip_type"); got != test.want {
					t.Errorf("requested IP type = %q, want %q", got, test.want)
				}
				_, _ = writer.Write([]byte(`{"countries":["GB","DE"]}`))
			}))
			defer server.Close()
			cfg := config.Load()
			cfg.APIURL = server.URL
			result := executeCLI(append([]string{"countries"}, test.args...), cfg, nil)
			want := "[SUCCESS] Available countries (2) for IP type: " + test.want + "\n\nCODE  COUNTRY    CODE  COUNTRY\nDE    Germany    GB    United Kingdom\n"
			assertCommandResult(t, result, 0, want, "")
			if got := requests.Load(); got != 1 {
				t.Fatalf("requests = %d, want 1", got)
			}
			data, err := os.ReadFile(store.Path())
			if test.config == "" {
				if !os.IsNotExist(err) {
					t.Fatalf("reading defaults created config: %q, %v", data, err)
				}
			} else if err != nil || string(data) != test.config {
				t.Fatalf("listing changed saved settings: %q, %v", data, err)
			}
		})
	}
}

func TestCountriesRejectInvalidSavedIPTypeBeforeRequests(t *testing.T) {
	for _, value := range []string{`"mobile"`, `""`, `null`, `42`} {
		t.Run(value, func(t *testing.T) {
			configureTestHome(t)
			writeTestConfigJSON(t, `{"profiles":{"default":{"ip_type":`+value+`}}}`)
			cfg := config.Load()
			cfg.APIURL = "invalid-api-url" // A request would instead fail with exit 1.
			result := executeCLI([]string{"countries"}, cfg, nil)
			if result.exitCode != 2 || result.stdout != "" || !strings.Contains(result.stderr, "ip_type") || !strings.Contains(result.stderr, `profile "default"`) {
				t.Fatalf("result = %+v, want profile IP type validation error", result)
			}
		})
	}
	configureTestHome(t)
	writeTestConfigJSON(t, "invalid JSON")
	result := executeCLI([]string{"countries"}, config.Load(), nil)
	if result.exitCode != 1 || result.stdout != "" || !strings.Contains(result.stderr, "decode config") {
		t.Fatalf("result = %+v, want config file error", result)
	}
}

func TestWriteCountriesTablePreservesCodesAndNames(t *testing.T) {
	countries := []string{"US", " de ", "ZZ", "CA", "GB", "CI"}
	before := strings.Join(countries, "|")
	var output bytes.Buffer
	writeCountries(&output, countries, proxy.IPTypeHosting)
	want := "[SUCCESS] Available countries (6) for IP type: hosting\n\n" +
		"CODE  COUNTRY          CODE  COUNTRY\nCA    Canada           GB    United Kingdom\nCI    Côte d’Ivoire    US    United States\nDE    Germany          ZZ    Unknown country\n"
	if output.String() != want {
		t.Errorf("output = %q, want %q", output.String(), want)
	}
	if strings.Join(countries, "|") != before {
		t.Fatal("rendering changed the server's country list")
	}
}

func TestWriteCountriesEmptyListStillShowsIPType(t *testing.T) {
	var output bytes.Buffer
	writeCountries(&output, nil, proxy.IPTypeResidential)
	if got, want := output.String(), "[SUCCESS] Available countries (0) for IP type: residential\n"; got != want {
		t.Errorf("output = %q, want %q", got, want)
	}
}

func TestCountryTableUsesTwoAlignedGroups(t *testing.T) {
	codes := []string{"CA", "CI", "DE", "GB", "US", "ZZ"}
	var output bytes.Buffer
	writeCountryTable(&output, codes)
	want := "CODE  COUNTRY          CODE  COUNTRY\n" +
		"CA    Canada           GB    United Kingdom\n" +
		"CI    Côte d’Ivoire    US    United States\n" +
		"DE    Germany          ZZ    Unknown country\n"
	if output.String() != want {
		t.Errorf("table:\n%s\nwant:\n%s", output.String(), want)
	}
	// The accent and curly apostrophe use more bytes than screen cells. All
	// entries in the second group must start at the same visible column.
	for i, line := range strings.Split(strings.TrimSuffix(output.String(), "\n"), "\n") {
		right := []string{"CODE", "GB", "US", "ZZ"}[i]
		at := strings.LastIndex(line, right)
		if at < 0 || utf8.RuneCountInString(line[:at]) != 23 {
			t.Errorf("second group is misaligned: %q", line)
		}
	}
}

func TestCountryTableOddCountAndSingleCountry(t *testing.T) {
	var output bytes.Buffer
	writeCountryTable(&output, []string{"AD", "CA", "DE", "GB", "US"})
	if !strings.HasSuffix(output.String(), "DE    Germany\n") || strings.Count(output.String(), "COUNTRY") != 2 {
		t.Fatalf("odd count produced a missing entry or an empty padded cell:\n%s", output.String())
	}
	output.Reset()
	writeCountryTable(&output, []string{"DE"})
	if want := "CODE  COUNTRY\nDE    Germany\n"; output.String() != want {
		t.Fatalf("single country = %q, want %q", output.String(), want)
	}
}

func TestStatusShowsSessionIPTypeInsteadOfProfileDefault(t *testing.T) {
	configureTestHome(t)
	saveTestSession(t) // Residential connection in Germany.
	writeTestConfigJSON(t, `{"profiles":{"default":{"country":"US","ip_type":"hosting"}}}`)
	result := executeCLI([]string{"status"}, config.Load(), nil)
	assertCommandResult(t, result, 0, "Connected:   yes\nIP address:  1.2.3.4\nIP type:     residential\nCountry:     DE (Germany)\nCity:        berlin\n", "")
}

func TestStatusPreservesUnknownLocationAndMissingIPType(t *testing.T) {
	configureTestHome(t)
	session := saveTestSession(t)
	session.Country, session.IPType = "zz", ""
	store, err := state.NewDefaultStore()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(session); err != nil {
		t.Fatal(err)
	}
	result := executeCLI([]string{"status"}, config.Load(), nil)
	assertCommandResult(t, result, 0, "Connected:   yes\nIP address:  1.2.3.4\nIP type:     unknown\nCountry:     ZZ (Unknown country)\nCity:        berlin\n", "")
}
