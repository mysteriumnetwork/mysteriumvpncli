package config

import (
	"reflect"
	"strings"
	"testing"
)

func TestSettingsValues(t *testing.T) {
	settings := DefaultSettings()
	if err := settings.Set("country", " de "); err != nil {
		t.Fatal(err)
	}
	if err := settings.Set("ip_type", "hosting"); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]string{"country": "DE", "ip_type": "hosting"} {
		if got, err := settings.Get(key); err != nil || got != want {
			t.Errorf("Get(%q) = %v, %v; want %q", key, got, err, want)
		}
	}
	settings.Country = "CA"
	if DefaultSettings().Country == "CA" {
		t.Error("updating settings mutated the built-in defaults")
	}
}

func TestSettingsInvalidValuesDoNotMutate(t *testing.T) {
	want := Settings{Country: "DE", IPType: "hosting"}
	settings := want
	for _, update := range [][2]string{{"country", "Germany"}, {"country", ""}, {"ip_type", "mobile"}, {"ip_type", ""}, {"missing", "value"}} {
		if err := settings.Set(update[0], update[1]); err == nil {
			t.Errorf("Set(%q, %q) accepted invalid value", update[0], update[1])
		}
		if !reflect.DeepEqual(settings, want) {
			t.Errorf("invalid update changed settings to %+v", settings)
		}
	}
	if _, err := settings.Get("missing"); err == nil || !strings.Contains(err.Error(), strings.Join(Keys(), ", ")) {
		t.Errorf("unknown key error = %v, want dynamically listed settings", err)
	}
}

// This schema deliberately differs from Settings to exercise extension with
// targeting names and types that the config command has never heard of.
type targetingSettings struct {
	City      string            `json:"city,omitempty"`
	ASN       int               `json:"asn,omitempty"`
	Dedicated bool              `json:"dedicated,omitempty"`
	Locations []string          `json:"locations,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"`
	Target    struct {
		City string `json:"city"`
	} `json:"target,omitempty"`
	Ignored string `json:"-"`
	private string
}

func TestSettingOperationsDiscoverNewNamesAndTypes(t *testing.T) {
	var settings targetingSettings
	wantKeys := []string{"city", "asn", "dedicated", "locations", "labels", "target"}
	if got := settingKeys(reflect.TypeOf(settings)); !reflect.DeepEqual(got, wantKeys) {
		t.Fatalf("keys = %v, want %v", got, wantKeys)
	}
	for _, test := range []struct {
		key   string
		input string
		want  any
	}{
		{"city", "Berlin", "Berlin"},
		{"asn", "64512", 64512},
		{"dedicated", "true", true},
		{"dedicated", "false", false},
		{"locations", `["Berlin","Madrid"]`, []string{"Berlin", "Madrid"}},
		{"labels", `{"region":"Europe"}`, map[string]string{"region": "Europe"}},
		{"target", `{"city":"Berlin"}`, struct {
			City string `json:"city"`
		}{City: "Berlin"}},
	} {
		if err := setSettingValue(&settings, test.key, test.input); err != nil {
			t.Fatalf("set %s: %v", test.key, err)
		}
		got, err := settingField(reflect.ValueOf(settings), test.key)
		if err != nil || !reflect.DeepEqual(got.Interface(), test.want) {
			t.Errorf("%s = %v, %v; want %v", test.key, got, err, test.want)
		}
	}
	for _, test := range [][2]string{{"asn", "text"}, {"asn", "1.5"}, {"asn", "null"}, {"dedicated", "yes"}, {"dedicated", "null"}, {"locations", `"Berlin"`}, {"Ignored", "value"}, {"private", "value"}} {
		before := settings
		if err := setSettingValue(&settings, test[0], test[1]); err == nil {
			t.Errorf("set %s = %s accepted invalid value", test[0], test[1])
		}
		if !reflect.DeepEqual(settings, before) {
			t.Errorf("failed set %s changed values", test[0])
		}
	}
}
