package config

import "testing"

func TestCitySettingsValidation(t *testing.T) {
	settings := DefaultSettings()
	if err := settings.Set("city", " New York "); err != nil || settings.City != "New York" {
		t.Fatalf("city normalization: %+v, %v", settings, err)
	}
	for _, value := range []string{"", "   ", "New\nYork", "berlin\x00", "\tberlin"} {
		before := settings
		if err := settings.Set("city", value); err == nil || settings != before {
			t.Errorf("Set city %q = %+v, %v", value, settings, err)
		}
	}
	document := DefaultDocument()
	if err := document.Set("", "city", "berlin"); err != nil {
		t.Fatal(err)
	}
	if err := document.Unset("", "city"); err != nil {
		t.Fatal(err)
	}
	if got, err := document.Effective(""); err != nil || got.City != "" {
		t.Fatalf("unset city: %+v, %v", got, err)
	}
}
