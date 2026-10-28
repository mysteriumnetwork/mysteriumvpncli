package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestProfilesInheritBuiltinsIndependently(t *testing.T) {
	document := DefaultDocument()
	if err := document.Set("", "country", "CA"); err != nil {
		t.Fatal(err)
	}
	if err := document.Set("", "ip_type", "hosting"); err != nil {
		t.Fatal(err)
	}
	if err := document.Create("us-1"); err != nil {
		t.Fatal(err)
	}
	settings, err := document.Effective("us-1")
	if err != nil || !reflect.DeepEqual(settings, DefaultSettings()) {
		t.Fatalf("new profile inherited user overrides: %+v, %v", settings, err)
	}
	if err := document.Set("us-1", "country", "us"); err != nil {
		t.Fatal(err)
	}
	if err := document.Set("us-1", "ip_type", "hosting"); err != nil {
		t.Fatal(err)
	}
	if err := document.Use("us-1"); err != nil {
		t.Fatal(err)
	}
	settings, err = document.Effective("")
	if err != nil || settings.Country != "US" || settings.IPType != "hosting" {
		t.Fatalf("selected profile = %+v, %v", settings, err)
	}
	if err := document.Unset("", "country"); err != nil {
		t.Fatal(err)
	}
	saved, err := document.Saved("")
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := saved["country"]; exists {
		t.Fatal("unset retained a persisted country override")
	}
	settings, err = document.Effective("")
	if err != nil || settings.Country != DefaultSettings().Country || settings.IPType != "hosting" {
		t.Errorf("unset profile = %+v, %v", settings, err)
	}
	settings, err = document.Effective(DefaultProfile)
	if err != nil || settings.Country != "CA" || settings.IPType != "hosting" {
		t.Errorf("editing another profile changed default: %+v, %v", settings, err)
	}
}

func TestProfilesPreserveUnknownJSONAndOnlyWriteOverrides(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	input := `{
		"active_profile":"us-1",
		"future_metadata":{"version":3},
		"profiles":{
			"default":{"country":"DE","future_target":{"cities":["Berlin"]}},
			"us-1":{"country":"US","ip_type":"hosting","future_flag":false}
		}
	}`
	if err := os.WriteFile(path, []byte(input), 0o600); err != nil {
		t.Fatal(err)
	}
	store := NewStore(path)
	document, err := store.LoadDocument()
	if err != nil {
		t.Fatal(err)
	}
	if err := document.Set("", "country", "ca"); err != nil {
		t.Fatal(err)
	}
	if err := document.Unset("", "ip_type"); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveDocument(document); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var actual, expected any
	if err := json.Unmarshal(data, &actual); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(`{
		"active_profile":"us-1",
		"future_metadata":{"version":3},
		"profiles":{
			"default":{"country":"DE","future_target":{"cities":["Berlin"]}},
			"us-1":{"country":"CA","future_flag":false}
		}
	}`), &expected); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(actual, expected) {
		t.Errorf("JSON properties lost or defaults materialized: %s", data)
	}
}

func TestProfileOperationsRejectInvalidChanges(t *testing.T) {
	document := DefaultDocument()
	for _, name := range []string{"", "bad name", "../default", "-leading", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"} {
		if err := document.Create(name); err == nil {
			t.Errorf("Create(%q) accepted invalid name", name)
		}
	}
	for _, operation := range []func() error{
		func() error { return document.Create(DefaultProfile) },
		func() error { return document.Use("missing") },
		func() error { return document.Use("") },
		func() error { return document.Delete(DefaultProfile) },
		func() error { return document.Delete("missing") },
		func() error { return document.Delete("") },
		func() error { return document.Set("missing", "country", "US") },
		func() error { return document.Set("", "country", "USA") },
		func() error { return document.Set("", "unknown", "value") },
		func() error { return document.Unset("", "unknown") },
	} {
		if err := operation(); err == nil {
			t.Error("invalid operation succeeded")
		}
	}
	if err := document.Create("us-1"); err != nil {
		t.Fatal(err)
	}
	if err := document.Use("us-1"); err != nil {
		t.Fatal(err)
	}
	if err := document.Delete("us-1"); err == nil {
		t.Error("deleted active profile")
	}
	if err := document.Use(DefaultProfile); err != nil {
		t.Fatal(err)
	}
	if err := document.Delete("us-1"); err != nil {
		t.Fatal(err)
	}
}

func TestProfilesReadsDoNotRewriteFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	input := `{"profiles":{"us-1":{"country":"us","future":123}},"active_profile":"us-1"}`
	if err := os.WriteFile(path, []byte(input), 0o600); err != nil {
		t.Fatal(err)
	}
	store := NewStore(path)
	settings, err := store.Load()
	if err != nil || settings.Country != "US" {
		t.Fatalf("Load() = %+v, %v", settings, err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != input {
		t.Errorf("read rewrote file: %s, %v", data, err)
	}
}
