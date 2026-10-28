package config

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestSettingsMissingFileDoesNotCreateAnything(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mystvpn", "config.json")
	settings, err := NewStore(path).Load()
	if err != nil || !reflect.DeepEqual(settings, DefaultSettings()) {
		t.Fatalf("Load() = %+v, %v; want built-in defaults", settings, err)
	}
	if _, err := os.Stat(filepath.Dir(path)); !os.IsNotExist(err) {
		t.Errorf("config directory Stat() = %v, want not found", err)
	}
}

func TestSettingsSaveAndLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mystvpn", "config.json")
	store := NewStore(path)
	document := DefaultDocument()
	if err := document.Set("", "country", " ca "); err != nil {
		t.Fatal(err)
	}
	if err := document.Set("", "ip_type", "hosting"); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveDocument(document); err != nil {
		t.Fatal(err)
	}
	settings, err := store.Load()
	if err != nil || !reflect.DeepEqual(settings, Settings{Country: "CA", IPType: "hosting"}) {
		t.Fatalf("Load() = %+v, %v", settings, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var saved Document
	if err := json.Unmarshal(data, &saved); err != nil {
		t.Fatal(err)
	}
	if saved.ActiveProfile != DefaultProfile || string(saved.Profiles[DefaultProfile]["country"]) != `"CA"` || string(saved.Profiles[DefaultProfile]["ip_type"]) != `"hosting"` {
		t.Errorf("saved JSON = %s", data)
	}
	for file, mode := range map[string]os.FileMode{path: 0o600, filepath.Dir(path): 0o700} {
		info, err := os.Stat(file)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != mode {
			t.Errorf("%s mode = %o, want %o", file, info.Mode().Perm(), mode)
		}
	}
	for _, key := range Keys() {
		if err := document.Unset("", key); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.SaveDocument(document); err != nil {
		t.Fatal(err)
	}
	settings, err = store.Load()
	if err != nil || !reflect.DeepEqual(settings, DefaultSettings()) {
		t.Errorf("Load() after replacement = %+v, %v", settings, err)
	}
	document, err = store.LoadDocument()
	if err != nil || len(document.Profiles[DefaultProfile]) != 0 {
		t.Fatalf("built-in defaults were persisted as overrides: %+v, %v", document, err)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(entries) != 1 {
		t.Errorf("config directory entries = %v, %v; want only config.json", entries, err)
	}
}

func TestSettingsLoadValidatesJSON(t *testing.T) {
	for _, data := range []string{
		"", "{", "null", "[]", `"DE"`,
		`{"country":"DE"}`, `{"profiles":{"default":{"country":42}}}`,
		`{"profiles":{"default":{"country":"Germany"}}}`, `{"profiles":{"default":{"country":"  "}}}`,
		`{"profiles":{"default":{"country":""}}}`, `{"profiles":{"default":{"country":null}}}`,
		`{"profiles":{"default":{"ip_type":""}}}`, `{"profiles":{"default":{"ip_type":null}}}`,
		`{"profiles":{"default":{"ip_type":"mobile"}}}`,
		`{"profiles":null}`, `{"profiles":[]}`, `{"profiles":{"default":null}}`,
		`{"profiles":{"default":"DE"}}`, `{"profiles":{"bad name":{}}}`,
		`{"active_profile":"missing"}`, `{"active_profile":""}`, `{"active_profile":null}`,
		`{"country":"DE"} {}`, `{} trailing`,
	} {
		t.Run(data, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := NewStore(path).Load(); err == nil {
				t.Fatal("Load() accepted invalid config")
			}
		})
	}
	for _, data := range []string{`{}`, `{"profiles":{"default":{"country":"de"}}}`, `{"profiles":{"default":{"ip_type":"hosting"}}}`} {
		t.Run(data, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
				t.Fatal(err)
			}
			settings, err := NewStore(path).Load()
			if err != nil {
				t.Fatal(err)
			}
			if settings.Country != "" && settings.Country != "DE" {
				t.Errorf("country = %q, want DE", settings.Country)
			}
		})
	}
}

func TestInvalidDocumentSavePreservesExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	store := NewStore(path)
	document := DefaultDocument()
	if err := document.Set("", "ip_type", "hosting"); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveDocument(document); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	document.ActiveProfile = "missing"
	if err := store.SaveDocument(document); err == nil {
		t.Fatal("SaveDocument() accepted a missing selected profile")
	}
	if after, err := os.ReadFile(path); err != nil || !bytes.Equal(before, after) {
		t.Errorf("invalid save changed config: %s, %v", after, err)
	}
}

func TestSettingsReportsFileErrors(t *testing.T) {
	store := NewStore(t.TempDir())
	if _, err := store.Load(); err == nil {
		t.Error("Load() accepted a directory")
	}
	if err := store.SaveDocument(DefaultDocument()); err == nil {
		t.Error("Save() replaced a directory")
	}
}
