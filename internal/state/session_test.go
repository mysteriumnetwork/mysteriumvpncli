package state

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestStoreSessionLifecycle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mystvpn", "session.json")
	store := NewStore(path)
	want := Session{
		SessionID:  "conn-abc123",
		PublicKey:  "public-value",
		PrivateKey: "private-value",
		Country:    "DE",
		IPType:     "residential",
		ExitIP:     "1.2.3.4",
		City:       "berlin",
		ConfigPath: "/tmp/mystvpn.conf",
		Timestamp:  time.Date(2026, time.September, 8, 12, 0, 0, 0, time.UTC),
	}

	if err := store.Save(want); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	got, err := store.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Load() = %+v, want %+v", got, want)
	}
	assertPermissions(t, filepath.Dir(path), 0o700)
	assertPermissions(t, path, 0o600)

	if err := store.Clear(); err != nil {
		t.Fatalf("Clear() error = %v", err)
	}
	if _, err := store.Load(); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Load() error = %v, want os.ErrNotExist", err)
	}
}

func TestStoreRejectsBroadSessionPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mystvpn", "session.json")
	store := NewStore(path)
	if err := store.Save(Session{PrivateKey: "private-value"}); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}

	if _, err := store.Load(); err == nil {
		t.Error("Load() error = nil, want permissions error")
	}
}

func assertPermissions(t *testing.T, path string, want os.FileMode) {
	t.Helper()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(%q) error = %v", path, err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Errorf("permissions for %q = %o, want %o", path, got, want)
	}
}
