package auth

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFileStoreTokenLifecycle(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "credentials")
	store := NewFileStore(directory)

	if err := store.SaveAccessToken("auth-value"); err != nil {
		t.Fatalf("SaveAccessToken() error = %v", err)
	}
	if err := store.SaveRefreshToken("refresh-value"); err != nil {
		t.Fatalf("SaveRefreshToken() error = %v", err)
	}

	accessToken, err := store.LoadAccessToken()
	if err != nil {
		t.Fatalf("LoadAccessToken() error = %v", err)
	}
	if accessToken != "auth-value" {
		t.Errorf("access token = %q, want auth-value", accessToken)
	}
	refreshToken, err := store.LoadRefreshToken()
	if err != nil {
		t.Fatalf("LoadRefreshToken() error = %v", err)
	}
	if refreshToken != "refresh-value" {
		t.Errorf("refresh token = %q, want refresh-value", refreshToken)
	}

	assertPermissions(t, directory, 0o700)
	assertPermissions(t, filepath.Join(directory, accessTokenFile), 0o600)
	assertPermissions(t, filepath.Join(directory, refreshTokenFile), 0o600)

	if err := store.ClearTokens(); err != nil {
		t.Fatalf("ClearTokens() error = %v", err)
	}
	if _, err := store.LoadAccessToken(); !errors.Is(err, ErrTokenNotFound) {
		t.Errorf("LoadAccessToken() error = %v, want ErrTokenNotFound", err)
	}
	if _, err := store.LoadRefreshToken(); !errors.Is(err, ErrTokenNotFound) {
		t.Errorf("LoadRefreshToken() error = %v, want ErrTokenNotFound", err)
	}
}

func TestFileStoreRejectsBroadTokenPermissions(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "credentials")
	store := NewFileStore(directory)
	if err := store.SaveAccessToken("auth-value"); err != nil {
		t.Fatalf("SaveAccessToken() error = %v", err)
	}
	if err := os.Chmod(filepath.Join(directory, accessTokenFile), 0o644); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}

	if _, err := store.LoadAccessToken(); err == nil {
		t.Error("LoadAccessToken() error = nil, want permissions error")
	}
}

func TestFileStorePendingAuthLifecycle(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "credentials")
	store := NewFileStore(directory)
	pending := PendingAuth{
		ActivationID: "223e4567-e89b-42d3-a456-426614174000",
		ExpiresAt:    time.Date(2026, time.September, 25, 10, 10, 0, 0, time.UTC),
	}

	if err := store.SavePendingAuth(pending); err != nil {
		t.Fatalf("SavePendingAuth() error = %v", err)
	}
	loaded, err := store.LoadPendingAuth()
	if err != nil {
		t.Fatalf("LoadPendingAuth() error = %v", err)
	}
	if loaded != pending {
		t.Errorf("loaded pending auth = %+v, want %+v", loaded, pending)
	}
	assertPermissions(t, directory, 0o700)
	assertPermissions(t, filepath.Join(directory, pendingAuthFile), 0o600)

	if err := store.ClearPendingAuth(); err != nil {
		t.Fatalf("ClearPendingAuth() error = %v", err)
	}
	if _, err := store.LoadPendingAuth(); !errors.Is(err, ErrPendingAuthNotFound) {
		t.Errorf("LoadPendingAuth() error = %v, want ErrPendingAuthNotFound", err)
	}
}

func TestFileStoreRejectsIncompletePendingActivation(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "credentials")
	store := NewFileStore(directory)
	if err := store.SavePendingAuth(PendingAuth{ExpiresAt: time.Now().Add(time.Minute)}); err == nil {
		t.Fatal("SavePendingAuth() error = nil, want incomplete activation error")
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
