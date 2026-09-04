package auth

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestFileStoreTokenLifecycle(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "credentials")
	store := NewFileStore(directory)

	if err := store.SaveAuthToken("auth-value"); err != nil {
		t.Fatalf("SaveAuthToken() error = %v", err)
	}
	if err := store.SaveRefreshToken("refresh-value"); err != nil {
		t.Fatalf("SaveRefreshToken() error = %v", err)
	}

	authToken, err := store.LoadAuthToken()
	if err != nil {
		t.Fatalf("LoadAuthToken() error = %v", err)
	}
	if authToken != "auth-value" {
		t.Errorf("auth token = %q, want auth-value", authToken)
	}
	refreshToken, err := store.LoadRefreshToken()
	if err != nil {
		t.Fatalf("LoadRefreshToken() error = %v", err)
	}
	if refreshToken != "refresh-value" {
		t.Errorf("refresh token = %q, want refresh-value", refreshToken)
	}

	assertPermissions(t, directory, 0o700)
	assertPermissions(t, filepath.Join(directory, authTokenFile), 0o600)
	assertPermissions(t, filepath.Join(directory, refreshTokenFile), 0o600)

	if err := store.ClearTokens(); err != nil {
		t.Fatalf("ClearTokens() error = %v", err)
	}
	if _, err := store.LoadAuthToken(); !errors.Is(err, ErrTokenNotFound) {
		t.Errorf("LoadAuthToken() error = %v, want ErrTokenNotFound", err)
	}
	if _, err := store.LoadRefreshToken(); !errors.Is(err, ErrTokenNotFound) {
		t.Errorf("LoadRefreshToken() error = %v, want ErrTokenNotFound", err)
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
