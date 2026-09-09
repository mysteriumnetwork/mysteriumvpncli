package wireguard

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestKeyStoreReusesKeyPair(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wireguard", "keypair.json")
	store := NewKeyStore(path)

	first, err := store.LoadOrCreate()
	if err != nil {
		t.Fatalf("first LoadOrCreate() error = %v", err)
	}
	second, err := store.LoadOrCreate()
	if err != nil {
		t.Fatalf("second LoadOrCreate() error = %v", err)
	}
	if first != second {
		t.Errorf("second keypair differs from first")
	}
	privateKey, err := base64.StdEncoding.DecodeString(first.PrivateKey)
	if err != nil || len(privateKey) != 32 {
		t.Errorf("private key is not 32-byte base64: length=%d error=%v", len(privateKey), err)
	}
	if len(privateKey) == 32 && (privateKey[0]&7 != 0 || privateKey[31]&0x80 != 0 || privateKey[31]&0x40 == 0) {
		t.Error("private key does not use WireGuard's X25519 clamping")
	}
	if publicKey, err := base64.StdEncoding.DecodeString(first.PublicKey); err != nil || len(publicKey) != 32 {
		t.Errorf("public key is not 32-byte base64: length=%d error=%v", len(publicKey), err)
	}
	assertMode(t, filepath.Dir(path), 0o700)
	assertMode(t, path, 0o600)
}

func TestKeyStoreRejectsBroadKeyPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wireguard", "keypair.json")
	store := NewKeyStore(path)
	if _, err := store.LoadOrCreate(); err != nil {
		t.Fatalf("LoadOrCreate() error = %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}

	if _, err := store.LoadOrCreate(); err == nil {
		t.Error("LoadOrCreate() error = nil, want permissions error")
	}
}

func TestWriteConfigReplacesPrivateKeySecurely(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "configs")
	template := "[Interface]\nPrivateKey=%private_key%\nAddress=10.10.0.2/24\n"

	path, err := WriteConfig(directory, template, "private-value")
	if err != nil {
		t.Fatalf("WriteConfig() error = %v", err)
	}
	t.Cleanup(func() { os.Remove(path) })

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if strings.Contains(string(data), privateKeyPlaceholder) {
		t.Error("config still contains private-key placeholder")
	}
	if !strings.Contains(string(data), "PrivateKey=private-value") {
		t.Errorf("config = %q, want replaced private key", data)
	}
	assertMode(t, directory, 0o700)
	assertMode(t, path, 0o600)
}

func TestWriteConfigRequiresPlaceholder(t *testing.T) {
	if _, err := WriteConfig(t.TempDir(), "[Interface]\n", "private-value"); err == nil {
		t.Error("WriteConfig() error = nil, want missing-placeholder error")
	}
}

func TestUpdateAndRemoveManagedConfig(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", home)
	directory, err := DefaultConfigDirectory()
	if err != nil {
		t.Fatalf("DefaultConfigDirectory() error = %v", err)
	}
	path, err := WriteConfig(directory, "[Interface]\nPrivateKey=%private_key%\nAddress=old\n", "private-value")
	if err != nil {
		t.Fatalf("WriteConfig() error = %v", err)
	}

	if err := UpdateConfig(path, "[Interface]\nPrivateKey=%private_key%\nAddress=new\n", "private-value"); err != nil {
		t.Fatalf("UpdateConfig() error = %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if !strings.Contains(string(data), "Address=new") || strings.Contains(string(data), privateKeyPlaceholder) {
		t.Errorf("updated config = %q", data)
	}
	assertMode(t, path, 0o600)

	if err := RemoveConfig(path); err != nil {
		t.Fatalf("RemoveConfig() error = %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("Stat() error = %v, want not exist", err)
	}
}

func TestManagedConfigRejectsExternalPath(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", home)
	externalPath := filepath.Join(t.TempDir(), "mvpn-test.conf")
	if err := os.WriteFile(externalPath, []byte("do not change"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	if err := UpdateConfig(externalPath, "PrivateKey=%private_key%", "private-value"); err == nil {
		t.Error("UpdateConfig() error = nil, want unmanaged-path error")
	}
	if err := RemoveConfig(externalPath); err == nil {
		t.Error("RemoveConfig() error = nil, want unmanaged-path error")
	}
	data, err := os.ReadFile(externalPath)
	if err != nil || string(data) != "do not change" {
		t.Errorf("external file changed: data=%q error=%v", data, err)
	}
}

func TestValidateConfigPathRejectsBroadPermissions(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", home)
	directory, err := DefaultConfigDirectory()
	if err != nil {
		t.Fatalf("DefaultConfigDirectory() error = %v", err)
	}
	path, err := WriteConfig(directory, "PrivateKey=%private_key%", "private-value")
	if err != nil {
		t.Fatalf("WriteConfig() error = %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}

	if err := ValidateConfigPath(path); err == nil {
		t.Error("ValidateConfigPath() error = nil, want permissions error")
	}
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(%q) error = %v", path, err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Errorf("permissions for %q = %o, want %o", path, got, want)
	}
}
