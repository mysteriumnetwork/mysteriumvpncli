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
