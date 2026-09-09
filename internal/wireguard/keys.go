// Package wireguard manages the local WireGuard keypair and tunnel configuration.
package wireguard

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// KeyPair contains base64-encoded X25519 keys in WireGuard's key format.
type KeyPair struct {
	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key"`
}

// KeyStore persists the app-owned WireGuard keypair in a protected file.
type KeyStore struct {
	path string
	mu   sync.Mutex
}

// NewKeyStore creates a key store at path.
func NewKeyStore(path string) *KeyStore {
	return &KeyStore{path: path}
}

// NewDefaultKeyStore creates a key store in the current user's config directory.
func NewDefaultKeyStore() (*KeyStore, error) {
	configDirectory, err := os.UserConfigDir()
	if err != nil {
		return nil, fmt.Errorf("find user config directory: %w", err)
	}
	return NewKeyStore(filepath.Join(configDirectory, "mystvpn", "wireguard", "keypair.json")), nil
}

// LoadOrCreate returns the saved keypair or generates and saves one when absent.
func (s *KeyStore) LoadOrCreate() (KeyPair, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	pair, err := s.load()
	if err == nil {
		return pair, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return KeyPair{}, err
	}

	pair, err = generateKeyPair()
	if err != nil {
		return KeyPair{}, err
	}
	if err := s.save(pair); err != nil {
		return KeyPair{}, err
	}
	return pair, nil
}

func generateKeyPair() (KeyPair, error) {
	privateKeyBytes := make([]byte, 32)
	if _, err := rand.Read(privateKeyBytes); err != nil {
		return KeyPair{}, fmt.Errorf("generate WireGuard keypair: %w", err)
	}
	privateKeyBytes[0] &= 248
	privateKeyBytes[31] = (privateKeyBytes[31] & 127) | 64

	privateKey, err := ecdh.X25519().NewPrivateKey(privateKeyBytes)
	if err != nil {
		return KeyPair{}, fmt.Errorf("create WireGuard private key: %w", err)
	}

	return KeyPair{
		PrivateKey: base64.StdEncoding.EncodeToString(privateKeyBytes),
		PublicKey:  base64.StdEncoding.EncodeToString(privateKey.PublicKey().Bytes()),
	}, nil
}

func (s *KeyStore) load() (KeyPair, error) {
	info, err := os.Lstat(s.path)
	if err != nil {
		return KeyPair{}, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return KeyPair{}, errors.New("stored WireGuard keypair is not an owner-only regular file")
	}
	data, err := os.ReadFile(s.path)
	if err != nil {
		return KeyPair{}, err
	}

	var pair KeyPair
	if err := json.Unmarshal(data, &pair); err != nil {
		return KeyPair{}, fmt.Errorf("decode WireGuard keypair: %w", err)
	}
	privateKeyBytes, err := base64.StdEncoding.DecodeString(pair.PrivateKey)
	if err != nil {
		return KeyPair{}, errors.New("stored WireGuard private key is invalid")
	}
	privateKey, err := ecdh.X25519().NewPrivateKey(privateKeyBytes)
	if err != nil {
		return KeyPair{}, errors.New("stored WireGuard private key is invalid")
	}
	derivedPublicKey := base64.StdEncoding.EncodeToString(privateKey.PublicKey().Bytes())
	if pair.PublicKey == "" || pair.PublicKey != derivedPublicKey {
		return KeyPair{}, errors.New("stored WireGuard keypair is invalid")
	}
	return pair, nil
}

func (s *KeyStore) save(pair KeyPair) error {
	directory := filepath.Dir(s.path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create WireGuard state directory: %w", err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return fmt.Errorf("secure WireGuard state directory: %w", err)
	}

	data, err := json.Marshal(pair)
	if err != nil {
		return fmt.Errorf("encode WireGuard keypair: %w", err)
	}
	temporary, err := os.CreateTemp(directory, ".keypair-*")
	if err != nil {
		return fmt.Errorf("create temporary keypair file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)

	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return fmt.Errorf("secure temporary keypair file: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return fmt.Errorf("write WireGuard keypair: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("sync WireGuard keypair: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close WireGuard keypair file: %w", err)
	}
	if err := os.Rename(temporaryPath, s.path); err != nil {
		return fmt.Errorf("store WireGuard keypair: %w", err)
	}
	return nil
}
