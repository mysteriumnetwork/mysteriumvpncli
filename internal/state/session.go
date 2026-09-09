// Package state persists protected local connection state.
package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Session contains the local metadata needed to manage an active connection.
type Session struct {
	SessionID  string    `json:"session_id"`
	PublicKey  string    `json:"public_key"`
	PrivateKey string    `json:"private_key"`
	Country    string    `json:"country"`
	IPType     string    `json:"ip_type"`
	ExitIP     string    `json:"exit_ip"`
	City       string    `json:"city"`
	ConfigPath string    `json:"config_path"`
	Timestamp  time.Time `json:"timestamp"`
}

// Store persists the current session in an owner-only file.
type Store struct {
	path string
}

// NewStore creates a session store at path.
func NewStore(path string) *Store {
	return &Store{path: path}
}

// NewDefaultStore creates a session store in the current user's config directory.
func NewDefaultStore() (*Store, error) {
	configDirectory, err := os.UserConfigDir()
	if err != nil {
		return nil, fmt.Errorf("find user config directory: %w", err)
	}
	return NewStore(filepath.Join(configDirectory, "mystvpn", "session.json")), nil
}

// Save atomically writes the current session with owner-only permissions.
func (s *Store) Save(session Session) error {
	directory := filepath.Dir(s.path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create session state directory: %w", err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return fmt.Errorf("secure session state directory: %w", err)
	}

	data, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("encode session state: %w", err)
	}
	temporary, err := os.CreateTemp(directory, ".session-*")
	if err != nil {
		return fmt.Errorf("create temporary session state: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)

	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return fmt.Errorf("secure temporary session state: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return fmt.Errorf("write session state: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("sync session state: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close session state: %w", err)
	}
	if err := os.Rename(temporaryPath, s.path); err != nil {
		return fmt.Errorf("store session state: %w", err)
	}
	return nil
}

// Load reads the current session.
func (s *Store) Load() (Session, error) {
	info, err := os.Lstat(s.path)
	if err != nil {
		return Session{}, fmt.Errorf("inspect session state: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return Session{}, errors.New("session state is not an owner-only regular file")
	}
	data, err := os.ReadFile(s.path)
	if err != nil {
		return Session{}, fmt.Errorf("read session state: %w", err)
	}
	var session Session
	if err := json.Unmarshal(data, &session); err != nil {
		return Session{}, fmt.Errorf("decode session state: %w", err)
	}
	return session, nil
}

// Clear removes the current session. A missing state file is ignored.
func (s *Store) Clear() error {
	if err := os.Remove(s.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove session state: %w", err)
	}
	return nil
}
