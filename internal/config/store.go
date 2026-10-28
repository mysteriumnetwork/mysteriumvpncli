package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Store reads and writes the user's settings JSON.
type Store struct{ path string }

func NewStore(path string) *Store { return &Store{path: path} }

// NewDefaultStore uses the same user config directory as authentication and state.
func NewDefaultStore() (*Store, error) {
	directory, err := os.UserConfigDir()
	if err != nil {
		return nil, fmt.Errorf("find user config directory: %w", err)
	}
	return NewStore(filepath.Join(directory, "mystvpn", "config.json")), nil
}

func (s *Store) Path() string { return s.path }

// Load returns the active profile's effective settings.
func (s *Store) Load() (Settings, error) {
	document, err := s.LoadDocument()
	if err != nil {
		return Settings{}, err
	}
	settings, err := document.Effective("")
	if err != nil {
		return Settings{}, fmt.Errorf("invalid config %s: %w", s.path, err)
	}
	return settings, nil
}

// LoadDocument uses built-in defaults when the file is missing, without writing it.
func (s *Store) LoadDocument() (*Document, error) {
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return DefaultDocument(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", s.path, err)
	}
	var document Document
	if err := json.Unmarshal(data, &document); err != nil {
		return nil, fmt.Errorf("decode config %s: %w", s.path, err)
	}
	return &document, nil
}

// SaveDocument checks structure and atomically writes owner-only JSON. Unrelated
// invalid values are preserved so profiles can be repaired through Set or Unset.
func (s *Store) SaveDocument(document *Document) error {
	if err := document.validateStructure(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return fmt.Errorf("encode config: %w", err)
	}
	data = append(data, '\n')
	directory := filepath.Dir(s.path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}
	temporary, err := os.CreateTemp(directory, ".config-*")
	if err != nil {
		return fmt.Errorf("create temporary config: %w", err)
	}
	defer os.Remove(temporary.Name())
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return fmt.Errorf("write config: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("sync config: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close config: %w", err)
	}
	if err := os.Rename(temporary.Name(), s.path); err != nil {
		return fmt.Errorf("store config: %w", err)
	}
	return nil
}
