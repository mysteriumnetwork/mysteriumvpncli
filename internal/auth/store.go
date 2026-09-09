package auth

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const (
	authTokenFile    = "auth_token"
	refreshTokenFile = "refresh_token"
)

// ErrTokenNotFound indicates that a requested token is not stored.
var ErrTokenNotFound = errors.New("token not found")

// TokenStore persists the token pair used by authentication and API clients.
type TokenStore interface {
	SaveAuthToken(token string) error
	SaveRefreshToken(token string) error
	LoadAuthToken() (string, error)
	LoadRefreshToken() (string, error)
	ClearTokens() error
}

// FileStore stores tokens in owner-only files inside an owner-only directory.
type FileStore struct {
	directory string
	mu        sync.Mutex
}

// NewFileStore creates a token store rooted at directory.
func NewFileStore(directory string) *FileStore {
	return &FileStore{directory: directory}
}

// NewDefaultFileStore creates a token store in the current user's config directory.
func NewDefaultFileStore() (*FileStore, error) {
	configDirectory, err := os.UserConfigDir()
	if err != nil {
		return nil, fmt.Errorf("find user config directory: %w", err)
	}
	return NewFileStore(filepath.Join(configDirectory, "mystvpn", "credentials")), nil
}

// SaveAuthToken securely stores the API authentication token.
func (s *FileStore) SaveAuthToken(token string) error {
	return s.save(authTokenFile, token)
}

// SaveRefreshToken securely stores the Sentinel refresh token.
func (s *FileStore) SaveRefreshToken(token string) error {
	return s.save(refreshTokenFile, token)
}

// LoadAuthToken loads the stored API authentication token.
func (s *FileStore) LoadAuthToken() (string, error) {
	return s.load(authTokenFile)
}

// LoadRefreshToken loads the stored Sentinel refresh token.
func (s *FileStore) LoadRefreshToken() (string, error) {
	return s.load(refreshTokenFile)
}

// ClearTokens removes both stored tokens. Missing token files are ignored.
func (s *FileStore) ClearTokens() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var clearErrors []error
	for _, name := range []string{authTokenFile, refreshTokenFile} {
		if err := os.Remove(filepath.Join(s.directory, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			clearErrors = append(clearErrors, fmt.Errorf("remove %s: %w", name, err))
		}
	}
	return errors.Join(clearErrors...)
}

func (s *FileStore) save(name, token string) error {
	if strings.TrimSpace(token) == "" {
		return errors.New("token must not be empty")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := os.MkdirAll(s.directory, 0o700); err != nil {
		return fmt.Errorf("create token directory: %w", err)
	}
	if err := os.Chmod(s.directory, 0o700); err != nil {
		return fmt.Errorf("secure token directory: %w", err)
	}

	temporary, err := os.CreateTemp(s.directory, ".token-*")
	if err != nil {
		return fmt.Errorf("create temporary token file: %w", err)
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)

	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return fmt.Errorf("secure temporary token file: %w", err)
	}
	if _, err := temporary.WriteString(token); err != nil {
		temporary.Close()
		return fmt.Errorf("write token: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("sync token: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close token file: %w", err)
	}
	if err := os.Rename(temporaryName, filepath.Join(s.directory, name)); err != nil {
		return fmt.Errorf("store token: %w", err)
	}
	return nil
}

func (s *FileStore) load(name string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	path := filepath.Join(s.directory, name)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", ErrTokenNotFound
	}
	if err != nil {
		return "", fmt.Errorf("inspect %s: %w", name, err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("%s is not an owner-only regular file", name)
	}
	token, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", name, err)
	}
	if strings.TrimSpace(string(token)) == "" {
		return "", ErrTokenNotFound
	}
	return string(token), nil
}
