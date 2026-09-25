package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	accessTokenFile     = "access_token"
	refreshTokenFile    = "refresh_token"
	pendingAuthFile     = "pending_auth.json"
	legacyAuthTokenFile = "auth_token"
)

var (
	// ErrTokenNotFound indicates that a requested token is not stored.
	ErrTokenNotFound = errors.New("token not found")
	// ErrPendingAuthNotFound indicates that no magic-link attempt is pending.
	ErrPendingAuthNotFound = errors.New("pending authentication not found")
)

// PendingAuth contains the protected local state required to complete a
// magic-link PKCE exchange.
type PendingAuth struct {
	Email             string    `json:"email"`
	State             string    `json:"state"`
	Nonce             string    `json:"nonce"`
	CodeVerifier      string    `json:"code_verifier"`
	CodeChallenge     string    `json:"code_challenge"`
	CallbackURL       string    `json:"callback_url"`
	AuthorizationCode string    `json:"authorization_code,omitempty"`
	ExpiresAt         time.Time `json:"expires_at"`
}

// CredentialStore persists tokens and pending magic-link authentication state.
type CredentialStore interface {
	SaveAccessToken(token string) error
	SaveRefreshToken(token string) error
	LoadAccessToken() (string, error)
	LoadRefreshToken() (string, error)
	ClearTokens() error
	SavePendingAuth(pending PendingAuth) error
	LoadPendingAuth() (PendingAuth, error)
	ClearPendingAuth() error
}

// FileStore stores credentials in owner-only files inside an owner-only directory.
type FileStore struct {
	directory string
	mu        sync.Mutex
}

// NewFileStore creates a credential store rooted at directory.
func NewFileStore(directory string) *FileStore {
	return &FileStore{directory: directory}
}

// NewDefaultFileStore creates a credential store in the current user's config directory.
func NewDefaultFileStore() (*FileStore, error) {
	configDirectory, err := os.UserConfigDir()
	if err != nil {
		return nil, fmt.Errorf("find user config directory: %w", err)
	}
	return NewFileStore(filepath.Join(configDirectory, "mystvpn", "credentials")), nil
}

// SaveAccessToken securely stores the API access token.
func (s *FileStore) SaveAccessToken(token string) error {
	return s.saveToken(accessTokenFile, token)
}

// SaveRefreshToken securely stores the refresh token.
func (s *FileStore) SaveRefreshToken(token string) error {
	return s.saveToken(refreshTokenFile, token)
}

// LoadAccessToken loads the stored API access token.
func (s *FileStore) LoadAccessToken() (string, error) {
	return s.loadToken(accessTokenFile)
}

// LoadRefreshToken loads the stored refresh token.
func (s *FileStore) LoadRefreshToken() (string, error) {
	return s.loadToken(refreshTokenFile)
}

// ClearTokens removes stored access and refresh tokens. A legacy auth-token
// file is also removed so logout clears credentials from pre-magic-link builds.
func (s *FileStore) ClearTokens() error {
	return s.removeFiles(accessTokenFile, refreshTokenFile, legacyAuthTokenFile)
}

// SavePendingAuth securely stores an in-progress magic-link authentication.
func (s *FileStore) SavePendingAuth(pending PendingAuth) error {
	if err := validatePendingAuth(pending); err != nil {
		return err
	}
	data, err := json.Marshal(pending)
	if err != nil {
		return fmt.Errorf("encode pending authentication: %w", err)
	}
	return s.saveFile(pendingAuthFile, data)
}

// LoadPendingAuth loads an in-progress magic-link authentication.
func (s *FileStore) LoadPendingAuth() (PendingAuth, error) {
	data, err := s.loadFile(pendingAuthFile, ErrPendingAuthNotFound)
	if err != nil {
		return PendingAuth{}, err
	}
	var pending PendingAuth
	if err := json.Unmarshal(data, &pending); err != nil {
		return PendingAuth{}, fmt.Errorf("decode pending authentication: %w", err)
	}
	if err := validatePendingAuth(pending); err != nil {
		return PendingAuth{}, fmt.Errorf("invalid pending authentication: %w", err)
	}
	return pending, nil
}

// ClearPendingAuth removes an in-progress magic-link authentication.
func (s *FileStore) ClearPendingAuth() error {
	return s.removeFiles(pendingAuthFile)
}

func (s *FileStore) saveToken(name, token string) error {
	token = strings.TrimSpace(token)
	if token == "" {
		return errors.New("token must not be empty")
	}
	return s.saveFile(name, []byte(token))
}

func (s *FileStore) loadToken(name string) (string, error) {
	data, err := s.loadFile(name, ErrTokenNotFound)
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", ErrTokenNotFound
	}
	return token, nil
}

func (s *FileStore) saveFile(name string, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := os.MkdirAll(s.directory, 0o700); err != nil {
		return fmt.Errorf("create credential directory: %w", err)
	}
	if err := os.Chmod(s.directory, 0o700); err != nil {
		return fmt.Errorf("secure credential directory: %w", err)
	}

	temporary, err := os.CreateTemp(s.directory, ".credential-*")
	if err != nil {
		return fmt.Errorf("create temporary credential file: %w", err)
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)

	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return fmt.Errorf("secure temporary credential file: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return fmt.Errorf("write credential: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("sync credential: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close credential file: %w", err)
	}
	if err := os.Rename(temporaryName, filepath.Join(s.directory, name)); err != nil {
		return fmt.Errorf("store credential: %w", err)
	}
	return nil
}

func (s *FileStore) loadFile(name string, notFound error) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	path := filepath.Join(s.directory, name)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, notFound
	}
	if err != nil {
		return nil, fmt.Errorf("inspect %s: %w", name, err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s is not an owner-only regular file", name)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", name, err)
	}
	return data, nil
}

func (s *FileStore) removeFiles(names ...string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var clearErrors []error
	for _, name := range names {
		if err := os.Remove(filepath.Join(s.directory, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			clearErrors = append(clearErrors, fmt.Errorf("remove %s: %w", name, err))
		}
	}
	return errors.Join(clearErrors...)
}

func validatePendingAuth(pending PendingAuth) error {
	if strings.TrimSpace(pending.Email) == "" ||
		strings.TrimSpace(pending.State) == "" ||
		strings.TrimSpace(pending.Nonce) == "" ||
		strings.TrimSpace(pending.CodeVerifier) == "" ||
		strings.TrimSpace(pending.CodeChallenge) == "" ||
		strings.TrimSpace(pending.CallbackURL) == "" ||
		pending.ExpiresAt.IsZero() {
		return errors.New("pending authentication is incomplete")
	}
	return nil
}
