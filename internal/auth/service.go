// Package auth provides magic-link authentication and token lifecycle handling.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/mail"
	"strings"
	"time"

	"github.com/mysteriumnetwork/mysteriumvpncli/internal/client"
)

const (
	startAuthEndpoint     = "/auth/magic-link"
	tokenExchangeEndpoint = "/auth/token"
	refreshTokenEndpoint  = "/token/refresh"
	codeChallengeMethod   = "S256"
)

// ErrPendingAuthExpired indicates that an authorization code belongs to an
// expired local authentication attempt.
var ErrPendingAuthExpired = errors.New("pending authentication has expired")

// HTTPStatusError reports an unsuccessful authentication response without
// exposing its response body.
type HTTPStatusError struct {
	StatusCode int
}

func (e *HTTPStatusError) Error() string {
	return fmt.Sprintf("HTTP status %d", e.StatusCode)
}

// Options configures the magic-link authentication contract.
type Options struct {
	Pool           string
	CallbackURL    string
	PendingAuthTTL time.Duration
}

// Service handles magic-link initiation, token exchange, token refresh, and
// API-client integration.
type Service struct {
	client  *client.Client
	store   CredentialStore
	options Options
	now     func() time.Time
}

// NewService creates a magic-link authentication service.
func NewService(authClient *client.Client, store CredentialStore, options Options) *Service {
	return &Service{
		client:  authClient,
		store:   store,
		options: options,
		now:     time.Now,
	}
}

// Start begins email authentication and securely stores the PKCE state needed
// to complete it in a later invocation.
func (s *Service) Start(ctx context.Context, email string) (PendingAuth, error) {
	email = strings.TrimSpace(email)
	if err := validateEmail(email); err != nil {
		return PendingAuth{}, err
	}
	if strings.TrimSpace(s.options.CallbackURL) == "" {
		return PendingAuth{}, errors.New("authentication callback URL must not be empty")
	}
	if s.options.PendingAuthTTL <= 0 {
		return PendingAuth{}, errors.New("pending authentication TTL must be positive")
	}

	verifier, challenge, err := GeneratePKCE()
	if err != nil {
		return PendingAuth{}, fmt.Errorf("generate PKCE challenge: %w", err)
	}
	state, err := randomURLSafe(32)
	if err != nil {
		return PendingAuth{}, fmt.Errorf("generate authentication state: %w", err)
	}
	nonce, err := randomURLSafe(32)
	if err != nil {
		return PendingAuth{}, fmt.Errorf("generate authentication nonce: %w", err)
	}

	pending := PendingAuth{
		Email:         email,
		State:         state,
		Nonce:         nonce,
		CodeVerifier:  verifier,
		CodeChallenge: challenge,
		CallbackURL:   s.options.CallbackURL,
		ExpiresAt:     s.now().UTC().Add(s.options.PendingAuthTTL),
	}
	if err := s.store.SavePendingAuth(pending); err != nil {
		return PendingAuth{}, fmt.Errorf("save pending authentication: %w", err)
	}

	request := startAuthRequest{
		Email:               pending.Email,
		State:               pending.State,
		Nonce:               pending.Nonce,
		CodeChallenge:       pending.CodeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		CallbackURL:         pending.CallbackURL,
		Pool:                s.options.Pool,
	}
	statusCode, err := s.client.PostWithStatus(ctx, startAuthEndpoint, request, nil)
	if err := authError(statusCode, err); err != nil {
		_ = s.store.ClearPendingAuth()
		return PendingAuth{}, err
	}
	return pending, nil
}

// Exchange exchanges an authorization code for an access and refresh token.
// Browser callback handling is intentionally left to a later commit.
func (s *Service) Exchange(ctx context.Context, authorizationCode, state string) error {
	if strings.TrimSpace(authorizationCode) == "" {
		return errors.New("authorization code must not be empty")
	}
	pending, err := s.store.LoadPendingAuth()
	if err != nil {
		return fmt.Errorf("load pending authentication: %w", err)
	}
	if !s.now().Before(pending.ExpiresAt) {
		_ = s.store.ClearPendingAuth()
		return ErrPendingAuthExpired
	}
	if subtle.ConstantTimeCompare([]byte(state), []byte(pending.State)) != 1 {
		return errors.New("authentication state does not match")
	}

	request := tokenExchangeRequest{
		AuthorizationCode: authorizationCode,
		CodeVerifier:      pending.CodeVerifier,
		CallbackURL:       pending.CallbackURL,
	}
	var tokens tokenResponse
	statusCode, err := s.client.PostWithStatus(ctx, tokenExchangeEndpoint, request, &tokens)
	if err := authError(statusCode, err); err != nil {
		return err
	}
	if err := validateTokenResponse(tokens); err != nil {
		return err
	}
	if err := s.saveTokens(tokens); err != nil {
		return err
	}
	if err := s.store.ClearPendingAuth(); err != nil {
		return fmt.Errorf("clear pending authentication: %w", err)
	}
	return nil
}

// Refresh exchanges the stored refresh token for a new token pair and returns
// the new access token.
func (s *Service) Refresh(ctx context.Context) (string, error) {
	refreshToken, err := s.store.LoadRefreshToken()
	if err != nil {
		return "", fmt.Errorf("load refresh token: %w", err)
	}

	request := refreshRequest{RefreshToken: refreshToken}
	var tokens tokenResponse
	statusCode, err := s.client.PostWithStatus(ctx, refreshTokenEndpoint, request, &tokens)
	if err := authError(statusCode, err); err != nil {
		return "", err
	}
	if err := validateTokenResponse(tokens); err != nil {
		return "", err
	}
	if err := s.saveTokens(tokens); err != nil {
		return "", err
	}
	return tokens.AccessToken, nil
}

// ConfigureClient loads the stored access token and enables one automatic
// token refresh when the client receives an unauthorized response.
func (s *Service) ConfigureClient(apiClient *client.Client) error {
	accessToken, err := s.store.LoadAccessToken()
	if err != nil {
		return fmt.Errorf("load access token: %w", err)
	}

	apiClient.SetAccessToken(accessToken)
	apiClient.SetUnauthorizedHandler(s.Refresh)
	return nil
}

// GeneratePKCE returns an RFC 7636 verifier and its S256 challenge.
func GeneratePKCE() (verifier, challenge string, err error) {
	verifier, err = randomURLSafe(32)
	if err != nil {
		return "", "", err
	}
	digest := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(digest[:]), nil
}

func randomURLSafe(size int) (string, error) {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func validateEmail(email string) error {
	address, err := mail.ParseAddress(email)
	if err != nil || address.Address != email {
		return errors.New("email must be a valid email address")
	}
	return nil
}

func (s *Service) saveTokens(tokens tokenResponse) error {
	if err := s.store.SaveAccessToken(tokens.AccessToken); err != nil {
		return fmt.Errorf("save access token: %w", err)
	}
	if err := s.store.SaveRefreshToken(tokens.RefreshToken); err != nil {
		return fmt.Errorf("save refresh token: %w", err)
	}
	return nil
}

func authError(statusCode int, err error) error {
	if err == nil {
		return nil
	}
	var apiErr *client.APIError
	if errors.As(err, &apiErr) {
		return &HTTPStatusError{StatusCode: apiErr.StatusCode}
	}
	if statusCode != 0 && (statusCode < http.StatusOK || statusCode >= http.StatusMultipleChoices) {
		return &HTTPStatusError{StatusCode: statusCode}
	}
	return err
}

func validateTokenResponse(tokens tokenResponse) error {
	if tokens.AccessToken == "" || tokens.RefreshToken == "" {
		return errors.New("authentication response did not contain both tokens")
	}
	return nil
}

type startAuthRequest struct {
	Email               string `json:"email"`
	State               string `json:"state"`
	Nonce               string `json:"nonce"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
	CallbackURL         string `json:"callback_url"`
	Pool                string `json:"pool"`
}

type tokenExchangeRequest struct {
	AuthorizationCode string `json:"code"`
	CodeVerifier      string `json:"code_verifier"`
	CallbackURL       string `json:"callback_url"`
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}
