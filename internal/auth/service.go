// Package auth provides browser activation authentication and token lifecycle handling.
package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/mysteriumnetwork/mysteriumvpncli/internal/client"
)

const (
	activationEndpoint = "/auth/activation"
	tokenEndpoint      = "/oauth/token"
	refreshTokenGrant  = "refresh_token"
)

var (
	// ErrAuthenticationTimedOut indicates that activation did not complete in time.
	ErrAuthenticationTimedOut = errors.New("authentication timed out")
	// ErrActivationInvalid indicates that the backend rejected or expired an activation.
	ErrActivationInvalid = errors.New("activation expired or was rejected")
)

// HTTPStatusError reports an unsuccessful authentication response without
// exposing its response body.
type HTTPStatusError struct {
	StatusCode int
}

func (e *HTTPStatusError) Error() string {
	return fmt.Sprintf("HTTP status %d", e.StatusCode)
}

// Options configures browser activation and token refresh.
type Options struct {
	ClientID           string
	ActivationClientID string
	AuthorizationURL   string
	PollInterval       time.Duration
	AuthTimeout        time.Duration
}

// StartResult contains the protected activation state and browser URL.
type StartResult struct {
	Pending          PendingAuth
	AuthorizationURL string
}

// Service handles activation, token persistence, token refresh, and API-client integration.
type Service struct {
	client  *client.Client
	store   CredentialStore
	options Options
	now     func() time.Time
}

// NewService creates an authentication service.
func NewService(authClient *client.Client, store CredentialStore, options Options) *Service {
	return &Service{client: authClient, store: store, options: options, now: time.Now}
}

// Start creates and stores a new browser activation.
func (s *Service) Start(ctx context.Context) (StartResult, error) {
	if strings.TrimSpace(s.options.ActivationClientID) == "" {
		return StartResult{}, errors.New("activation client ID must not be empty")
	}
	if s.options.AuthTimeout <= 0 {
		return StartResult{}, errors.New("authentication timeout must be positive")
	}

	activationID, err := generateUUID()
	if err != nil {
		return StartResult{}, fmt.Errorf("generate activation ID: %w", err)
	}
	authorizationURL, err := buildAuthorizationURL(s.options.AuthorizationURL, s.options.ActivationClientID, activationID)
	if err != nil {
		return StartResult{}, err
	}

	pending := PendingAuth{ActivationID: activationID, ExpiresAt: s.now().UTC().Add(s.options.AuthTimeout)}
	if err := s.store.SavePendingAuth(pending); err != nil {
		return StartResult{}, fmt.Errorf("save pending authentication: %w", err)
	}

	statusCode, requestErr := s.client.PostWithStatusDebug(ctx, activationEndpoint, activationRequest{ID: activationID}, nil)
	if requestErr != nil {
		_ = s.store.ClearPendingAuth()
		return StartResult{}, authError(statusCode, requestErr)
	}
	if statusCode != http.StatusOK && statusCode != http.StatusNoContent {
		_ = s.store.ClearPendingAuth()
		return StartResult{}, &HTTPStatusError{StatusCode: statusCode}
	}

	return StartResult{Pending: pending, AuthorizationURL: authorizationURL}, nil
}

// Cancel clears an incomplete local authentication attempt.
func (s *Service) Cancel() error {
	if err := s.store.ClearPendingAuth(); err != nil {
		return fmt.Errorf("clear pending authentication: %w", err)
	}
	return nil
}

// Poll waits for the browser activation to produce an access and refresh token pair.
func (s *Service) Poll(ctx context.Context) error {
	if s.options.PollInterval <= 0 {
		return errors.New("authentication poll interval must be positive")
	}
	pending, err := s.store.LoadPendingAuth()
	if err != nil {
		return fmt.Errorf("load pending authentication: %w", err)
	}
	if !s.now().Before(pending.ExpiresAt) {
		_ = s.store.ClearPendingAuth()
		return ErrAuthenticationTimedOut
	}

	pollContext, cancel := context.WithDeadline(ctx, pending.ExpiresAt)
	defer cancel()
	endpoint := activationEndpoint + "/" + url.PathEscape(pending.ActivationID)

	for {
		var response activationResponse
		if err := s.client.Get(pollContext, endpoint, &response); err != nil {
			_ = s.store.ClearPendingAuth()
			if pollContext.Err() != nil {
				return ErrAuthenticationTimedOut
			}
			return authError(0, err)
		}
		if response.ID != pending.ActivationID {
			_ = s.store.ClearPendingAuth()
			return errors.New("authentication response contained an unexpected activation ID")
		}
		if !response.Valid {
			_ = s.store.ClearPendingAuth()
			return ErrActivationInvalid
		}
		if response.Token != nil && tokenPairComplete(*response.Token) {
			if err := validateTokenResponse(*response.Token); err != nil {
				_ = s.store.ClearPendingAuth()
				return err
			}
			if err := s.saveTokens(*response.Token); err != nil {
				_ = s.store.ClearPendingAuth()
				return err
			}
			if err := s.store.ClearPendingAuth(); err != nil {
				return fmt.Errorf("clear pending authentication: %w", err)
			}
			return nil
		}

		timer := time.NewTimer(s.options.PollInterval)
		select {
		case <-pollContext.Done():
			timer.Stop()
			_ = s.store.ClearPendingAuth()
			return ErrAuthenticationTimedOut
		case <-timer.C:
		}
	}
}

// Refresh exchanges the stored refresh token for a new token pair and returns
// the new access token.
func (s *Service) Refresh(ctx context.Context) (string, error) {
	if strings.TrimSpace(s.options.ClientID) == "" {
		return "", errors.New("authentication client ID must not be empty")
	}
	refreshToken, err := s.store.LoadRefreshToken()
	if err != nil {
		return "", fmt.Errorf("load refresh token: %w", err)
	}

	request := tokenRequest{GrantType: refreshTokenGrant, ClientID: s.options.ClientID, RefreshToken: refreshToken}
	var tokens TokenResponse
	statusCode, err := s.client.PostWithStatus(ctx, tokenEndpoint, request, &tokens)
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

func generateUUID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	encoded := hex.EncodeToString(value)
	return encoded[0:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:32], nil
}

func isUUID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	_, err := hex.DecodeString(strings.ReplaceAll(value, "-", ""))
	return err == nil
}

func buildAuthorizationURL(rawURL, clientID, activationID string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return "", errors.New("invalid authentication authorization URL")
	}
	query := parsed.Query()
	query.Set("response_type", "activation_none")
	query.Set("client_id", clientID)
	query.Set("request_id", activationID)
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

func (s *Service) saveTokens(tokens TokenResponse) error {
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

func tokenPairComplete(tokens TokenResponse) bool {
	return strings.TrimSpace(tokens.AccessToken) != "" && strings.TrimSpace(tokens.RefreshToken) != ""
}

func validateTokenResponse(tokens TokenResponse) error {
	if !tokenPairComplete(tokens) {
		return errors.New("authentication response did not contain both tokens")
	}
	if !strings.EqualFold(strings.TrimSpace(tokens.TokenType), "Bearer") {
		return errors.New("authentication response contained an unsupported token type")
	}
	if tokens.ExpiresIn <= 0 {
		return errors.New("authentication response contained an invalid expiry")
	}
	return nil
}

type activationRequest struct {
	ID string `json:"id"`
}

type activationResponse struct {
	ID    string         `json:"id"`
	Valid bool           `json:"valid"`
	Token *TokenResponse `json:"token"`
}

type tokenRequest struct {
	GrantType    string `json:"grant_type"`
	ClientID     string `json:"client_id"`
	RefreshToken string `json:"refresh_token"`
}

// TokenResponse is the token payload returned by activation and refresh.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	UserID       string `json:"user_id,omitempty"`
}
