// Package auth provides Sentinel authentication and token lifecycle handling.
package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/mysteriumnetwork/mysteriumvpncli/internal/client"
)

const (
	passwordAuthEndpoint = "/auth/password"
	refreshTokenEndpoint = "/token/refresh"
)

// HTTPStatusError reports an unsuccessful Sentinel response without exposing
// its response body.
type HTTPStatusError struct {
	StatusCode int
}

func (e *HTTPStatusError) Error() string {
	return fmt.Sprintf("HTTP status %d", e.StatusCode)
}

// Service handles Sentinel login, token refresh, and API-client integration.
type Service struct {
	client *client.Client
	store  TokenStore
	pool   string
}

// NewService creates a Sentinel authentication service.
func NewService(sentinelClient *client.Client, store TokenStore, pool string) *Service {
	return &Service{
		client: sentinelClient,
		store:  store,
		pool:   pool,
	}
}

// Login exchanges username and password credentials for a token pair.
func (s *Service) Login(ctx context.Context, username, password string) error {
	if strings.TrimSpace(username) == "" {
		return errors.New("username must not be empty")
	}
	if password == "" {
		return errors.New("password must not be empty")
	}

	request := passwordAuthRequest{
		Username: username,
		Password: password,
		Pool:     s.pool,
	}
	var tokens tokenResponse
	statusCode, err := s.client.PostWithStatus(ctx, passwordAuthEndpoint, request, &tokens)
	if err := sentinelError(statusCode, err); err != nil {
		return err
	}
	if statusCode != http.StatusOK {
		return &HTTPStatusError{StatusCode: statusCode}
	}
	if err := validateTokenResponse(tokens); err != nil {
		return err
	}
	return s.saveTokens(tokens)
}

// Refresh exchanges the stored refresh token for a new token pair and returns
// the new auth token.
func (s *Service) Refresh(ctx context.Context) (string, error) {
	refreshToken, err := s.store.LoadRefreshToken()
	if err != nil {
		return "", fmt.Errorf("load refresh token: %w", err)
	}

	request := refreshRequest{Token: refreshToken}
	var tokens tokenResponse
	statusCode, err := s.client.PostWithStatus(ctx, refreshTokenEndpoint, request, &tokens)
	if err := sentinelError(statusCode, err); err != nil {
		return "", err
	}
	if statusCode != http.StatusOK {
		return "", &HTTPStatusError{StatusCode: statusCode}
	}
	if err := validateTokenResponse(tokens); err != nil {
		return "", err
	}
	if err := s.saveTokens(tokens); err != nil {
		return "", err
	}
	return tokens.AuthToken, nil
}

// ConfigureClient loads the stored auth token and enables one automatic token
// refresh when the client receives an unauthorized response.
func (s *Service) ConfigureClient(apiClient *client.Client) error {
	authToken, err := s.store.LoadAuthToken()
	if err != nil {
		return fmt.Errorf("load auth token: %w", err)
	}

	apiClient.SetToken(authToken)
	apiClient.SetUnauthorizedHandler(s.Refresh)
	return nil
}

func (s *Service) saveTokens(tokens tokenResponse) error {
	if err := s.store.SaveAuthToken(tokens.AuthToken); err != nil {
		return fmt.Errorf("save auth token: %w", err)
	}
	if err := s.store.SaveRefreshToken(tokens.RefreshToken); err != nil {
		return fmt.Errorf("save refresh token: %w", err)
	}
	return nil
}

func sentinelError(statusCode int, err error) error {
	if err == nil {
		return nil
	}
	var apiErr *client.APIError
	if errors.As(err, &apiErr) {
		return &HTTPStatusError{StatusCode: apiErr.StatusCode}
	}
	if statusCode != 0 && statusCode != http.StatusOK {
		return &HTTPStatusError{StatusCode: statusCode}
	}
	return err
}

func validateTokenResponse(tokens tokenResponse) error {
	if tokens.AuthToken == "" || tokens.RefreshToken == "" {
		return errors.New("authentication response did not contain both tokens")
	}
	return nil
}

type passwordAuthRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Pool     string `json:"pool"`
}

type refreshRequest struct {
	Token string `json:"token"`
}

type tokenResponse struct {
	AuthToken    string `json:"auth_token"`
	RefreshToken string `json:"refresh_token"`
}
