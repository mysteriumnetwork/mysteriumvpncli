// Package mockserver provides a deterministic local API for end-to-end tests.
package mockserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"

	"github.com/mysteriumnetwork/mysteriumvpncli/internal/proxy"
)

const (
	authToken    = "test-auth-token"
	refreshToken = "test-refresh-token"
)

// Snapshot contains the non-sensitive requests observed by a Server.
type Snapshot struct {
	AuthCalls           int
	ActivationPollCalls int
	TokenRefreshCalls   int
	CountryQueries      []string
	ConnectRequests     []proxy.ConnectRequest
	DisconnectRequests  []proxy.DisconnectRequest
}

// Server is a stateful auth-compatible and proxy-compatible test server.
type Server struct {
	server *httptest.Server

	mu                  sync.Mutex
	authStatus          int
	connectStatus       int
	disconnectStatus    int
	unauthorizedProxy   int
	authCalls           int
	activationPollCalls int
	tokenRefreshCalls   int
	pendingActivationID string
	countryQueries      []string
	connectRequests     []proxy.ConnectRequest
	successfulConnects  int
	disconnectRequests  []proxy.DisconnectRequest
}

// New starts a local mock API server.
func New() *Server {
	server := &Server{}
	server.server = httptest.NewServer(http.HandlerFunc(server.serveHTTP))
	return server
}

// Close stops the local server.
func (s *Server) Close() {
	s.server.Close()
}

// APIURL returns the versioned base URL used by proxy requests.
func (s *Server) APIURL() string {
	return s.server.URL + "/api/v1"
}

// SetAuthStatus overrides the activation creation response status. Zero restores success.
func (s *Server) SetAuthStatus(statusCode int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.authStatus = statusCode
}

// SetConnectStatus overrides connection responses. Zero restores success.
func (s *Server) SetConnectStatus(statusCode int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.connectStatus = statusCode
}

// SetDisconnectStatus overrides disconnect responses. Zero restores success.
func (s *Server) SetDisconnectStatus(statusCode int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.disconnectStatus = statusCode
}

// RejectNextProxyRequest makes the next otherwise-authorized proxy call return 401.
func (s *Server) RejectNextProxyRequest() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.unauthorizedProxy++
}

// Snapshot returns a race-safe copy of the recorded requests.
func (s *Server) Snapshot() Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Snapshot{
		AuthCalls:           s.authCalls,
		ActivationPollCalls: s.activationPollCalls,
		TokenRefreshCalls:   s.tokenRefreshCalls,
		CountryQueries:      append([]string(nil), s.countryQueries...),
		ConnectRequests:     append([]proxy.ConnectRequest(nil), s.connectRequests...),
		DisconnectRequests:  append([]proxy.DisconnectRequest(nil), s.disconnectRequests...),
	}
}

func (s *Server) serveHTTP(writer http.ResponseWriter, request *http.Request) {
	switch {
	case request.URL.Path == "/api/v1/auth/activation" && request.Method == http.MethodPost:
		s.handleActivationStart(writer, request)
	case strings.HasPrefix(request.URL.Path, "/api/v1/auth/activation/") && request.Method == http.MethodGet:
		s.handleActivationPoll(writer, request)
	case request.URL.Path == "/api/v1/oauth/token":
		s.handleOAuthToken(writer, request)
	case request.URL.Path == "/api/v1/connection/config":
		s.handleCountries(writer, request)
	case request.URL.Path == "/api/v1/connection/connect":
		s.handleConnect(writer, request)
	case request.URL.Path == "/api/v1/connection/disconnect":
		s.handleDisconnect(writer, request)
	default:
		http.NotFound(writer, request)
	}
}

func (s *Server) handleActivationStart(writer http.ResponseWriter, request *http.Request) {
	var body struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(request.Body).Decode(&body); err != nil || body.ID == "" {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	s.authCalls++
	s.pendingActivationID = body.ID
	statusCode := s.authStatus
	s.mu.Unlock()
	if statusCode != 0 && statusCode != http.StatusOK && statusCode != http.StatusNoContent {
		writer.WriteHeader(statusCode)
		return
	}
	if statusCode == http.StatusNoContent {
		writer.WriteHeader(http.StatusNoContent)
		return
	}
	writer.WriteHeader(http.StatusOK)
}

func (s *Server) handleActivationPoll(writer http.ResponseWriter, request *http.Request) {
	activationID := strings.TrimPrefix(request.URL.Path, "/api/v1/auth/activation/")
	s.mu.Lock()
	if activationID == "" || activationID != s.pendingActivationID {
		s.mu.Unlock()
		writer.WriteHeader(http.StatusNotFound)
		return
	}
	s.activationPollCalls++
	s.mu.Unlock()
	writeJSON(writer, http.StatusOK, map[string]any{
		"id":    activationID,
		"valid": true,
		"token": map[string]any{
			"access_token":  authToken,
			"refresh_token": refreshToken,
			"token_type":    "Bearer",
			"expires_in":    3600,
			"user_id":       "test-user",
		},
	})
}

func (s *Server) handleOAuthToken(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writer.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var body map[string]string
	if err := json.NewDecoder(request.Body).Decode(&body); err != nil || len(body) != 3 || body["client_id"] != "cli" || body["grant_type"] != "refresh_token" || body["refresh_token"] != refreshToken {
		writer.WriteHeader(http.StatusUnauthorized)
		return
	}

	s.mu.Lock()
	s.tokenRefreshCalls++
	s.mu.Unlock()
	writeJSON(writer, http.StatusOK, map[string]any{
		"access_token":  authToken,
		"refresh_token": refreshToken,
		"token_type":    "Bearer",
		"expires_in":    3600,
		"user_id":       "test-user",
	})
}

func (s *Server) handleCountries(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		writer.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !s.authorized(request) {
		writer.WriteHeader(http.StatusUnauthorized)
		return
	}
	ipType := request.URL.Query().Get("ip_type")
	if ipType != string(proxy.IPTypeResidential) && ipType != string(proxy.IPTypeHosting) {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	s.countryQueries = append(s.countryQueries, ipType)
	s.mu.Unlock()
	writeJSON(writer, http.StatusOK, map[string]any{
		"countries":     []string{"SE", "DE", "CA"},
		"top_countries": []string{"SE"},
	})
}

func (s *Server) handleConnect(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writer.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !s.authorized(request) {
		writer.WriteHeader(http.StatusUnauthorized)
		return
	}
	var body proxy.ConnectRequest
	if err := json.NewDecoder(request.Body).Decode(&body); err != nil || body.PublicKey == "" || body.Country == "" || body.IPType == "" || body.OSType != proxy.OSTypeLinux {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	s.connectRequests = append(s.connectRequests, body)
	statusCode := s.connectStatus
	s.mu.Unlock()
	if statusCode != 0 && statusCode != http.StatusOK {
		writer.WriteHeader(statusCode)
		return
	}
	s.mu.Lock()
	s.successfulConnects++
	connectionNumber := s.successfulConnects
	s.mu.Unlock()

	exitIP := "1.2.3.4"
	city := "berlin"
	if connectionNumber > 1 {
		exitIP = "2.3.4.5"
		city = "hamburg"
	}
	writeJSON(writer, http.StatusOK, map[string]any{
		"id":        fmt.Sprintf("connection-%d", connectionNumber),
		"wg_config": fmt.Sprintf("[Interface]\nPrivateKey=%%private_key%%\nAddress=10.10.0.%d/24\n\n[Peer]\nPublicKey=peer-value\nEndpoint=%s:51820\nAllowedIPs=0.0.0.0/0\n", connectionNumber+1, exitIP),
		"exit_ip":   exitIP,
		"ip_type":   body.IPType,
		"country":   body.Country,
		"city":      city,
	})
}

func (s *Server) handleDisconnect(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		writer.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !s.authorized(request) {
		writer.WriteHeader(http.StatusUnauthorized)
		return
	}
	publicKey := request.URL.Query().Get("public_key")
	if publicKey == "" {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	s.disconnectRequests = append(s.disconnectRequests, proxy.DisconnectRequest{PublicKey: publicKey})
	statusCode := s.disconnectStatus
	s.mu.Unlock()
	if statusCode != 0 && statusCode != http.StatusNoContent {
		writer.WriteHeader(statusCode)
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (s *Server) authorized(request *http.Request) bool {
	if request.Header.Get("Authorization") != "Bearer "+authToken {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.unauthorizedProxy > 0 {
		s.unauthorizedProxy--
		return false
	}
	return true
}

func writeJSON(writer http.ResponseWriter, statusCode int, body any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(statusCode)
	_ = json.NewEncoder(writer).Encode(body)
}
