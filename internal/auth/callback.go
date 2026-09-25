package auth

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

const callbackPath = "/auth/callback"

// CallbackResult contains the non-token values returned by the browser redirect.
type CallbackResult struct {
	AuthorizationCode string
	State             string
	Nonce             string
}

// LoopbackCallback owns a temporary HTTP listener bound only to IPv4 loopback.
type LoopbackCallback struct {
	listener net.Listener

	mu     sync.Mutex
	server *http.Server
}

// NewLoopbackCallback reserves a random loopback port for an authentication callback.
func NewLoopbackCallback() (*LoopbackCallback, error) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen for authentication callback: %w", err)
	}
	return &LoopbackCallback{listener: listener}, nil
}

// URL returns the callback URL to send to the authentication backend.
func (c *LoopbackCallback) URL() string {
	return fmt.Sprintf("http://%s%s", c.listener.Addr().String(), callbackPath)
}

// Wait serves the callback endpoint until a valid code arrives or ctx expires.
func (c *LoopbackCallback) Wait(ctx context.Context, expectedState, expectedNonce string) (CallbackResult, error) {
	if expectedState == "" || expectedNonce == "" {
		return CallbackResult{}, errors.New("callback state and nonce must not be empty")
	}

	results := make(chan CallbackResult, 1)
	var completed atomic.Bool
	mux := http.NewServeMux()
	mux.HandleFunc(callbackPath, func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Cache-Control", "no-store")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		if request.Method != http.MethodGet {
			writer.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		query := request.URL.Query()
		result := CallbackResult{
			AuthorizationCode: query.Get("code"),
			State:             query.Get("state"),
			Nonce:             query.Get("nonce"),
		}
		if subtle.ConstantTimeCompare([]byte(result.State), []byte(expectedState)) != 1 ||
			subtle.ConstantTimeCompare([]byte(result.Nonce), []byte(expectedNonce)) != 1 {
			http.Error(writer, "invalid authentication callback", http.StatusBadRequest)
			return
		}
		if result.AuthorizationCode == "" {
			http.Error(writer, "authorization code is missing", http.StatusBadRequest)
			return
		}

		if !completed.CompareAndSwap(false, true) {
			writer.WriteHeader(http.StatusConflict)
			return
		}
		writer.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(writer, "<!doctype html><title>Authentication complete</title><p>Authentication received. You can close this window.</p>")
		if flusher, ok := writer.(http.Flusher); ok {
			flusher.Flush()
		}
		results <- result
	})

	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	c.mu.Lock()
	if c.server != nil {
		c.mu.Unlock()
		return CallbackResult{}, errors.New("authentication callback listener already started")
	}
	c.server = server
	c.mu.Unlock()

	serveErrors := make(chan error, 1)
	go func() {
		serveErrors <- server.Serve(c.listener)
	}()

	select {
	case result := <-results:
		return result, nil
	case err := <-serveErrors:
		if errors.Is(err, http.ErrServerClosed) {
			return CallbackResult{}, errors.New("authentication callback listener closed")
		}
		return CallbackResult{}, fmt.Errorf("serve authentication callback: %w", err)
	case <-ctx.Done():
		return CallbackResult{}, fmt.Errorf("wait for authentication callback: %w", ctx.Err())
	}
}

// Close stops the callback server and releases its loopback port.
func (c *LoopbackCallback) Close() error {
	c.mu.Lock()
	server := c.server
	c.mu.Unlock()
	if server != nil {
		if err := server.Close(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("close authentication callback server: %w", err)
		}
		return nil
	}
	if err := c.listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		return fmt.Errorf("close authentication callback listener: %w", err)
	}
	return nil
}
