package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

type authTestTransport func(*http.Request) (*http.Response, error)

func (f authTestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestStartUnavailableBrowserClearsPending(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
	defer server.Close()
	store := &memoryCredentialStore{}
	service := newTestService(t, server.URL, store)
	service.options.AuthorizationURL = server.URL + "/oauth/authorize"
	result, err := service.Start(context.Background())
	if err == nil || result.AuthorizationURL != "" {
		t.Fatalf("result=%+v, error=%v", result, err)
	}
	assertPendingCleared(t, store)
}
