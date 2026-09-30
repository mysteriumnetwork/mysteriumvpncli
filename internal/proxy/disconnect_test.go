package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mysteriumnetwork/mysteriumvpncli/internal/client"
)

func TestDisconnect(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			t.Errorf("method = %s, want GET", request.Method)
		}
		if request.URL.Path != "/api/v1/connection/disconnect" {
			t.Errorf("path = %q, want disconnect endpoint", request.URL.Path)
		}
		if got := request.Header.Get("Authorization"); got != "Bearer auth-value" {
			t.Errorf("Authorization = %q, want stored token", got)
		}
		if got := request.URL.Query().Get("public_key"); got != "public+/=value" {
			t.Errorf("public_key = %q, want encoded public key", got)
		}
		if request.ContentLength > 0 {
			t.Errorf("Content-Length = %d, want no request body", request.ContentLength)
		}
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	apiClient, err := client.New(server.URL+"/api/v1", time.Second, false)
	if err != nil {
		t.Fatalf("client.New() error = %v", err)
	}
	apiClient.SetToken("auth-value")

	if err := Disconnect(context.Background(), apiClient, "public+/=value"); err != nil {
		t.Fatalf("Disconnect() error = %v", err)
	}
}
