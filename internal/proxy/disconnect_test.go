package proxy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mysteriumnetwork/mysteriumvpncli/internal/client"
)

func TestDisconnect(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", request.Method)
		}
		if request.URL.Path != "/api/v1/connection/disconnect" {
			t.Errorf("path = %q, want disconnect endpoint", request.URL.Path)
		}
		if got := request.Header.Get("Authorization"); got != "Bearer auth-value" {
			t.Errorf("Authorization = %q, want stored token", got)
		}

		var body DisconnectRequest
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if body.PublicKey != "public-value" {
			t.Errorf("public key = %q, want public-value", body.PublicKey)
		}
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	apiClient, err := client.New(server.URL+"/api/v1", time.Second, false)
	if err != nil {
		t.Fatalf("client.New() error = %v", err)
	}
	apiClient.SetToken("auth-value")

	if err := Disconnect(context.Background(), apiClient, "public-value"); err != nil {
		t.Fatalf("Disconnect() error = %v", err)
	}
}
