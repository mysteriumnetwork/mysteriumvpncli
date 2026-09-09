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

func TestConnect(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", request.Method)
		}
		if request.URL.Path != "/api/v1/connection/connect" {
			t.Errorf("path = %q, want /api/v1/connection/connect", request.URL.Path)
		}
		if got := request.Header.Get("Authorization"); got != "Bearer auth-value" {
			t.Errorf("Authorization = %q, want bearer token", got)
		}

		var body ConnectRequest
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if body.PublicKey != "public-value" || body.Country != "DE" || body.IPType != IPTypeResidential || body.OSType != OSTypeLinux || !body.ResetConnection {
			t.Errorf("request body = %+v, want connect parameters", body)
		}

		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{
			"id":"conn-abc123",
			"wg_config":"[Interface]\nPrivateKey=%private_key%\n",
			"hash":"hash-value",
			"exit_ip":"1.2.3.4",
			"limit_exceeded":false,
			"ip_type":"residential",
			"country":"DE",
			"city":"berlin",
			"ignored":"value"
		}`))
	}))
	defer server.Close()

	apiClient, err := client.New(server.URL+"/api/v1", time.Second, false)
	if err != nil {
		t.Fatalf("client.New() error = %v", err)
	}
	apiClient.SetToken("auth-value")

	response, err := Connect(context.Background(), apiClient, ConnectRequest{
		PublicKey:       "public-value",
		Country:         "DE",
		IPType:          IPTypeResidential,
		OSType:          OSTypeLinux,
		ResetConnection: true,
	})
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	if response.ID != "conn-abc123" || response.ExitIP != "1.2.3.4" || response.Country != "DE" || response.City != "berlin" {
		t.Errorf("response = %+v, want connection metadata", response)
	}
	if response.WGConfig != "[Interface]\nPrivateKey=%private_key%\n" {
		t.Errorf("WGConfig = %q, want decoded config", response.WGConfig)
	}
}
