package proxy

import (
	"context"

	"github.com/mysteriumnetwork/mysteriumvpncli/internal/client"
)

const (
	connectEndpoint = "/connection/connect"
	// OSTypeLinux identifies Linux clients in connection requests.
	OSTypeLinux = "linux"
)

// ConnectRequest contains the parameters required to create a proxy connection.
type ConnectRequest struct {
	PublicKey       string `json:"public_key"`
	Country         string `json:"country"`
	IPType          IPType `json:"ip_type"`
	OSType          string `json:"os_type"`
	ResetConnection bool   `json:"reset_connection"`
}

// ConnectResponse contains the WireGuard configuration and connection metadata.
type ConnectResponse struct {
	ID            string `json:"id"`
	WGConfig      string `json:"wg_config"`
	Hash          string `json:"hash"`
	ExitIP        string `json:"exit_ip"`
	LimitExceeded bool   `json:"limit_exceeded"`
	IPType        IPType `json:"ip_type"`
	Country       string `json:"country"`
	City          string `json:"city"`
}

// Connect requests a WireGuard connection configuration from the proxy API.
func Connect(ctx context.Context, apiClient *client.Client, request ConnectRequest) (ConnectResponse, error) {
	var response ConnectResponse
	if err := apiClient.Post(ctx, connectEndpoint, request, &response); err != nil {
		return ConnectResponse{}, err
	}
	return response, nil
}
