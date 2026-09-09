package proxy

import (
	"context"

	"github.com/mysteriumnetwork/mysteriumvpncli/internal/client"
)

const disconnectEndpoint = "/connection/disconnect"

// DisconnectRequest identifies the connection to close by its WireGuard public key.
type DisconnectRequest struct {
	PublicKey string `json:"public_key"`
}

// Disconnect closes the proxy connection associated with publicKey.
func Disconnect(ctx context.Context, apiClient *client.Client, publicKey string) error {
	return apiClient.Post(ctx, disconnectEndpoint, DisconnectRequest{PublicKey: publicKey}, nil)
}
