package proxy

import (
	"context"
	"net/url"

	"github.com/mysteriumnetwork/mysteriumvpncli/internal/client"
)

const disconnectEndpoint = "/connection/disconnect"

// DisconnectRequest records the connection identified by its WireGuard public key.
type DisconnectRequest struct {
	PublicKey string
}

// Disconnect closes the proxy connection associated with publicKey.
func Disconnect(ctx context.Context, apiClient *client.Client, publicKey string) error {
	query := url.Values{"public_key": []string{publicKey}}
	return apiClient.Get(ctx, disconnectEndpoint+"?"+query.Encode(), nil)
}
