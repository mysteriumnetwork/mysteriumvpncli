package proxy

import (
	"context"
	"net/url"

	"github.com/mysteriumnetwork/mysteriumvpncli/internal/client"
)

// ConnectionLocation groups city/state identifiers under their country.
// The API uses city for both cities and states; preserve identifiers verbatim.
type ConnectionLocation struct {
	Country     string           `json:"country"`
	Cities      []ConnectionCity `json:"cities"`
	IsAvailable *bool            `json:"is_available"`
}

// ConnectionCity is a city or state target with optional availability metadata.
type ConnectionCity struct {
	City        string `json:"city"`
	IsAvailable *bool  `json:"is_available"`
}

// GetConnectionLocations fetches city/state targets for an IP type.
func GetConnectionLocations(ctx context.Context, apiClient *client.Client, ipType IPType) ([]ConnectionLocation, error) {
	query := url.Values{"ip_type": {string(ipType)}}
	var response []ConnectionLocation
	if err := apiClient.Get(ctx, "/connection/config/locations?"+query.Encode(), &response); err != nil {
		return nil, err
	}
	return response, nil
}
