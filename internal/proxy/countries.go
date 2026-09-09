// Package proxy provides access to the proxy API.
package proxy

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/mysteriumnetwork/mysteriumvpncli/internal/client"
)

// ParseCountry normalizes and validates an ISO-style two-letter country code.
func ParseCountry(value string) (string, error) {
	country := strings.ToUpper(strings.TrimSpace(value))
	if len(country) != 2 || country[0] < 'A' || country[0] > 'Z' || country[1] < 'A' || country[1] > 'Z' {
		return "", errors.New("country must be a two-letter code")
	}
	return country, nil
}

const connectionConfigEndpoint = "/connection/config"

// IPType identifies the requested class of proxy IP addresses.
type IPType string

const (
	IPTypeResidential IPType = "residential"
	IPTypeHosting     IPType = "hosting"
)

// ConnectionConfig is the country data returned by the proxy configuration endpoint.
type ConnectionConfig struct {
	Countries    []string `json:"countries"`
	TopCountries []string `json:"top_countries"`
}

// ParseIPType validates and converts a command-line IP type.
func ParseIPType(value string) (IPType, error) {
	switch IPType(value) {
	case IPTypeResidential:
		return IPTypeResidential, nil
	case IPTypeHosting:
		return IPTypeHosting, nil
	default:
		return "", fmt.Errorf("ip type must be %q or %q", IPTypeResidential, IPTypeHosting)
	}
}

// GetConnectionConfig fetches the available countries for an IP type.
func GetConnectionConfig(ctx context.Context, apiClient *client.Client, ipType IPType) (ConnectionConfig, error) {
	query := url.Values{"ip_type": []string{string(ipType)}}
	endpoint := connectionConfigEndpoint + "?" + query.Encode()

	var response ConnectionConfig
	if err := apiClient.Get(ctx, endpoint, &response); err != nil {
		return ConnectionConfig{}, err
	}
	return response, nil
}
