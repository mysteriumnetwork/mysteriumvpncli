package main

import (
	"github.com/mysteriumnetwork/mysteriumvpncli/internal/client"
	"github.com/mysteriumnetwork/mysteriumvpncli/internal/config"
	"github.com/mysteriumnetwork/mysteriumvpncli/internal/discovery"
	"os"
	"path/filepath"
)

// Share discovery state across API and authentication clients.
var discoveryLoader = discovery.NewDefault()

func newAPIClient(cfg config.Config) (*client.Client, error) {
	apiClient, err := client.New(cfg.APIURL, cfg.Timeout, cfg.Debug)
	if err == nil {
		apiClient.Discovery = discoveryLoader
		if directory, err := os.UserConfigDir(); err == nil {
			apiClient.DomainState = client.NewDomainState(filepath.Join(directory, "mystvpn", "domain-state.json"))
		}
	}
	return apiClient, err
}
