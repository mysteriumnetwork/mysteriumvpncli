package config

import (
	"fmt"

	"github.com/mysteriumnetwork/mysteriumvpncli/internal/proxy"
)

// Settings defines the user-editable config schema. JSON field names are also
// the keys accepted by config get/set/unset; adding a field exposes it there
// automatically. Keep built-in values in DefaultSettings below.
type Settings struct {
	Country string `json:"country,omitempty"`
	IPType  string `json:"ip_type,omitempty"`
}

// DefaultSettings is the single place to define built-in connection defaults.
// Return a fresh value so callers cannot modify the defaults for other commands.
func DefaultSettings() Settings {
	return Settings{
		Country: "DE",
		IPType:  "residential",
	}
}

// Normalize validates configured values and normalizes country codes.
func (s *Settings) Normalize() error {
	country, err := proxy.ParseCountry(s.Country)
	if err != nil {
		return fmt.Errorf("country: %w", err)
	}
	s.Country = country
	if _, err := proxy.ParseIPType(s.IPType); err != nil {
		return fmt.Errorf("ip_type: %w", err)
	}
	return nil
}
