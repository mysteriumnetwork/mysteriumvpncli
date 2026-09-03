// Package config defines shared application configuration.
package config

import (
	"flag"
	"time"
)

const (
	DefaultAPIURL  = "https://api.example.com/api/v1"
	DefaultTimeout = 30 * time.Second
)

// Config contains settings shared by CLI commands.
type Config struct {
	APIURL  string
	Debug   bool
	Timeout time.Duration
}

// Load registers configuration flags on flags, parses args, and returns the
// resulting configuration. Callers may register command-specific flags first.
func Load(flags *flag.FlagSet, args []string) (Config, error) {
	cfg := Config{
		APIURL:  DefaultAPIURL,
		Timeout: DefaultTimeout,
	}

	flags.StringVar(&cfg.APIURL, "api-url", cfg.APIURL, "base URL for the API")
	flags.BoolVar(&cfg.Debug, "debug", false, "enable debug logging")

	if err := flags.Parse(args); err != nil {
		return Config{}, err
	}

	return cfg, nil
}
