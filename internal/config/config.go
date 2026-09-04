// Package config defines shared application configuration.
package config

import (
	"time"
)

const (
	DefaultAPIURL      = "https://api.example.com/api/v1"
	DefaultSentinelURL = "https://sentinel.mysterium.network"
	DefaultPool        = "default"
	DefaultTimeout     = 30 * time.Second
)

// Config contains settings shared by CLI commands.
type Config struct {
	APIURL      string
	SentinelURL string
	Pool        string
	Debug       bool
	Timeout     time.Duration
}

// Load returns the application's built-in configuration.
func Load() Config {
	return Config{
		APIURL:      DefaultAPIURL,
		SentinelURL: DefaultSentinelURL,
		Pool:        DefaultPool,
		Timeout:     DefaultTimeout,
	}
}
