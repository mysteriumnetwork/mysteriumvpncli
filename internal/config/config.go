// Package config defines shared application configuration.
package config

import (
	"time"
)

const (
	DefaultAPIURL              = "https://api.mysteriumvpn.com/api/v1"
	DefaultSentinelURL         = "https://sentinel.mysterium.network/api/v1"
	DefaultAuthClientID        = "dvpn"
	DefaultTimeout             = 30 * time.Second
	DefaultAuthCallbackTimeout = 2 * time.Minute
	DefaultPendingAuthTTL      = 10 * time.Minute
)

// Config contains settings shared by CLI commands.
type Config struct {
	APIURL              string
	SentinelURL         string
	AuthClientID        string
	AuthCallbackTimeout time.Duration
	PendingAuthTTL      time.Duration
	Debug               bool
	Timeout             time.Duration
}

// Load returns the application's built-in configuration.
func Load() Config {
	return Config{
		APIURL:              DefaultAPIURL,
		SentinelURL:         DefaultSentinelURL,
		AuthClientID:        DefaultAuthClientID,
		AuthCallbackTimeout: DefaultAuthCallbackTimeout,
		PendingAuthTTL:      DefaultPendingAuthTTL,
		Timeout:             DefaultTimeout,
	}
}
