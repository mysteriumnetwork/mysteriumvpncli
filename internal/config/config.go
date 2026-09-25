// Package config defines shared application configuration.
package config

import (
	"time"
)

const (
	DefaultAPIURL          = "https://api.mysteriumvpn.com/api/v1"
	DefaultSentinelURL     = "https://sentinel.mysterium.network/api/v1"
	DefaultPool            = "dvpn"
	DefaultTimeout         = 30 * time.Second
	DefaultAuthCallbackURL = "http://127.0.0.1:53682/auth/callback"
	DefaultPendingAuthTTL  = 10 * time.Minute
)

// Config contains settings shared by CLI commands.
type Config struct {
	APIURL          string
	SentinelURL     string
	Pool            string
	AuthCallbackURL string
	PendingAuthTTL  time.Duration
	Debug           bool
	Timeout         time.Duration
}

// Load returns the application's built-in configuration.
func Load() Config {
	return Config{
		APIURL:          DefaultAPIURL,
		SentinelURL:     DefaultSentinelURL,
		Pool:            DefaultPool,
		AuthCallbackURL: DefaultAuthCallbackURL,
		PendingAuthTTL:  DefaultPendingAuthTTL,
		Timeout:         DefaultTimeout,
	}
}
