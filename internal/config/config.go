// Package config defines shared application configuration.
package config

import (
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultAPIURL           = "https://api.mysteriumvpn.com/api/v1"
	DefaultAuthClientID     = "cli"
	DefaultAuthorizationURL = "https://app.mysteriumvpn.com/oauth/authorize"
	DefaultTimeout          = 30 * time.Second
	DefaultAuthPollInterval = 10 * time.Second
	DefaultAuthTimeout      = 5 * time.Minute
)

// Config contains settings shared by CLI commands.
type Config struct {
	APIURL           string
	AuthClientID     string
	AuthorizationURL string
	AuthPollInterval time.Duration
	AuthTimeout      time.Duration
	Debug            bool
	Timeout          time.Duration
}

// Load returns the application's built-in configuration.
func Load() Config {
	return Config{
		APIURL:           DefaultAPIURL,
		AuthClientID:     DefaultAuthClientID,
		AuthorizationURL: DefaultAuthorizationURL,
		AuthPollInterval: DefaultAuthPollInterval,
		AuthTimeout:      DefaultAuthTimeout,
		Debug:            debugEnabled(),
		Timeout:          DefaultTimeout,
	}
}

func debugEnabled() bool {
	enabled, err := strconv.ParseBool(strings.TrimSpace(os.Getenv("MYSTVPN_DEBUG")))
	return err == nil && enabled
}
