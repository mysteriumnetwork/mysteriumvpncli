package config

import (
	"testing"
	"time"
)

func TestLoadDefaults(t *testing.T) {
	t.Setenv("MYSTVPN_DEBUG", "")
	cfg := Load()

	if DefaultAPIURL != "https://api.mysteriumvpn.com/api/v1" {
		t.Errorf("DefaultAPIURL = %q", DefaultAPIURL)
	}
	if DefaultAuthClientID != "cli" {
		t.Errorf("DefaultAuthClientID = %q", DefaultAuthClientID)
	}
	if DefaultAuthorizationURL != "https://app.mysteriumvpn.com/oauth/authorize" {
		t.Errorf("DefaultAuthorizationURL = %q", DefaultAuthorizationURL)
	}
	if DefaultAuthPollInterval != 10*time.Second {
		t.Errorf("DefaultAuthPollInterval = %v", DefaultAuthPollInterval)
	}
	if DefaultAuthTimeout != 5*time.Minute {
		t.Errorf("DefaultAuthTimeout = %v", DefaultAuthTimeout)
	}
	if cfg.APIURL != DefaultAPIURL {
		t.Errorf("APIURL = %q, want %q", cfg.APIURL, DefaultAPIURL)
	}
	if cfg.AuthClientID != DefaultAuthClientID {
		t.Errorf("AuthClientID = %q, want %q", cfg.AuthClientID, DefaultAuthClientID)
	}
	if cfg.AuthorizationURL != DefaultAuthorizationURL {
		t.Errorf("AuthorizationURL = %q, want %q", cfg.AuthorizationURL, DefaultAuthorizationURL)
	}
	if cfg.AuthPollInterval != DefaultAuthPollInterval {
		t.Errorf("AuthPollInterval = %v, want %v", cfg.AuthPollInterval, DefaultAuthPollInterval)
	}
	if cfg.AuthTimeout != DefaultAuthTimeout {
		t.Errorf("AuthTimeout = %v, want %v", cfg.AuthTimeout, DefaultAuthTimeout)
	}
	if cfg.Debug {
		t.Error("Debug = true, want false")
	}
	if cfg.Timeout != DefaultTimeout {
		t.Errorf("Timeout = %v, want %v", cfg.Timeout, DefaultTimeout)
	}
}

func TestLoadEnablesDebugFromEnvironment(t *testing.T) {
	t.Setenv("MYSTVPN_DEBUG", "1")

	if cfg := Load(); !cfg.Debug {
		t.Error("Debug = false, want true when MYSTVPN_DEBUG=1")
	}
}

func TestLoadIgnoresInvalidDebugEnvironment(t *testing.T) {
	t.Setenv("MYSTVPN_DEBUG", "not-a-boolean")

	if cfg := Load(); cfg.Debug {
		t.Error("Debug = true, want false for invalid MYSTVPN_DEBUG")
	}
}
