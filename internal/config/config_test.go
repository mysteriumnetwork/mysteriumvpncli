package config

import (
	"testing"
	"time"
)

func TestLoadDefaults(t *testing.T) {
	cfg := Load()

	if DefaultAPIURL != "https://api.mysteriumvpn.com/api/v1" {
		t.Errorf("DefaultAPIURL = %q", DefaultAPIURL)
	}
	if DefaultSentinelURL != "https://sentinel.mysterium.network/api/v1" {
		t.Errorf("DefaultSentinelURL = %q", DefaultSentinelURL)
	}
	if DefaultAuthClientID != "dvpn" {
		t.Errorf("DefaultAuthClientID = %q", DefaultAuthClientID)
	}
	if DefaultAuthCallbackTimeout != 2*time.Minute {
		t.Errorf("DefaultAuthCallbackTimeout = %v", DefaultAuthCallbackTimeout)
	}
	if DefaultPendingAuthTTL != 10*time.Minute {
		t.Errorf("DefaultPendingAuthTTL = %v", DefaultPendingAuthTTL)
	}
	if cfg.APIURL != DefaultAPIURL {
		t.Errorf("APIURL = %q, want %q", cfg.APIURL, DefaultAPIURL)
	}
	if cfg.SentinelURL != DefaultSentinelURL {
		t.Errorf("SentinelURL = %q, want %q", cfg.SentinelURL, DefaultSentinelURL)
	}
	if cfg.AuthClientID != DefaultAuthClientID {
		t.Errorf("AuthClientID = %q, want %q", cfg.AuthClientID, DefaultAuthClientID)
	}
	if cfg.AuthCallbackTimeout != DefaultAuthCallbackTimeout {
		t.Errorf("AuthCallbackTimeout = %v, want %v", cfg.AuthCallbackTimeout, DefaultAuthCallbackTimeout)
	}
	if cfg.PendingAuthTTL != DefaultPendingAuthTTL {
		t.Errorf("PendingAuthTTL = %v, want %v", cfg.PendingAuthTTL, DefaultPendingAuthTTL)
	}
	if cfg.Debug {
		t.Error("Debug = true, want false")
	}
	if cfg.Timeout != DefaultTimeout {
		t.Errorf("Timeout = %v, want %v", cfg.Timeout, DefaultTimeout)
	}
}
