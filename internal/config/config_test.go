package config

import (
	"testing"
)

func TestLoadDefaults(t *testing.T) {
	cfg := Load()

	if DefaultAPIURL != "https://api.mysteriumvpn.com/api/v1" {
		t.Errorf("DefaultAPIURL = %q", DefaultAPIURL)
	}
	if DefaultSentinelURL != "https://sentinel.mysterium.network/api/v1" {
		t.Errorf("DefaultSentinelURL = %q", DefaultSentinelURL)
	}
	if DefaultPool != "dvpn" {
		t.Errorf("DefaultPool = %q", DefaultPool)
	}
	if cfg.APIURL != DefaultAPIURL {
		t.Errorf("APIURL = %q, want %q", cfg.APIURL, DefaultAPIURL)
	}
	if cfg.SentinelURL != DefaultSentinelURL {
		t.Errorf("SentinelURL = %q, want %q", cfg.SentinelURL, DefaultSentinelURL)
	}
	if cfg.Pool != DefaultPool {
		t.Errorf("Pool = %q, want %q", cfg.Pool, DefaultPool)
	}
	if cfg.Debug {
		t.Error("Debug = true, want false")
	}
	if cfg.Timeout != DefaultTimeout {
		t.Errorf("Timeout = %v, want %v", cfg.Timeout, DefaultTimeout)
	}
}
