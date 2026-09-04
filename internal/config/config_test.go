package config

import (
	"testing"
)

func TestLoadDefaults(t *testing.T) {
	cfg := Load()

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
