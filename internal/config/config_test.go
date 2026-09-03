package config

import (
	"flag"
	"io"
	"testing"
)

func TestLoadDefaults(t *testing.T) {
	flags := flag.NewFlagSet("test", flag.ContinueOnError)
	flags.SetOutput(io.Discard)

	cfg, err := Load(flags, nil)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.APIURL != DefaultAPIURL {
		t.Errorf("APIURL = %q, want %q", cfg.APIURL, DefaultAPIURL)
	}
	if cfg.Debug {
		t.Error("Debug = true, want false")
	}
	if cfg.Timeout != DefaultTimeout {
		t.Errorf("Timeout = %v, want %v", cfg.Timeout, DefaultTimeout)
	}
}

func TestLoadOverrides(t *testing.T) {
	flags := flag.NewFlagSet("test", flag.ContinueOnError)
	flags.SetOutput(io.Discard)

	cfg, err := Load(flags, []string{"--api-url", "https://vpn.example/api/v1", "--debug", "status"})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.APIURL != "https://vpn.example/api/v1" {
		t.Errorf("APIURL = %q, want override", cfg.APIURL)
	}
	if !cfg.Debug {
		t.Error("Debug = false, want true")
	}
	if got := flags.Args(); len(got) != 1 || got[0] != "status" {
		t.Errorf("remaining args = %v, want [status]", got)
	}
}
