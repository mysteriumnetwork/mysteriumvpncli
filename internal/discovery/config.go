// Package discovery loads domain alternatives used when an API is unavailable.
package discovery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const maxConfigSize = 1 << 20

// DefaultSources are tried in order. Additional mirrors can be appended.
var DefaultSources = []string{
	"https://static-resources-hub.github.io/config.json",
	"https://raw.githubusercontent.com/static-resources-hub/static-resources-hub.github.io/main/config.json",
}

// Config is the discovery envelope. Signatures are intentionally ignored for now.
type Config struct {
	Signed SignedConfig `json:"signed"`
}

// SignedConfig describes versioned domain mappings.
type SignedConfig struct {
	SchemaVersion int                 `json:"schema_version"`
	Version       int                 `json:"version"`
	IssuedAt      time.Time           `json:"issued_at"`
	ExpiresAt     time.Time           `json:"expires_at"`
	Mappings      map[string][]string `json:"mappings"`
}

// Parse validates the envelope and supported schema while allowing future fields.
// Expired configurations remain usable for offline recovery.
func Parse(data []byte) (Config, error) {
	var cfg Config
	if len(data) > maxConfigSize {
		return cfg, errors.New("discovery config exceeds 1 MiB limit")
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("decode discovery config: %w", err)
	}
	s := cfg.Signed
	if s.SchemaVersion != 1 {
		return cfg, fmt.Errorf("unsupported discovery schema version %d", s.SchemaVersion)
	}
	if s.Version < 1 || s.IssuedAt.IsZero() || !s.ExpiresAt.After(s.IssuedAt) || s.Mappings == nil {
		return cfg, errors.New("incomplete discovery config")
	}
	for host, alternatives := range s.Mappings {
		if !validDomain(host) || len(alternatives) == 0 {
			return cfg, errors.New("invalid discovery mapping")
		}
		for _, alternative := range alternatives {
			if !validDomain(alternative) {
				return cfg, fmt.Errorf("invalid discovery domain %q", alternative)
			}
		}
	}
	return cfg, nil
}

func validDomain(host string) bool {
	if len(host) > 253 || !strings.Contains(host, ".") || net.ParseIP(host) != nil {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, ch := range label {
			if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
				return false
			}
		}
	}
	return true
}

// Loader serializes refreshes and keeps the last valid configuration in memory
// and on disk. Configure its exported fields before using it concurrently.
type Loader struct {
	Sources         []string
	HTTPClient      *http.Client
	CachePath       string
	RefreshInterval time.Duration
	mu              sync.Mutex
	config          Config
	loaded          bool
	lastAttempt     time.Time
}

// New creates a loader. An empty cache path disables persistence.
func New(cachePath string) *Loader {
	return &Loader{Sources: append([]string(nil), DefaultSources...), HTTPClient: &http.Client{Timeout: 3 * time.Second}, CachePath: cachePath, RefreshInterval: time.Hour}
}

// NewDefault stores discovery data alongside the application's configuration.
func NewDefault() *Loader {
	directory, err := os.UserConfigDir()
	if err != nil {
		return New("")
	}
	return New(filepath.Join(directory, "mystvpn", "discovery.json"))
}

// Fallbacks refreshes on demand, at most once per interval, and returns a copy
// of the alternatives. Failed refreshes never discard the previous list.
func (l *Loader) Fallbacks(ctx context.Context, host string) []string {
	host = strings.ToLower(host)
	if !validDomain(host) || ctx.Err() != nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.loadCache()
	if l.lastAttempt.IsZero() || time.Since(l.lastAttempt) >= l.RefreshInterval {
		l.lastAttempt = time.Now()
		l.refresh(ctx)
	}
	alternatives := l.config.Signed.Mappings[host]
	return append([]string(nil), alternatives...)
}

// CachedFallbacks returns the last valid mappings without contacting discovery
// sources, even when the on-disk configuration is expired.
func (l *Loader) CachedFallbacks(host string) []string {
	host = strings.ToLower(host)
	if !validDomain(host) {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.loadCache()
	return append([]string(nil), l.config.Signed.Mappings[host]...)
}

// loadCache requires l.mu to be held.
func (l *Loader) loadCache() {
	if !l.loaded {
		l.loaded = true
		if data, err := os.ReadFile(l.CachePath); err == nil {
			if cfg, err := Parse(data); err == nil {
				l.config = cfg
				if info, err := os.Stat(l.CachePath); err == nil && time.Now().Before(cfg.Signed.ExpiresAt) {
					l.lastAttempt = info.ModTime()
				}
			}
		}
	}
}

func (l *Loader) refresh(ctx context.Context) {
	for _, source := range l.Sources {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
		if err != nil {
			continue
		}
		response, err := l.HTTPClient.Do(request)
		if err != nil {
			continue
		}
		data, readErr := io.ReadAll(io.LimitReader(response.Body, maxConfigSize+1))
		response.Body.Close()
		if response.StatusCode != http.StatusOK || readErr != nil {
			continue
		}
		cfg, err := Parse(data)
		if err != nil {
			continue
		}
		l.config = cfg
		// A write failure must not prevent using a successfully fetched config.
		_ = l.save(data)
		return
	}
}

func (l *Loader) save(data []byte) error {
	if l.CachePath == "" {
		return nil
	}
	directory := filepath.Dir(l.CachePath)
	if err := os.MkdirAll(directory, 0700); err != nil {
		return err
	}
	file, err := os.CreateTemp(directory, ".discovery-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if _, err = file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), l.CachePath)
}
