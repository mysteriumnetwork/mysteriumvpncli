package update

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestVersionComparison(t *testing.T) {
	for _, test := range []struct {
		latest, current string
		want            bool
	}{
		{"v1.10.0", "1.9.9", true},
		{"2.0.0", "v1.99.99", true},
		{"1.2.4+build.1", "1.2.3", true},
		{"1.2.3+build.2", "v1.2.3+build.1", false},
		{"1.2.3", "1.2.4", false},
		{"1.2.3", "dev", false},
		{"1.2.3", "1.2.2-rc.1", false},
		{"1.2.4-rc.1", "1.2.3", false},
		{"01.2.4", "1.2.3", false},
		{"1.2.4\nmalicious output", "1.2.3", false},
		{"1.999999999999999999999999999.0", "1.9.0", true},
	} {
		t.Run(test.latest+"/"+test.current, func(t *testing.T) {
			if got := newer(test.latest, test.current); got != test.want {
				t.Fatalf("newer = %v, want %v", got, test.want)
			}
		})
	}
}

func TestCheckCachesRequestsAndReminders(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Header.Get("Authorization") != "" {
			t.Error("release check sent credentials")
		}
		w.Write([]byte(`{"tag_name":"v1.10.0"}`))
	}))
	defer server.Close()
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	n := Notifier{Path: filepath.Join(t.TempDir(), "mystvpn", "update.json"), URL: server.URL, Now: func() time.Time { return now }}
	if got := n.Check(context.Background(), "1.9.0"); got != "v1.10.0" {
		t.Fatalf("first check = %q", got)
	}
	if got := n.Check(context.Background(), "1.9.0"); got != "" {
		t.Fatalf("duplicate notice = %q", got)
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("requests = %d", got)
	}
	now = now.Add(24 * time.Hour)
	if got := n.Check(context.Background(), "1.9.0"); got != "v1.10.0" {
		t.Fatalf("daily reminder = %q", got)
	}
	if got := requests.Load(); got != 2 {
		t.Fatalf("requests = %d", got)
	}
	now = now.Add(24 * time.Hour)
	if got := n.Check(context.Background(), "1.10.0"); got != "" {
		t.Fatalf("notice after upgrade = %q", got)
	}
	info, err := os.Stat(n.Path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("cache permissions: %v, %v", info, err)
	}
}

func TestCheckIgnoresInvalidReleasesAndThrottlesFailures(t *testing.T) {
	for _, body := range []string{
		`{"tag_name":"1.2.4","draft":true}`,
		`{"tag_name":"1.2.4","prerelease":true}`,
		`{"tag_name":"1.2.4-rc.1"}`,
		`{"tag_name":"1.2.4\u001b[31m"}`,
		`{broken`,
		`rate-limit`,
	} {
		t.Run(body, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if body == "rate-limit" {
					w.WriteHeader(http.StatusForbidden)
				}
				w.Write([]byte(body))
			}))
			defer server.Close()
			n := Notifier{Path: filepath.Join(t.TempDir(), "update.json"), URL: server.URL}
			for range 2 {
				if got := n.Check(context.Background(), "1.2.3"); got != "" {
					t.Fatalf("notice = %q", got)
				}
			}
			if got := requests.Load(); got != 1 {
				t.Fatalf("requests = %d, want 1", got)
			}
		})
	}
}

func TestTimeoutRetainsCachedRelease(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer server.Close()
	now := time.Now()
	n := Notifier{Path: filepath.Join(t.TempDir(), "update.json"), URL: server.URL}
	if !save(n.Path, cache{Checked: now.Add(-48 * time.Hour), Latest: "1.2.4"}) {
		t.Fatal("save failed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if got := n.Check(ctx, "1.2.3"); got != "1.2.4" {
		t.Fatalf("cached notice on timeout = %q", got)
	}
	data, err := os.ReadFile(n.Path)
	if err != nil {
		t.Fatal(err)
	}
	var state cache
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatal(err)
	}
	if state.Checked.Before(now) {
		t.Fatal("failed attempt was not cached")
	}
}

func TestConcurrentCheckSkipsLockedCache(t *testing.T) {
	path := filepath.Join(t.TempDir(), "update.json")
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	n := Notifier{Path: path, URL: "http://127.0.0.1:1"}
	if got := n.Check(context.Background(), "1.2.3"); got != "" {
		t.Fatalf("locked check = %q", got)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("locked cache was modified: %v", err)
	}
}

func TestDevelopmentBuildDoesNotTouchCache(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "update.json")
	n := Notifier{Path: path}
	if got := n.Check(context.Background(), "dev"); got != "" {
		t.Fatalf("notice = %q", got)
	}
	if _, err := os.Stat(filepath.Dir(path)); !os.IsNotExist(err) {
		t.Fatalf("created cache for dev build: %v", err)
	}
}

func TestReadOnlyCacheSkipsNetwork(t *testing.T) {
	// A regular file used as the cache directory also works when tests run as root.
	dir := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(dir, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	n := Notifier{Path: filepath.Join(dir, "update.json")}
	if got := n.Check(context.Background(), "1.2.3"); got != "" {
		t.Fatalf("notice = %q", got)
	}
}

func TestCorruptCacheRecovers(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"tag_name":"1.2.4"}`))
	}))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "update.json")
	if err := os.WriteFile(path, []byte(`{"checked":"broken"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	n := Notifier{Path: path, URL: server.URL}
	if got := n.Check(context.Background(), "1.2.3"); got != "1.2.4" {
		t.Fatalf("check with corrupt cache = %q", got)
	}
}

func TestCachedAnnouncementDoesNotNeedNetwork(t *testing.T) {
	path := filepath.Join(t.TempDir(), "update.json")
	now := time.Now()
	if !save(path, cache{Checked: now, Latest: "1.2.4"}) {
		t.Fatal("save failed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	n := Notifier{Path: path}
	if got := n.Check(ctx, "1.2.3"); got != "1.2.4" {
		t.Fatalf("cached notice = %q", got)
	}
}
