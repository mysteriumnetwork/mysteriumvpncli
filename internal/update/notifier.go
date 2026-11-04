// Package update checks for release announcements without installing software.
package update

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

const LatestURL = "https://api.github.com/repos/mysteriumnetwork/mysteriumvpncli/releases/latest"
const interval = 24 * time.Hour

// Notifier keeps metadata separate from credentials and connection settings.
// Client and URL may be supplied for testing; defaults use the public GitHub API.
type Notifier struct {
	Path   string
	Client *http.Client
	URL    string
	Now    func() time.Time
}

type cache struct {
	Checked  time.Time `json:"checked"`
	Latest   string    `json:"latest,omitempty"`
	Notified time.Time `json:"notified,omitempty"`
}

// Check returns a newer stable version at most once per day. All failures are
// silent. The caller must bound ctx and only invoke this for interactive use.
func (n Notifier) Check(ctx context.Context, current string) string {
	if _, ok := stableVersion(current); !ok {
		return ""
	}
	now := time.Now()
	if n.Now != nil {
		now = n.Now()
	}
	if err := os.MkdirAll(filepath.Dir(n.Path), 0o700); err != nil {
		return ""
	}
	// A nonblocking process lock prevents duplicate requests and notices when
	// several CLI invocations share a cache. The OS releases it on process exit.
	lock, err := os.OpenFile(n.Path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return ""
	}
	defer lock.Close()
	if syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		return ""
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	var state cache
	if data, err := os.ReadFile(n.Path); err == nil {
		if json.Unmarshal(data, &state) != nil {
			state = cache{}
		}
	}
	changed := false
	if due(now, state.Checked) {
		state.Checked = now // Also throttle offline failures and API rate limits.
		// Persist the attempt before network access, so interrupted commands
		// and unwritable caches cannot trigger repeated requests.
		if !save(n.Path, state) {
			return ""
		}
		if latest := n.latest(ctx); latest != "" {
			changed = state.Latest != latest
			state.Latest = latest
		}
	}
	announce := newer(state.Latest, current) && due(now, state.Notified)
	if announce {
		changed = true
		state.Notified = now
	}
	if changed && !save(n.Path, state) {
		return ""
	}
	if announce {
		return state.Latest
	}
	return ""
}

func due(now, previous time.Time) bool {
	return previous.IsZero() || now.Before(previous) || now.Sub(previous) >= interval
}

func (n Notifier) latest(ctx context.Context) string {
	url := n.URL
	if url == "" {
		url = LatestURL
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "mystvpn-update-notifier")
	client := n.Client
	if client == nil {
		client = http.DefaultClient
	}
	response, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return ""
	}
	var release struct {
		Tag        string `json:"tag_name"`
		Draft      bool   `json:"draft"`
		Prerelease bool   `json:"prerelease"`
	}
	if json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&release) != nil || release.Draft || release.Prerelease {
		return ""
	}
	if _, ok := stableVersion(release.Tag); !ok {
		return ""
	}
	return release.Tag
}

func save(path string, state cache) bool {
	data, err := json.Marshal(state)
	if err != nil {
		return false
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".update-*")
	if err != nil {
		return false
	}
	defer os.Remove(file.Name())
	_, err = file.Write(data)
	closeErr := file.Close()
	return err == nil && closeErr == nil && os.Rename(file.Name(), path) == nil
}

var stablePattern = regexp.MustCompile(`^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$`)

func stableVersion(version string) ([]string, bool) {
	parts := stablePattern.FindStringSubmatch(version)
	if parts == nil {
		return nil, false
	}
	return parts[1:4], true
}

func newer(latest, current string) bool {
	a, ok := stableVersion(latest)
	if !ok {
		return false
	}
	b, ok := stableVersion(current)
	if !ok {
		return false
	}
	for i := range a {
		if len(a[i]) != len(b[i]) {
			return len(a[i]) > len(b[i])
		}
		if cmp := strings.Compare(a[i], b[i]); cmp != 0 {
			return cmp > 0
		}
	}
	return false
}
