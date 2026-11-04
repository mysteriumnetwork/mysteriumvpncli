package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUpdateNoticesRespectInstallationOwnership(t *testing.T) {
	for _, debian := range []bool{true, false} {
		var output bytes.Buffer
		writeUpdateNotice(&output, "1.3.0", "1.2.0", debian)
		got := output.String()
		if !strings.Contains(got, "1.3.0 is available (installed: 1.2.0)") {
			t.Fatalf("missing versions: %q", got)
		}
		if debian {
			for _, expected := range []string{"With the Mysterium repository configured", "apt install --only-upgrade mystvpn", "newer .deb", "holds, and pinning"} {
				if !strings.Contains(got, expected) {
					t.Errorf("missing %q: %q", expected, got)
				}
			}
		} else if !strings.Contains(got, "#updating") || strings.Contains(got, "apt install") {
			t.Fatalf("unsafe fallback: %q", got)
		}
	}
}

func TestDebianOwnershipMatchesActualExecutable(t *testing.T) {
	for _, test := range []struct {
		output, executable string
		want               bool
	}{
		{"mystvpn: /usr/bin/mystvpn\n", "/usr/bin/mystvpn", true},
		{"mystvpn:arm64: /usr/bin/mystvpn\n", "/usr/bin/mystvpn", true},
		{"mystvpn: /usr/bin/mystvpn\n", "/usr/local/bin/mystvpn", false},
		{"other: /usr/bin/mystvpn\n", "/usr/bin/mystvpn", false},
		{"diversion by mystvpn from: /usr/bin/mystvpn\n", "/usr/bin/mystvpn", false},
		{"", "", false},
	} {
		if got := ownedByDebianPackage(test.output, test.executable); got != test.want {
			t.Errorf("ownership(%q, %q) = %v", test.output, test.executable, got)
		}
	}
}

func TestRedirectedCommandsNeverCheckForUpdates(t *testing.T) {
	// Release builds must also leave script output and cache untouched.
	oldVersion := version
	version = "1.2.3"
	t.Cleanup(func() { version = oldVersion })
	directory := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", directory)
	// UserCacheDir uses HOME/Library/Caches on macOS rather than XDG_CACHE_HOME.
	t.Setenv("HOME", directory)
	t.Setenv("TERM", "xterm-256color")
	regular, err := os.Create(filepath.Join(directory, "stderr"))
	if err != nil {
		t.Fatal(err)
	}
	defer regular.Close()
	null, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer null.Close()
	var stderr bytes.Buffer
	for _, output := range []io.Writer{&stderr, regular, null} {
		var stdout bytes.Buffer
		if code := run([]string{"version"}, nil, &stdout, output); code != 0 || stdout.String() != "mystvpn 1.2.3\n" || stderr.Len() != 0 {
			t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
		}
	}
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(cacheDir, "mystvpn")); !os.IsNotExist(err) {
		t.Fatalf("redirected command touched update cache: %v", err)
	}
}
