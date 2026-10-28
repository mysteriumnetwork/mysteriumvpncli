package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestStatusMessagesRemainPlainWhenRedirected(t *testing.T) {
	t.Setenv("TERM", "xterm-256color")
	for _, noColor := range []bool{false, true} {
		t.Run(map[bool]string{false: "default", true: "NO_COLOR"}[noColor], func(t *testing.T) {
			if noColor {
				t.Setenv("NO_COLOR", "1")
			}
			path := filepath.Join(t.TempDir(), "output")
			file, err := os.Create(path)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			writeSuccess(file, "Completed %s.", "operation")
			writeError(file, "mystvpn connect: %s", "failed")
			got, err := os.ReadFile(path)
			want := "[SUCCESS] Completed operation.\n[ERROR] mystvpn connect: failed\n"
			if err != nil || string(got) != want {
				t.Fatalf("redirected output = %q, %v; want %q", got, err, want)
			}
		})
	}
}

func TestStatusMessagesDoNotChangeExitCodeConventions(t *testing.T) {
	configureTestHome(t)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"logout"}, nil, &stdout, &stderr); code != 0 || stdout.String() != "[SUCCESS] Logout successful.\n" || stderr.Len() != 0 {
		t.Fatalf("logout: exit %d, stdout %q, stderr %q", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"disconnect"}, nil, &stdout, &stderr); code != 1 || stdout.Len() != 0 || stderr.Len() == 0 {
		t.Fatalf("disconnect: exit %d, stdout %q, stderr %q", code, stdout.String(), stderr.String())
	}
}
