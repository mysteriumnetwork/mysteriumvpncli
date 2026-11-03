package main

import (
	"os"
	"testing"
)

func TestDetectOSVersion(t *testing.T) {
	for _, test := range []struct {
		name  string
		files map[string]string
		want  string
	}{
		{"distribution", map[string]string{"/etc/os-release": "NAME=Ubuntu\nVERSION_ID=24.04\nPRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\n"}, "Ubuntu 24.04.1 LTS"},
		{"single quotes", map[string]string{"/etc/os-release": "PRETTY_NAME='Debian GNU/Linux 12 (bookworm)'"}, "Debian GNU/Linux 12 (bookworm)"},
		{"escaped quotes", map[string]string{"/etc/os-release": `PRETTY_NAME="Linux \"Custom\""`}, `Linux "Custom"`},
		{"name and version", map[string]string{"/etc/os-release": "# ignored\ninvalid\nNAME=Alpine\nVERSION_ID=3.20.0"}, "Alpine 3.20.0"},
		{"vendor fallback", map[string]string{"/usr/lib/os-release": "PRETTY_NAME=\"Fedora Linux 40\""}, "Fedora Linux 40"},
		{"empty distribution fallback", map[string]string{"/etc/os-release": "PRETTY_NAME=\"\"", "/usr/lib/os-release": "PRETTY_NAME=Fedora"}, "Fedora"},
		{"kernel fallback", map[string]string{"/etc/os-release": "# no usable version", "/proc/sys/kernel/osrelease": "6.8.0-generic\n"}, "Linux 6.8.0-generic"},
		{"unavailable", nil, "unknown"},
		{"empty kernel", map[string]string{"/proc/sys/kernel/osrelease": "\n"}, "unknown"},
	} {
		t.Run(test.name, func(t *testing.T) {
			readFile := func(path string) ([]byte, error) {
				if content, ok := test.files[path]; ok {
					return []byte(content), nil
				}
				return nil, os.ErrNotExist
			}
			if got := detectOSVersion(readFile); got != test.want {
				t.Errorf("detectOSVersion() = %q, want %q", got, test.want)
			}
		})
	}
}
