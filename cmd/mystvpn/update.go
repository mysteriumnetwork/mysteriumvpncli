package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/mysteriumnetwork/mysteriumvpncli/internal/config"
	"github.com/mysteriumnetwork/mysteriumvpncli/internal/update"
	"golang.org/x/term"
)

func notifyUpdate(stderr io.Writer) {
	if _, disabled := os.LookupEnv("MYSTVPN_NO_UPDATE_NOTIFIER"); disabled {
		return
	}
	file, ok := stderr.(*os.File)
	if !ok || os.Getenv("TERM") == "dumb" || !term.IsTerminal(int(file.Fd())) {
		return
	}
	directory, err := os.UserCacheDir()
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	publicClient, err := newAPIClient(config.Load())
	if err != nil {
		return
	}
	// Bound DNS/TCP dialing explicitly for this optional update check.
	transport := publicClient.HTTPClient.Transport.(*http.Transport)
	transport.DialContext = (&net.Dialer{Timeout: 500 * time.Millisecond, KeepAlive: 30 * time.Second}).DialContext
	publicClient.HTTPClient.Timeout = 500 * time.Millisecond
	notifier := update.Notifier{Path: filepath.Join(directory, "mystvpn", "update.json"), Client: publicClient}
	latest := notifier.Check(ctx, version)
	if latest == "" {
		return
	}
	// Ownership is checked for this executable, never inferred from APT's
	// presence or the first mystvpn on PATH. Do not execute an upgrade.
	ctx, cancelOwnership := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancelOwnership()
	executable, err := os.Executable()
	if err != nil {
		writeUpdateNotice(stderr, latest, version, false)
		return
	}
	if resolved, err := filepath.EvalSymlinks(executable); err == nil {
		executable = resolved
	}
	output, err := exec.CommandContext(ctx, "dpkg-query", "--search", executable).Output()
	writeUpdateNotice(stderr, latest, version, err == nil && ownedByDebianPackage(string(output), executable))
}

func writeUpdateNotice(stderr io.Writer, latest, current string, debianPackage bool) {
	fmt.Fprintf(stderr, "[UPDATE] mystvpn %s is available (installed: %s).\n", latest, current)
	if debianPackage {
		fmt.Fprintln(stderr, "[UPDATE] Managed by APT. With the Mysterium repository configured, run: sudo apt update && sudo apt install --only-upgrade mystvpn")
		fmt.Fprintln(stderr, "[UPDATE] Otherwise, install the newer .deb through APT. Repository availability, holds, and pinning may affect upgrades.")
	} else {
		fmt.Fprintln(stderr, "[UPDATE] Upgrade using your original installation method; see https://github.com/mysteriumnetwork/mysteriumvpncli#updating")
	}
}

func ownedByDebianPackage(output, executable string) bool {
	if executable == "" {
		return false
	}
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		owner, path, ok := strings.Cut(line, ": ")
		if ok && strings.TrimSpace(path) == executable && (owner == "mystvpn" || strings.HasPrefix(owner, "mystvpn:")) {
			return true
		}
	}
	return false
}
