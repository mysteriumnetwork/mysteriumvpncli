package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunWithoutArgumentsPrintsUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer

	exitCode := run(nil, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("run() exit code = %d, want 0", exitCode)
	}
	if !strings.Contains(stdout.String(), "Usage:") {
		t.Errorf("stdout = %q, want usage", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr = %q, want empty", stderr.String())
	}
}

func TestRunVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer

	exitCode := run([]string{"--version"}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("run() exit code = %d, want 0", exitCode)
	}
	if got, want := stdout.String(), "mystvpn "+version+"\n"; got != want {
		t.Errorf("stdout = %q, want %q", got, want)
	}
}

func TestRunHelpListsFlagsAndCommands(t *testing.T) {
	var stdout, stderr bytes.Buffer

	exitCode := run([]string{"--help"}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("run() exit code = %d, want 0", exitCode)
	}
	for _, expected := range []string{"--api-url", "--debug", "--help", "--version", "auth", "disconnect"} {
		if !strings.Contains(stderr.String(), expected) {
			t.Errorf("help output does not contain %q: %q", expected, stderr.String())
		}
	}
}

func TestRunPlaceholderCommands(t *testing.T) {
	for _, command := range commands {
		t.Run(command, func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			exitCode := run([]string{"--api-url", "https://vpn.example/api/v1", "--debug", command}, &stdout, &stderr)

			if exitCode != 0 {
				t.Fatalf("run() exit code = %d, want 0; stderr = %q", exitCode, stderr.String())
			}
			if got, want := stdout.String(), "mystvpn "+command+": not implemented yet\n"; got != want {
				t.Errorf("stdout = %q, want %q", got, want)
			}
		})
	}
}

func TestRunRejectsUnknownCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer

	exitCode := run([]string{"unknown"}, &stdout, &stderr)

	if exitCode != 2 {
		t.Fatalf("run() exit code = %d, want 2", exitCode)
	}
	if !strings.Contains(stderr.String(), `unknown command "unknown"`) {
		t.Errorf("stderr = %q, want unknown-command error", stderr.String())
	}
}
