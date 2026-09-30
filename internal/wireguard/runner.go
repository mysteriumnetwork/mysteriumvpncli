package wireguard

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// ErrTunnelAlreadyDown indicates that wg-quick could not find the interface
// requested for teardown.
var ErrTunnelAlreadyDown = errors.New("wireguard tunnel is already down")

// TunnelRunner manages a WireGuard tunnel from a configuration file.
type TunnelRunner interface {
	Up(ctx context.Context, configPath string) error
	Down(ctx context.Context, configPath string) error
}

// WGQuickRunner invokes the system wg-quick executable without elevation.
type WGQuickRunner struct{}

// Up runs wg-quick up with configPath.
func (WGQuickRunner) Up(ctx context.Context, configPath string) error {
	return runWGQuick(ctx, "up", configPath)
}

// Down runs wg-quick down with configPath.
func (WGQuickRunner) Down(ctx context.Context, configPath string) error {
	return runWGQuick(ctx, "down", configPath)
}

func runWGQuick(ctx context.Context, action, configPath string) error {
	command := exec.CommandContext(ctx, "wg-quick", action, configPath)
	output, err := command.CombinedOutput()
	if err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return errors.New("wg-quick is not installed")
		}
		details := strings.TrimSpace(string(output))
		if action == "down" && isMissingInterfaceOutput(details) {
			return fmt.Errorf("%w: %s", ErrTunnelAlreadyDown, details)
		}
		if details != "" {
			return fmt.Errorf("wg-quick %s failed: %s: %w", action, details, err)
		}
		return fmt.Errorf("wg-quick %s failed: %w", action, err)
	}
	return nil
}

func isMissingInterfaceOutput(output string) bool {
	output = strings.ToLower(output)
	for _, message := range []string{
		"is not a wireguard interface",
		"cannot find device",
		"no such device",
	} {
		if strings.Contains(output, message) {
			return true
		}
	}
	return strings.Contains(output, "does not exist") &&
		(strings.Contains(output, "device") || strings.Contains(output, "interface"))
}
