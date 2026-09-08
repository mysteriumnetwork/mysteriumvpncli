package wireguard

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
)

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
	if err := command.Run(); err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return errors.New("wg-quick is not installed")
		}
		return fmt.Errorf("wg-quick %s failed: %w", action, err)
	}
	return nil
}
