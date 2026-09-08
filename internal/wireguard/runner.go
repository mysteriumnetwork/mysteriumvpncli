package wireguard

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
)

// TunnelRunner brings up a WireGuard tunnel from a configuration file.
type TunnelRunner interface {
	Up(ctx context.Context, configPath string) error
}

// WGQuickRunner invokes the system wg-quick executable without elevation.
type WGQuickRunner struct{}

// Up runs wg-quick up with configPath.
func (WGQuickRunner) Up(ctx context.Context, configPath string) error {
	command := exec.CommandContext(ctx, "wg-quick", "up", configPath)
	if err := command.Run(); err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return errors.New("wg-quick is not installed")
		}
		return fmt.Errorf("wg-quick up failed: %w", err)
	}
	return nil
}
