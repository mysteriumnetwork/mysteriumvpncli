package wireguard

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const privateKeyPlaceholder = "%private_key%"

// DefaultConfigDirectory returns the protected directory for active tunnel configs.
func DefaultConfigDirectory() (string, error) {
	configDirectory, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("find user config directory: %w", err)
	}
	return filepath.Join(configDirectory, "mystvpn", "wireguard", "configs"), nil
}

// WriteConfig replaces the private-key placeholder and writes an owner-only config.
func WriteConfig(directory, template, privateKey string) (string, error) {
	if privateKey == "" {
		return "", errors.New("WireGuard private key is empty")
	}
	if !strings.Contains(template, privateKeyPlaceholder) {
		return "", errors.New("WireGuard config is missing the private key placeholder")
	}
	config := strings.ReplaceAll(template, privateKeyPlaceholder, privateKey)

	if err := os.MkdirAll(directory, 0o700); err != nil {
		return "", fmt.Errorf("create WireGuard config directory: %w", err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return "", fmt.Errorf("secure WireGuard config directory: %w", err)
	}

	file, err := os.CreateTemp(directory, "mvpn-*.conf")
	if err != nil {
		return "", fmt.Errorf("create WireGuard config: %w", err)
	}
	path := file.Name()
	succeeded := false
	defer func() {
		if !succeeded {
			os.Remove(path)
		}
	}()

	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return "", fmt.Errorf("secure WireGuard config: %w", err)
	}
	if _, err := file.WriteString(config); err != nil {
		file.Close()
		return "", fmt.Errorf("write WireGuard config: %w", err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return "", fmt.Errorf("sync WireGuard config: %w", err)
	}
	if err := file.Close(); err != nil {
		return "", fmt.Errorf("close WireGuard config: %w", err)
	}

	succeeded = true
	return path, nil
}
