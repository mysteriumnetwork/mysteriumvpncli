package wireguard

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const privateKeyPlaceholder = "%private_key%"
const configFilePrefix = "mvpn-"

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
	config, err := renderConfig(template, privateKey)
	if err != nil {
		return "", err
	}

	if err := os.MkdirAll(directory, 0o700); err != nil {
		return "", fmt.Errorf("create WireGuard config directory: %w", err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return "", fmt.Errorf("secure WireGuard config directory: %w", err)
	}

	file, err := os.CreateTemp(directory, configFilePrefix+"*.conf")
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

// UpdateConfig atomically replaces an app-managed config while preserving its path.
func UpdateConfig(path, template, privateKey string) error {
	if err := ValidateConfigPath(path); err != nil {
		return err
	}
	config, err := renderConfig(template, privateKey)
	if err != nil {
		return err
	}

	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".config-*")
	if err != nil {
		return fmt.Errorf("create temporary WireGuard config: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)

	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return fmt.Errorf("secure temporary WireGuard config: %w", err)
	}
	if _, err := temporary.WriteString(config); err != nil {
		temporary.Close()
		return fmt.Errorf("write WireGuard config: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("sync WireGuard config: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close WireGuard config: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("replace WireGuard config: %w", err)
	}
	return nil
}

// ValidateConfigPath verifies that path names a regular app-managed config file.
func ValidateConfigPath(path string) error {
	directory, err := DefaultConfigDirectory()
	if err != nil {
		return err
	}
	cleanPath, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return fmt.Errorf("resolve WireGuard config path: %w", err)
	}
	cleanDirectory, err := filepath.Abs(filepath.Clean(directory))
	if err != nil {
		return fmt.Errorf("resolve WireGuard config directory: %w", err)
	}
	name := filepath.Base(cleanPath)
	if filepath.Dir(cleanPath) != cleanDirectory || !strings.HasPrefix(name, configFilePrefix) || filepath.Ext(name) != ".conf" {
		return errors.New("WireGuard config path is not managed by mystvpn")
	}
	info, err := os.Lstat(cleanPath)
	if err != nil {
		return fmt.Errorf("inspect WireGuard config: %w", err)
	}
	if !info.Mode().IsRegular() {
		return errors.New("WireGuard config is not a regular file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return errors.New("WireGuard config permissions are not owner-only")
	}
	return nil
}

// RemoveConfig removes an app-managed config file.
func RemoveConfig(path string) error {
	if err := ValidateConfigPath(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove WireGuard config: %w", err)
	}
	return nil
}

func renderConfig(template, privateKey string) (string, error) {
	if privateKey == "" {
		return "", errors.New("WireGuard private key is empty")
	}
	if !strings.Contains(template, privateKeyPlaceholder) {
		return "", errors.New("WireGuard config is missing the private key placeholder")
	}
	return strings.ReplaceAll(template, privateKeyPlaceholder, privateKey), nil
}
