// Package store provides secure file I/O with XDG Base Directory compliance.
package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const (
	// DirPerm is the permission mode for directories containing sensitive data.
	DirPerm = 0o700
	// FilePerm is the permission mode for files containing sensitive data.
	FilePerm = 0o600
)

// XDGConfigDir returns the XDG-compliant config directory for the given app.
// It respects $XDG_CONFIG_HOME and falls back to ~/.config/<appName>.
func XDGConfigDir(appName string) (string, error) {
	configHome := os.Getenv("XDG_CONFIG_HOME")
	if configHome == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("resolve home directory: %w", err)
		}
		configHome = filepath.Join(home, ".config")
	}
	return filepath.Join(configHome, appName), nil
}

// EnsureDir creates a directory with DirPerm if it does not exist.
func EnsureDir(path string) error {
	if err := os.MkdirAll(path, DirPerm); err != nil {
		return fmt.Errorf("create directory %s: %w", path, err)
	}
	return nil
}

// WriteSecure writes data to path with FilePerm, creating parent directories
// with DirPerm as needed.
func WriteSecure(path string, data []byte) error {
	if err := EnsureDir(filepath.Dir(path)); err != nil {
		return err
	}
	if err := os.WriteFile(path, data, FilePerm); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// ReadSecure reads data from path. Returns an error wrapping [os.ErrNotExist]
// if the file does not exist.
func ReadSecure(path string) ([]byte, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path from caller, validated upstream
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return data, nil
}

// Exists reports whether path exists on disk.
func Exists(path string) bool {
	_, err := os.Stat(path)
	return !errors.Is(err, os.ErrNotExist) && err == nil
}
