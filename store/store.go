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

// ErrUnsafePath is returned when a sensitive-data directory is a symlink or
// another non-directory filesystem object.
var ErrUnsafePath = errors.New("unsafe sensitive-data path")

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
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect directory %s: %w", path, err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("secure directory %s: %w", path, ErrUnsafePath)
	}
	if err := os.Chmod(path, DirPerm); err != nil {
		return fmt.Errorf("secure directory %s: %w", path, err)
	}
	return nil
}

// WriteSecure writes data to path with FilePerm, creating parent directories
// with DirPerm as needed. The replacement is atomic when path and its parent
// are on the same filesystem.
func WriteSecure(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := EnsureDir(dir); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(dir, ".credkit-write-*")
	if err != nil {
		return fmt.Errorf("create temporary credential file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
	if err := temporary.Chmod(FilePerm); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("secure temporary credential file: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write temporary credential file: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync temporary credential file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary credential file: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("replace %s: %w", path, err)
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
	return err == nil
}
