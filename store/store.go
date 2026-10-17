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

// ErrUnsafePath identifies unsafe sensitive-data paths or permissions, including
// managed symlinks, unexpected file types, and permissions outside the storage policy.
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
	if err := secureDirectoryPath(path, info); err != nil {
		return fmt.Errorf("secure directory %s: %w", path, err)
	}
	return nil
}

// WriteSecure writes data to path with FilePerm, creating parent directories
// with DirPerm as needed. The replacement is atomic when path and its parent
// are on the same filesystem. The parent is caller-trusted; use WriteSecureAt
// when a configured application root must constrain descendant traversal.
func WriteSecure(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := EnsureDir(dir); err != nil {
		return err
	}
	return WriteSecureAt(dir, filepath.Base(path), data)
}

// ReadSecure reads data from path. Returns an error wrapping [os.ErrNotExist]
// if the file does not exist.
func ReadSecure(path string) ([]byte, error) {
	return ReadSecureAt(filepath.Dir(path), filepath.Base(path))
}

// Exists reports whether path exists on disk.
func Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
