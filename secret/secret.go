// Package secret provides small, provider-neutral secret storage primitives.
package secret

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/albertocavalcante/credkit/store"
)

var (
	// ErrNotFound is returned when a secret does not exist.
	ErrNotFound = errors.New("secret not found")
	// ErrUnsupported is returned when the selected backend is unavailable.
	ErrUnsupported = errors.New("secret backend unsupported")
	// ErrInvalidKey is returned when a key omits its service or account.
	ErrInvalidKey = errors.New("invalid secret key")
)

// Key identifies a secret without containing secret material.
type Key struct {
	Service string
	Account string
}

// Store persists opaque secret values.
type Store interface {
	Put(context.Context, Key, []byte) error
	Get(context.Context, Key) ([]byte, error)
	Delete(context.Context, Key) error
}

// FileStore persists each value in a dedicated owner-only file. It is a
// portable fallback for hosts without an OS credential store.
type FileStore struct {
	Dir string
}

// Put atomically replaces a file-backed secret.
func (s FileStore) Put(ctx context.Context, key Key, value []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	path, err := s.path(key)
	if err != nil {
		return err
	}
	if err := store.WriteSecure(path, value); err != nil {
		return fmt.Errorf("put file secret: %w", err)
	}
	return nil
}

// Get reads a file-backed secret.
func (s FileStore) Get(ctx context.Context, key Key) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	path, err := s.path(key)
	if err != nil {
		return nil, err
	}
	value, err := store.ReadSecure(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get file secret: %w", err)
	}
	return value, nil
}

// Delete removes a file-backed secret. It is idempotent.
func (s FileStore) Delete(ctx context.Context, key Key) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	path, err := s.path(key)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("delete file secret: %w", err)
	}
	return nil
}

func (s FileStore) path(key Key) (string, error) {
	if err := validateKey(key); err != nil {
		return "", err
	}
	if strings.TrimSpace(s.Dir) == "" {
		return "", errors.New("file secret directory is required")
	}
	digest := sha256.Sum256([]byte(key.Service + "\x00" + key.Account))
	return filepath.Join(s.Dir, hex.EncodeToString(digest[:])+".secret"), nil
}

// KeychainStore uses the macOS login keychain through /usr/bin/security.
// Secrets are supplied over stdin and never placed in process arguments.
type KeychainStore struct {
	// ExecutablePath overrides /usr/bin/security. It is primarily a test seam.
	ExecutablePath string
	// CommandContext overrides process creation. It is primarily a test seam.
	CommandContext func(context.Context, string, ...string) *exec.Cmd
}

// Put creates or updates a generic-password item.
func (s KeychainStore) Put(ctx context.Context, key Key, value []byte) error {
	if err := validateKey(key); err != nil {
		return err
	}
	if bytes.ContainsAny(value, "\r\n\x00") {
		return errors.New("keychain secret cannot contain a newline or NUL")
	}
	input := make([]byte, len(value)+1)
	copy(input, value)
	input[len(value)] = '\n'
	_, err := s.run(ctx, input, "add-generic-password", "-a", key.Account, "-s", key.Service, "-U", "-w")
	if err != nil {
		return fmt.Errorf("put keychain secret: %w", err)
	}
	return nil
}

// Get reads a generic-password item.
func (s KeychainStore) Get(ctx context.Context, key Key) ([]byte, error) {
	if err := validateKey(key); err != nil {
		return nil, err
	}
	value, err := s.run(ctx, nil, "find-generic-password", "-a", key.Account, "-s", key.Service, "-w")
	if err != nil {
		if isNotFoundExit(err) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get keychain secret: %w", err)
	}
	value = bytes.TrimSuffix(value, []byte{'\n'})
	return value, nil
}

// Delete removes a generic-password item. It is idempotent.
func (s KeychainStore) Delete(ctx context.Context, key Key) error {
	if err := validateKey(key); err != nil {
		return err
	}
	_, err := s.run(ctx, nil, "delete-generic-password", "-a", key.Account, "-s", key.Service)
	if isNotFoundExit(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("delete keychain secret: %w", err)
	}
	return nil
}

func (s KeychainStore) run(ctx context.Context, input []byte, args ...string) ([]byte, error) {
	executable := strings.TrimSpace(s.ExecutablePath)
	if executable == "" {
		if runtime.GOOS != "darwin" {
			return nil, ErrUnsupported
		}
		executable = "/usr/bin/security"
	}
	commandContext := s.CommandContext
	if commandContext == nil {
		commandContext = exec.CommandContext
	}
	cmd := commandContext(ctx, executable, args...)
	if input != nil {
		cmd.Stdin = bytes.NewReader(input)
	}
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	return stdout.Bytes(), nil
}

func validateKey(key Key) error {
	if strings.TrimSpace(key.Service) == "" || strings.TrimSpace(key.Account) == "" {
		return ErrInvalidKey
	}
	if strings.ContainsAny(key.Service, "\x00\r\n") || strings.ContainsAny(key.Account, "\x00\r\n") {
		return ErrInvalidKey
	}
	return nil
}

func isNotFoundExit(err error) bool {
	if err == nil {
		return false
	}
	var exitErr *exec.ExitError
	return errors.As(err, &exitErr) && exitErr.ExitCode() == 44
}
