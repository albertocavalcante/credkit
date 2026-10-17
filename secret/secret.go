// Package secret provides small, provider-neutral secret storage primitives.
package secret

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
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
	// ErrAmbiguousEncoding requires an explicit legacy decoding policy.
	ErrAmbiguousEncoding = errors.New("ambiguous legacy keychain encoding")
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
	if err := store.WriteSecureAt(s.Dir, filepath.Base(path), value); err != nil {
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
	value, err := store.ReadSecureAt(s.Dir, filepath.Base(path))
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
	if err := store.RemoveSecureAt(s.Dir, filepath.Base(path)); err != nil && !errors.Is(err, os.ErrNotExist) {
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

// LegacyEncoding selects how unmarked Keychain items with a b64: prefix are read.
type LegacyEncoding int

const (
	// LegacyRejectAmbiguous refuses values that could be literal or encoded.
	LegacyRejectAmbiguous LegacyEncoding = iota
	// LegacyPlain treats unmarked values as literal bytes.
	LegacyPlain
	// LegacyBase64 decodes unmarked b64: values written by older credkit versions.
	LegacyBase64
)

// KeychainStore uses the macOS login keychain through /usr/bin/security.
// Secrets are supplied to `security -i` over stdin and never placed in process
// arguments.
type KeychainStore struct {
	// LegacyEncoding resolves ambiguous unmarked b64: entries during migration.
	// The default refuses ambiguity; marked entries always use their metadata.
	LegacyEncoding LegacyEncoding

	// ExecutablePath overrides /usr/bin/security. It is primarily a test seam.
	ExecutablePath string
	// CommandContext overrides process creation. It is primarily a test seam.
	CommandContext func(context.Context, string, ...string) *exec.Cmd
}

// encodedPrefix marks values stored by this package as base64. It keeps the
// stored password shell- and parser-safe. encodedKind distinguishes new
// entries from arbitrary legacy plain-text values.
const encodedPrefix = "b64:"

// encodedKind is metadata, separate from arbitrary legacy password bytes.
const encodedKind = "credkit.base64.v1"

// Put creates or updates a generic-password item.
//
// The secret is delivered to `security -i` on stdin, never in process
// arguments. `security add-generic-password -w` with no value reads the
// password from the controlling terminal (it prompts), not from stdin, so it
// cannot be used non-interactively. Interactive mode also exits 0 when the
// command fails, so Put reads the item back to confirm the write.
func (s KeychainStore) Put(ctx context.Context, key Key, value []byte) error {
	if s.LegacyEncoding < LegacyRejectAmbiguous || s.LegacyEncoding > LegacyBase64 {
		return errors.New("invalid legacy encoding policy")
	}
	if err := validateKey(key); err != nil {
		return err
	}
	encoded := encodedPrefix + base64.StdEncoding.EncodeToString(value)
	script := "add-generic-password -a " + quoteArg(key.Account) +
		" -s " + quoteArg(key.Service) + " -D " + encodedKind + " -U -w " + encoded + "\n"
	if _, err := s.run(ctx, []byte(script), "-i"); err != nil {
		return fmt.Errorf("put keychain secret: %w", err)
	}
	got, err := s.Get(ctx, key)
	if err != nil || !bytes.Equal(got, value) {
		return errors.New("put keychain secret: write could not be verified")
	}
	return nil
}

// Get reads a generic-password item. Unmarked b64: values require an explicit
// LegacyEncoding policy because their original representation is ambiguous.
func (s KeychainStore) Get(ctx context.Context, key Key) ([]byte, error) {
	if err := validateKey(key); err != nil {
		return nil, err
	}
	if s.LegacyEncoding < LegacyRejectAmbiguous || s.LegacyEncoding > LegacyBase64 {
		return nil, errors.New("invalid legacy encoding policy")
	}
	metadata, err := s.run(ctx, nil, "find-generic-password", "-a", key.Account, "-s", key.Service)
	if err != nil {
		if isNotFoundExit(err) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get keychain metadata: %w", err)
	}
	marked := hasEncodedKind(metadata)
	value, err := s.run(ctx, nil, "find-generic-password", "-a", key.Account, "-s", key.Service, "-w")
	if err != nil {
		if isNotFoundExit(err) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get keychain secret: %w", err)
	}
	after, err := s.run(ctx, nil, "find-generic-password", "-a", key.Account, "-s", key.Service)
	if err != nil {
		if isNotFoundExit(err) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("recheck keychain metadata: %w", err)
	}
	if hasEncodedKind(after) != marked {
		return nil, errors.New("get keychain secret: encoding changed during read")
	}

	value = bytes.TrimSuffix(value, []byte{'\n'})
	rest, prefixed := bytes.CutPrefix(value, []byte(encodedPrefix))
	if marked || (prefixed && s.LegacyEncoding == LegacyBase64) {
		if !prefixed {
			return nil, errors.New("get keychain secret: encoded item has no encoding prefix")
		}
		decoded, err := base64.StdEncoding.DecodeString(string(rest))
		if err != nil {
			return nil, fmt.Errorf("get keychain secret: stored value is corrupt: %w", err)
		}
		return decoded, nil
	}
	if prefixed && s.LegacyEncoding == LegacyRejectAmbiguous {
		return nil, ErrAmbiguousEncoding
	}
	return value, nil
}

// The security CLI advertises -D as a filter but does not reliably apply it.
// Inspect its description attribute instead of inferring encoding from lookup success.
func hasEncodedKind(metadata []byte) bool {
	expected := []byte(`"desc"<blob>="` + encodedKind + `"`)
	for line := range bytes.SplitSeq(metadata, []byte{'\n'}) {
		if bytes.Equal(bytes.TrimSpace(line), expected) {
			return true
		}
	}
	return false
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

// quoteArg double-quotes a value for the `security -i` command parser.
func quoteArg(v string) string {
	v = strings.ReplaceAll(v, `\`, `\\`)
	v = strings.ReplaceAll(v, `"`, `\"`)
	return `"` + v + `"`
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
