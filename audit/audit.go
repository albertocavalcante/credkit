// Package audit provides structured, append-only audit logging for credential operations.
//
// Entries are written as JSON lines to a log file, enabling cross-tool audit trails.
package audit

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/albertocavalcante/credkit/store"
)

// Entry represents a single audit log record.
type Entry struct {
	Timestamp time.Time `json:"ts"`
	Action    string    `json:"action"`     // issue, revoke, validate, rotate, login, logout
	Provider  string    `json:"provider"`   // sonarcloud, cloudflare, bitwarden, etc.
	TokenName string    `json:"token_name"` // identifier of the affected token
	Success   bool      `json:"success"`
	Error     string    `json:"error,omitempty"`
	Source    string    `json:"source"` // issuing tool: sonar-cli, flare, cofre
}

// Logger writes audit entries to a JSON-lines file.
type Logger struct {
	path string
	mu   sync.Mutex
}

// NewLogger creates a logger that appends entries to the given file.
func NewLogger(path string) *Logger {
	return &Logger{path: path}
}

// Log appends an entry to the audit log. Thread-safe.
func (l *Logger) Log(e Entry) error {
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}

	data, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("marshal audit entry: %w", err)
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if dirErr := store.EnsureDir(filepath.Dir(l.path)); dirErr != nil {
		return dirErr
	}

	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, store.FilePerm) //nolint:gosec // path from Logger, not user input
	if err != nil {
		return fmt.Errorf("open audit log: %w", err)
	}
	defer func() { _ = f.Close() }()

	data = append(data, '\n')
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("write audit entry: %w", err)
	}
	return nil
}

// Query reads entries from the audit log, filtered by time and optionally by provider.
// Pass an empty provider to return all entries.
func (l *Logger) Query(since time.Time, provider string) ([]Entry, error) {
	f, err := os.Open(l.path) //nolint:gosec // path from Logger, not user input
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	defer func() { _ = f.Close() }()

	var entries []Entry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			continue // skip malformed lines
		}

		if e.Timestamp.Before(since) {
			continue
		}
		if provider != "" && e.Provider != provider {
			continue
		}
		entries = append(entries, e)
	}

	if err := scanner.Err(); err != nil {
		return entries, fmt.Errorf("scan audit log: %w", err)
	}
	return entries, nil
}
