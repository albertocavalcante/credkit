// Package token provides a ledger for tracking issued tokens across providers.
//
// The ledger enables expiry monitoring, rotation planning, and cross-tool visibility.
// Tokens are stored in a JSON file, one entry per issued token.
//
// Note: the mutex protects against concurrent access within a single process.
// Cross-process coordination requires external locking (e.g., file locks).
package token

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sync"
	"time"

	"github.com/albertocavalcante/credkit/store"
)

// Metadata describes an issued token tracked by the ledger.
type Metadata struct {
	Provider  string            `json:"provider"`
	Name      string            `json:"name"`
	ID        string            `json:"id,omitempty"`
	IssuedAt  time.Time         `json:"issued_at"`
	ExpiresAt *time.Time        `json:"expires_at,omitempty"`
	Scope     map[string]string `json:"scope,omitempty"`
	MasterKey string            `json:"master_key,omitempty"`
	Source    string            `json:"source,omitempty"`
}

// IsExpired reports whether the token has expired.
func (m *Metadata) IsExpired() bool {
	return m.ExpiresAt != nil && time.Now().After(*m.ExpiresAt)
}

// ExpiresWithin reports whether the token expires within the given duration.
// Returns false for tokens without an expiry.
func (m *Metadata) ExpiresWithin(d time.Duration) bool {
	return m.ExpiresAt != nil && time.Now().Add(d).After(*m.ExpiresAt)
}

// Ledger tracks issued tokens in a JSON file.
type Ledger struct {
	path string
	mu   sync.Mutex
}

// NewLedger creates a ledger backed by the given file path.
func NewLedger(path string) *Ledger {
	return &Ledger{path: path}
}

// Record adds a token to the ledger.
func (l *Ledger) Record(m *Metadata) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	entries, err := l.loadLocked()
	if err != nil {
		return fmt.Errorf("record token: %w", err)
	}
	entries = append(entries, *m)
	return l.saveLocked(entries)
}

// List returns all tokens, optionally filtered by provider.
// Pass an empty provider to list all tokens.
func (l *Ledger) List(provider string) ([]Metadata, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	entries, err := l.loadLocked()
	if err != nil {
		return nil, err
	}

	if provider == "" {
		return entries, nil
	}

	var filtered []Metadata
	for _, e := range entries {
		if e.Provider == provider {
			filtered = append(filtered, e)
		}
	}
	return filtered, nil
}

// Expiring returns tokens that expire within the given duration.
// Already-expired tokens are included. Tokens without an expiry are excluded.
func (l *Ledger) Expiring(within time.Duration) ([]Metadata, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	entries, err := l.loadLocked()
	if err != nil {
		return nil, err
	}

	var expiring []Metadata
	for _, e := range entries {
		if e.ExpiresWithin(within) {
			expiring = append(expiring, e)
		}
	}
	return expiring, nil
}

// Remove deletes a token entry by provider and name.
func (l *Ledger) Remove(provider, name string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	entries, err := l.loadLocked()
	if err != nil {
		return err
	}

	var kept []Metadata
	for _, e := range entries {
		if e.Provider == provider && e.Name == name {
			continue
		}
		kept = append(kept, e)
	}
	return l.saveLocked(kept)
}

// Cleanup removes expired tokens and tokens older than the given age from the ledger.
func (l *Ledger) Cleanup(olderThan time.Duration) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	entries, err := l.loadLocked()
	if err != nil {
		return 0, err
	}

	cutoff := time.Now().Add(-olderThan)
	var kept []Metadata
	for _, e := range entries {
		if e.IsExpired() {
			continue
		}
		if !e.IssuedAt.IsZero() && e.IssuedAt.Before(cutoff) {
			continue
		}
		kept = append(kept, e)
	}

	removed := len(entries) - len(kept)
	if removed > 0 {
		if err := l.saveLocked(kept); err != nil {
			return 0, err
		}
	}
	return removed, nil
}

func (l *Ledger) loadLocked() ([]Metadata, error) {
	data, err := os.ReadFile(l.path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read ledger: %w", err)
	}

	var entries []Metadata
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("parse ledger: %w", err)
	}
	return entries, nil
}

func (l *Ledger) saveLocked(entries []Metadata) error {
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal ledger: %w", err)
	}
	return store.WriteSecure(l.path, append(data, '\n'))
}
