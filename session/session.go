// Package session provides TTL-based session caching for credential keys.
//
// Sessions are stored as JSON files under a config directory, keyed by provider name.
// This allows tools to cache validated tokens or vault session keys with automatic expiry.
package session

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/albertocavalcante/credkit/store"
)

// DefaultTTL is the default session cache lifetime.
const DefaultTTL = 4 * time.Hour

// Session represents a cached session key.
type Session struct {
	Key        string    `json:"key"`
	CreatedAt  time.Time `json:"created_at"`
	TTLSeconds int       `json:"ttl_seconds"`
	Provider   string    `json:"provider,omitempty"`
}

// IsExpired reports whether the session has exceeded its TTL.
func (s *Session) IsExpired() bool {
	ttl := time.Duration(s.TTLSeconds) * time.Second
	return time.Now().After(s.CreatedAt.Add(ttl))
}

// Manager handles loading, saving, and clearing session files.
type Manager struct {
	dir string
	ttl time.Duration
}

// NewManager creates a session manager rooted at the given directory.
func NewManager(dir string, ttl time.Duration) *Manager {
	if ttl == 0 {
		ttl = DefaultTTL
	}
	return &Manager{dir: dir, ttl: ttl}
}

// Load reads a cached session for the given provider.
func (m *Manager) Load(provider string) (*Session, error) {
	data, err := os.ReadFile(m.path(provider))
	if err != nil {
		return nil, fmt.Errorf("load session: %w", err)
	}

	var sess Session
	if err := json.Unmarshal(data, &sess); err != nil {
		return nil, fmt.Errorf("parse session: %w", err)
	}
	return &sess, nil
}

// Save writes a session key for the given provider.
func (m *Manager) Save(provider, key string) error {
	sess := Session{
		Key:        key,
		CreatedAt:  time.Now().UTC(),
		TTLSeconds: int(m.ttl.Seconds()),
		Provider:   provider,
	}

	data, err := json.Marshal(sess)
	if err != nil {
		return fmt.Errorf("marshal session: %w", err)
	}

	return store.WriteSecure(m.path(provider), data)
}

// Clear removes the cached session for the given provider.
func (m *Manager) Clear(provider string) error {
	if err := os.Remove(m.path(provider)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("clear session: %w", err)
	}
	return nil
}

// Resolve returns a session key using priority: explicit value > env vars > cached file.
// It returns ("", nil) when no session is available (callers should prompt or error).
func (m *Manager) Resolve(provider, explicit string, envVars ...string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}

	for _, name := range envVars {
		if v := os.Getenv(name); v != "" {
			return v, nil
		}
	}

	sess, err := m.Load(provider)
	if err != nil {
		return "", nil //nolint:nilerr // missing cache is not an error
	}
	if sess.IsExpired() {
		return "", nil
	}
	return sess.Key, nil
}

func (m *Manager) path(provider string) string {
	if provider == "" {
		return filepath.Join(m.dir, "session.json")
	}
	return filepath.Join(m.dir, "session-"+provider+".json")
}
