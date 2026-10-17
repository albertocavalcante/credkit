package session_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/albertocavalcante/credkit/session"
)

func TestResolvePreservesCorruptCacheErrors(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "session-test.json"), []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := session.NewManager(dir, time.Hour).Resolve("test", ""); err == nil {
		t.Fatal("corrupt cache reported as absence")
	}
}

func TestSubsecondSessionSurvivesSave(t *testing.T) {
	m := session.NewManager(t.TempDir(), 900*time.Millisecond)
	if err := m.Save("test", "synthetic"); err != nil {
		t.Fatal(err)
	}
	s, err := m.Load("test")
	if err != nil {
		t.Fatal(err)
	}
	if s.IsExpired() {
		t.Fatal("fresh subsecond session already expired")
	}
}

func TestExplicitSessionDoesNotReadCorruptCache(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "session-test.json"), []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := session.NewManager(dir, time.Hour).Resolve("test", "explicit")
	if err != nil || got != "explicit" {
		t.Fatalf("got %q %v", got, err)
	}
}

func TestPreciseExpiryAndLegacyCompatibility(t *testing.T) {
	ttl := 1500 * time.Millisecond
	m := session.NewManager(t.TempDir(), ttl)
	if err := m.Save("test", "value"); err != nil {
		t.Fatal(err)
	}
	s, err := m.Load("test")
	if err != nil {
		t.Fatal(err)
	}
	if s.ExpiresAt == nil || s.ExpiresAt.Sub(s.CreatedAt) != ttl {
		t.Fatalf("precise expiry missing: %+v", s)
	}
	legacy := session.Session{CreatedAt: time.Now(), TTLSeconds: 60}
	if legacy.IsExpired() {
		t.Fatal("legacy session expired prematurely")
	}
	legacy.CreatedAt = time.Now().Add(-2 * time.Minute)
	if !legacy.IsExpired() {
		t.Fatal("expired legacy session is live")
	}
}
