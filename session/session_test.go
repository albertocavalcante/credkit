package session_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/albertocavalcante/credkit/session"
)

func TestNewManager_DefaultTTL(t *testing.T) {
	m := session.NewManager(t.TempDir(), 0)
	// Save should use DefaultTTL.
	if err := m.Save("test", "key"); err != nil {
		t.Fatal(err)
	}
	sess, err := m.Load("test")
	if err != nil {
		t.Fatal(err)
	}
	if sess.TTLSeconds != int(session.DefaultTTL.Seconds()) {
		t.Fatalf("ttl = %d, want %d", sess.TTLSeconds, int(session.DefaultTTL.Seconds()))
	}
}

func TestNewManager_CustomTTL(t *testing.T) {
	m := session.NewManager(t.TempDir(), 30*time.Minute)
	if err := m.Save("test", "key"); err != nil {
		t.Fatal(err)
	}
	sess, _ := m.Load("test")
	if sess.TTLSeconds != 1800 {
		t.Fatalf("ttl = %d, want 1800", sess.TTLSeconds)
	}
}

func TestSaveAndLoad(t *testing.T) {
	dir := t.TempDir()
	m := session.NewManager(dir, time.Hour)

	if err := m.Save("bitwarden", "session-key-123"); err != nil {
		t.Fatal(err)
	}

	sess, err := m.Load("bitwarden")
	if err != nil {
		t.Fatal(err)
	}
	if sess.Key != "session-key-123" {
		t.Fatalf("key = %q, want %q", sess.Key, "session-key-123")
	}
	if sess.Provider != "bitwarden" {
		t.Fatalf("provider = %q, want %q", sess.Provider, "bitwarden")
	}
	if sess.IsExpired() {
		t.Fatal("session should not be expired")
	}
}

func TestLoad_NotFound(t *testing.T) {
	m := session.NewManager(t.TempDir(), time.Hour)
	_, err := m.Load("nonexistent")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestLoad_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "session-bad.json"), []byte("{corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := session.NewManager(dir, time.Hour)
	_, err := m.Load("bad")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestIsExpired(t *testing.T) {
	expired := &session.Session{
		Key:        "old",
		CreatedAt:  time.Now().Add(-2 * time.Hour),
		TTLSeconds: 3600,
	}
	if !expired.IsExpired() {
		t.Fatal("should be expired")
	}

	fresh := &session.Session{
		Key:        "new",
		CreatedAt:  time.Now(),
		TTLSeconds: 3600,
	}
	if fresh.IsExpired() {
		t.Fatal("should not be expired")
	}
}

func TestClear(t *testing.T) {
	dir := t.TempDir()
	m := session.NewManager(dir, time.Hour)

	m.Save("test", "key")
	if err := m.Clear("test"); err != nil {
		t.Fatal(err)
	}
	_, err := m.Load("test")
	if err == nil {
		t.Fatal("expected error after clear")
	}
}

func TestClear_NonexistentIsOK(t *testing.T) {
	m := session.NewManager(t.TempDir(), time.Hour)
	if err := m.Clear("nonexistent"); err != nil {
		t.Fatalf("clearing nonexistent should succeed, got %v", err)
	}
}

func TestResolve_ExplicitWins(t *testing.T) {
	m := session.NewManager(t.TempDir(), time.Hour)
	t.Setenv("CREDKIT_SESS", "from-env")
	m.Save("test", "cached")

	key, err := m.Resolve("test", "explicit-val", "CREDKIT_SESS")
	if err != nil {
		t.Fatal(err)
	}
	if key != "explicit-val" {
		t.Fatalf("key = %q, want %q", key, "explicit-val")
	}
}

func TestResolve_EnvFallback(t *testing.T) {
	m := session.NewManager(t.TempDir(), time.Hour)
	t.Setenv("CREDKIT_SESS", "from-env")

	key, err := m.Resolve("test", "", "CREDKIT_SESS")
	if err != nil {
		t.Fatal(err)
	}
	if key != "from-env" {
		t.Fatalf("key = %q, want %q", key, "from-env")
	}
}

func TestResolve_CachedFallback(t *testing.T) {
	dir := t.TempDir()
	m := session.NewManager(dir, time.Hour)
	t.Setenv("CREDKIT_SESS_UNUSED", "")

	m.Save("test", "cached-key")

	key, err := m.Resolve("test", "", "CREDKIT_SESS_UNUSED")
	if err != nil {
		t.Fatal(err)
	}
	if key != "cached-key" {
		t.Fatalf("key = %q, want %q", key, "cached-key")
	}
}

func TestResolve_ExpiredCacheReturnsEmpty(t *testing.T) {
	dir := t.TempDir()
	// Very short TTL so it expires immediately.
	m := session.NewManager(dir, time.Nanosecond)
	m.Save("test", "expired-key")
	time.Sleep(time.Millisecond)

	key, err := m.Resolve("test", "")
	if err != nil {
		t.Fatal(err)
	}
	if key != "" {
		t.Fatalf("key = %q, want empty for expired", key)
	}
}

func TestResolve_NoCacheReturnsEmpty(t *testing.T) {
	m := session.NewManager(t.TempDir(), time.Hour)
	key, err := m.Resolve("test", "")
	if err != nil {
		t.Fatal(err)
	}
	if key != "" {
		t.Fatalf("key = %q, want empty", key)
	}
}

func TestEmptyProvider_UsesDefaultPath(t *testing.T) {
	dir := t.TempDir()
	m := session.NewManager(dir, time.Hour)

	m.Save("", "default-key")
	sess, err := m.Load("")
	if err != nil {
		t.Fatal(err)
	}
	if sess.Key != "default-key" {
		t.Fatalf("key = %q, want %q", sess.Key, "default-key")
	}

	// Verify it's at session.json, not session-.json.
	if _, err := os.Stat(filepath.Join(dir, "session.json")); err != nil {
		t.Fatal("expected session.json file")
	}
}

func TestNamedProvider_UsesSeparateFile(t *testing.T) {
	dir := t.TempDir()
	m := session.NewManager(dir, time.Hour)

	m.Save("bw", "bw-key")
	m.Save("cf", "cf-key")

	bw, _ := m.Load("bw")
	cf, _ := m.Load("cf")
	if bw.Key != "bw-key" || cf.Key != "cf-key" {
		t.Fatalf("separate providers should have separate files")
	}
}
