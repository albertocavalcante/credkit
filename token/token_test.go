package token_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/albertocavalcante/credkit/token"
)

func newLedger(t *testing.T) *token.Ledger {
	t.Helper()
	return token.NewLedger(filepath.Join(t.TempDir(), "tokens.json"))
}

func TestRecord_And_List(t *testing.T) {
	l := newLedger(t)

	m := &token.Metadata{
		Provider: "sonarcloud",
		Name:     "cofre-sonarcloud-myapp",
		IssuedAt: time.Now().UTC(),
		Scope:    map[string]string{"project": "myapp"},
		Source:   "cofre",
	}
	if err := l.Record(m); err != nil {
		t.Fatal(err)
	}

	entries, err := l.List("sonarcloud")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1, got %d", len(entries))
	}
	if entries[0].Name != m.Name {
		t.Fatalf("name = %q, want %q", entries[0].Name, m.Name)
	}
}

func TestList_FilterByProvider(t *testing.T) {
	l := newLedger(t)
	l.Record(&token.Metadata{Provider: "sonarcloud", Name: "a"})
	l.Record(&token.Metadata{Provider: "cloudflare", Name: "b"})

	sc, _ := l.List("sonarcloud")
	if len(sc) != 1 || sc[0].Name != "a" {
		t.Fatalf("sonarcloud filter wrong: %+v", sc)
	}

	cf, _ := l.List("cloudflare")
	if len(cf) != 1 || cf[0].Name != "b" {
		t.Fatalf("cloudflare filter wrong: %+v", cf)
	}

	all, _ := l.List("")
	if len(all) != 2 {
		t.Fatalf("all should be 2, got %d", len(all))
	}
}

func TestList_Empty(t *testing.T) {
	l := newLedger(t)
	entries, err := l.List("")
	if err != nil {
		t.Fatal(err)
	}
	if entries != nil {
		t.Fatalf("expected nil for empty ledger, got %v", entries)
	}
}

func TestExpiring(t *testing.T) {
	l := newLedger(t)

	soon := time.Now().Add(3 * time.Hour)
	later := time.Now().Add(30 * 24 * time.Hour)

	l.Record(&token.Metadata{Provider: "a", Name: "expiring-soon", ExpiresAt: &soon})
	l.Record(&token.Metadata{Provider: "a", Name: "expiring-later", ExpiresAt: &later})
	l.Record(&token.Metadata{Provider: "a", Name: "no-expiry"})

	expiring, err := l.Expiring(7 * 24 * time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(expiring) != 1 || expiring[0].Name != "expiring-soon" {
		t.Fatalf("expected only expiring-soon, got %+v", expiring)
	}
}

func TestExpiring_IncludesAlreadyExpired(t *testing.T) {
	l := newLedger(t)
	past := time.Now().Add(-time.Hour)
	l.Record(&token.Metadata{Provider: "a", Name: "dead", ExpiresAt: &past})

	expiring, _ := l.Expiring(24 * time.Hour)
	if len(expiring) != 1 {
		t.Fatalf("expired tokens should be included, got %d", len(expiring))
	}
}

func TestExpiring_Empty(t *testing.T) {
	l := newLedger(t)
	expiring, err := l.Expiring(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if expiring != nil {
		t.Fatalf("expected nil, got %v", expiring)
	}
}

func TestRemove(t *testing.T) {
	l := newLedger(t)
	l.Record(&token.Metadata{Provider: "a", Name: "keep"})
	l.Record(&token.Metadata{Provider: "a", Name: "remove-me"})
	l.Record(&token.Metadata{Provider: "b", Name: "remove-me"}) // different provider, should stay

	if err := l.Remove("a", "remove-me"); err != nil {
		t.Fatal(err)
	}

	entries, _ := l.List("")
	if len(entries) != 2 {
		t.Fatalf("expected 2, got %d", len(entries))
	}
}

func TestRemove_Nonexistent(t *testing.T) {
	l := newLedger(t)
	l.Record(&token.Metadata{Provider: "a", Name: "x"})

	if err := l.Remove("a", "nonexistent"); err != nil {
		t.Fatal(err)
	}
	entries, _ := l.List("")
	if len(entries) != 1 {
		t.Fatalf("should still have 1 entry")
	}
}

func TestRecord_CorruptedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tokens.json")

	// Write corrupt data.
	os.WriteFile(path, []byte("{not-an-array}"), 0o600)

	l := token.NewLedger(path)
	err := l.Record(&token.Metadata{Provider: "a", Name: "b"})
	if err == nil {
		t.Fatal("expected error for corrupted ledger")
	}
}

func TestList_CorruptedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tokens.json")
	os.WriteFile(path, []byte("garbage"), 0o600)

	l := token.NewLedger(path)
	_, err := l.List("")
	if err == nil {
		t.Fatal("expected error for corrupted file")
	}
}

func TestMetadata_IsExpired(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	if m := (&token.Metadata{ExpiresAt: &past}); !m.IsExpired() {
		t.Fatal("should be expired")
	}

	future := time.Now().Add(time.Hour)
	if m := (&token.Metadata{ExpiresAt: &future}); m.IsExpired() {
		t.Fatal("should not be expired")
	}

	if m := (&token.Metadata{}); m.IsExpired() {
		t.Fatal("nil ExpiresAt should not be expired")
	}
}

func TestMetadata_ExpiresWithin(t *testing.T) {
	soon := time.Now().Add(2 * time.Hour)
	m := &token.Metadata{ExpiresAt: &soon}

	if !m.ExpiresWithin(3 * time.Hour) {
		t.Fatal("should expire within 3h")
	}
	if m.ExpiresWithin(1 * time.Hour) {
		t.Fatal("should NOT expire within 1h")
	}

	noExpiry := &token.Metadata{}
	if noExpiry.ExpiresWithin(24 * time.Hour) {
		t.Fatal("nil expiry should return false")
	}
}

func TestCleanup(t *testing.T) {
	l := newLedger(t)

	past := time.Now().Add(-time.Hour)
	future := time.Now().Add(7 * 24 * time.Hour)
	old := time.Now().Add(-60 * 24 * time.Hour)

	l.Record(&token.Metadata{Provider: "a", Name: "expired", ExpiresAt: &past, IssuedAt: time.Now()})
	l.Record(&token.Metadata{Provider: "a", Name: "old", IssuedAt: old})
	l.Record(&token.Metadata{Provider: "a", Name: "current", ExpiresAt: &future, IssuedAt: time.Now()})
	l.Record(&token.Metadata{Provider: "a", Name: "no-expiry", IssuedAt: time.Now()})

	removed, err := l.Cleanup(30 * 24 * time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if removed != 2 {
		t.Fatalf("expected 2 removed (expired + old), got %d", removed)
	}

	entries, _ := l.List("")
	if len(entries) != 2 {
		t.Fatalf("expected 2 remaining, got %d", len(entries))
	}
}

func TestCleanup_Empty(t *testing.T) {
	l := newLedger(t)
	removed, err := l.Cleanup(24 * time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if removed != 0 {
		t.Fatalf("expected 0, got %d", removed)
	}
}

func TestRemove_EmptyLedger(t *testing.T) {
	l := newLedger(t)
	if err := l.Remove("a", "b"); err != nil {
		t.Fatal(err)
	}
}

func TestRecord_ReadError(t *testing.T) {
	// Make ledger file unreadable.
	dir := t.TempDir()
	path := filepath.Join(dir, "tokens.json")
	os.WriteFile(path, []byte("[]"), 0o000)
	t.Cleanup(func() { os.Chmod(path, 0o600) })

	l := token.NewLedger(path)
	err := l.Record(&token.Metadata{Provider: "a", Name: "b"})
	if err == nil {
		t.Fatal("expected error for unreadable file")
	}
}

func TestFindByID(t *testing.T) {
	l := newLedger(t)
	l.Record(&token.Metadata{Provider: "a", Name: "tok-1", ID: "id-1"})
	l.Record(&token.Metadata{Provider: "a", Name: "tok-2", ID: "id-2"})
	l.Record(&token.Metadata{Provider: "b", Name: "tok-3", ID: "id-3"})

	// Find by ID.
	m, err := l.FindByID("a", "id-1")
	if err != nil {
		t.Fatal(err)
	}
	if m.Name != "tok-1" {
		t.Fatalf("name = %q", m.Name)
	}

	// Find by name (fallback).
	m, err = l.FindByID("a", "tok-2")
	if err != nil {
		t.Fatal(err)
	}
	if m.ID != "id-2" {
		t.Fatalf("id = %q", m.ID)
	}

	// Not found.
	_, err = l.FindByID("a", "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent")
	}

	// Wrong provider.
	_, err = l.FindByID("b", "id-1")
	if err == nil {
		t.Fatal("expected error for wrong provider")
	}
}

func TestList_ReadError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tokens.json")
	os.WriteFile(path, []byte("[]"), 0o000)
	t.Cleanup(func() { os.Chmod(path, 0o600) })

	l := token.NewLedger(path)
	_, err := l.List("")
	if err == nil {
		t.Fatal("expected error for unreadable file")
	}
}

func TestExpiring_ReadError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tokens.json")
	os.WriteFile(path, []byte("[]"), 0o000)
	t.Cleanup(func() { os.Chmod(path, 0o600) })

	l := token.NewLedger(path)
	_, err := l.Expiring(time.Hour)
	if err == nil {
		t.Fatal("expected error for unreadable file")
	}
}

func TestRemove_ReadError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tokens.json")
	os.WriteFile(path, []byte("[]"), 0o000)
	t.Cleanup(func() { os.Chmod(path, 0o600) })

	l := token.NewLedger(path)
	err := l.Remove("a", "b")
	if err == nil {
		t.Fatal("expected error for unreadable file")
	}
}

func TestExpiring_NonexistentFile(t *testing.T) {
	l := token.NewLedger(filepath.Join(t.TempDir(), "nope.json"))
	expiring, err := l.Expiring(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if expiring != nil {
		t.Fatalf("expected nil, got %v", expiring)
	}
}
