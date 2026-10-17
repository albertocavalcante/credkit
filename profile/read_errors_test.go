package profile_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/albertocavalcante/credkit/profile"
	"github.com/albertocavalcante/credkit/store"
)

func TestLoadPreservesUnderlyingStorageError(t *testing.T) {
	dir := t.TempDir()
	m := profile.NewManagerWithDir(dir)
	if _, err := m.Load("missing"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing error lost: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "profiles", "work.json"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Load("work"); !errors.Is(err, store.ErrUnsafePath) {
		t.Fatalf("unsafe-path error lost: %v", err)
	}
}

func TestActiveReadFailureNeverSelectsDefault(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "active-profile"), 0700); err != nil {
		t.Fatal(err)
	}
	name, err := profile.NewManagerWithDir(dir).Active()
	if err == nil || name != "" {
		t.Fatalf("name=%q err=%v", name, err)
	}
}

func TestDeleteReportsActiveMarkerFailure(t *testing.T) {
	dir := t.TempDir()
	m := profile.NewManagerWithDir(dir)
	if err := m.Save("work", &profile.Profile{}); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "active-profile"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := m.Delete("work"); err == nil {
		t.Fatal("active marker failure discarded")
	}
}
