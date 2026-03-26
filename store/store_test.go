package store_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/albertocavalcante/credkit/store"
)

func TestXDGConfigDir_WithEnv(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "/tmp/xdg-test")
	dir, err := store.XDGConfigDir("myapp")
	if err != nil {
		t.Fatal(err)
	}
	if dir != "/tmp/xdg-test/myapp" {
		t.Fatalf("got %s, want /tmp/xdg-test/myapp", dir)
	}
}

func TestXDGConfigDir_Fallback(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "")
	dir, err := store.XDGConfigDir("myapp")
	if err != nil {
		t.Fatal(err)
	}
	home, _ := os.UserHomeDir()
	want := filepath.Join(home, ".config", "myapp")
	if dir != want {
		t.Fatalf("got %s, want %s", dir, want)
	}
}

func TestWriteSecure_CreatesParentDirs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a", "b", "secret.txt")
	data := []byte("s3cret")

	if err := store.WriteSecure(path, data); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != store.FilePerm {
		t.Fatalf("file perm = %o, want %o", perm, store.FilePerm)
	}

	dirInfo, err := os.Stat(filepath.Join(dir, "a", "b"))
	if err != nil {
		t.Fatal(err)
	}
	if perm := dirInfo.Mode().Perm(); perm != store.DirPerm {
		t.Fatalf("dir perm = %o, want %o", perm, store.DirPerm)
	}
}

func TestWriteSecure_Overwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	if err := store.WriteSecure(path, []byte("first")); err != nil {
		t.Fatal(err)
	}
	if err := store.WriteSecure(path, []byte("second")); err != nil {
		t.Fatal(err)
	}
	got, _ := store.ReadSecure(path)
	if string(got) != "second" {
		t.Fatalf("got %q, want %q", got, "second")
	}
}

func TestReadSecure_Success(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	want := []byte("hello")
	if err := store.WriteSecure(path, want); err != nil {
		t.Fatal(err)
	}
	got, err := store.ReadSecure(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestReadSecure_NotFound(t *testing.T) {
	_, err := store.ReadSecure(filepath.Join(t.TempDir(), "nonexistent"))
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestEnsureDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "a", "b", "c")
	if err := store.EnsureDir(dir); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsDir() {
		t.Fatal("expected directory")
	}
	if perm := info.Mode().Perm(); perm != store.DirPerm {
		t.Fatalf("dir perm = %o, want %o", perm, store.DirPerm)
	}
}

func TestEnsureDir_Idempotent(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "x")
	if err := store.EnsureDir(dir); err != nil {
		t.Fatal(err)
	}
	if err := store.EnsureDir(dir); err != nil {
		t.Fatal("second call should succeed:", err)
	}
}

func TestWriteSecure_BadPath(t *testing.T) {
	// Writing to /dev/null/impossible should fail at dir creation.
	err := store.WriteSecure("/dev/null/impossible/file", []byte("x"))
	if err == nil {
		t.Fatal("expected error for bad path")
	}
}

func TestEnsureDir_BadPath(t *testing.T) {
	// /dev/null is not a directory — can't create subdirs under it.
	err := store.EnsureDir("/dev/null/sub")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestExists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file")

	if store.Exists(path) {
		t.Fatal("should not exist yet")
	}

	if err := store.WriteSecure(path, []byte("x")); err != nil {
		t.Fatal(err)
	}

	if !store.Exists(path) {
		t.Fatal("should exist after write")
	}

	if store.Exists(filepath.Join(dir, "nonexistent")) {
		t.Fatal("nonexistent should not exist")
	}
}
