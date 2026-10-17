package store_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/albertocavalcante/credkit/store"
)

func TestXDGConfigDir_WithEnv(t *testing.T) {
	base := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", base)
	dir, err := store.XDGConfigDir("myapp")
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(base, "myapp"); dir != want {
		t.Fatalf("got %s, want %s", dir, want)
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
	if perm := info.Mode().Perm(); runtime.GOOS != "windows" && perm != store.FilePerm {
		t.Fatalf("file perm = %o, want %o", perm, store.FilePerm)
	}

	dirInfo, err := os.Stat(filepath.Join(dir, "a", "b"))
	if err != nil {
		t.Fatal(err)
	}
	if perm := dirInfo.Mode().Perm(); runtime.GOOS != "windows" && perm != store.DirPerm {
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

func TestWriteSecure_RepairsExistingPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission repair; Windows uses explicit ACL provisioning")
	}
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := store.WriteSecure(path, []byte("new")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != store.FilePerm {
		t.Fatalf("file perm = %o, want %o", got, store.FilePerm)
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
	if perm := info.Mode().Perm(); runtime.GOOS != "windows" && perm != store.DirPerm {
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
	if runtime.GOOS == "windows" {
		return // Windows idempotence is checked above; chmod is not ACL repair.
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := store.EnsureDir(dir); err != nil {
		t.Fatal("permission repair should succeed:", err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != store.DirPerm {
		t.Fatalf("dir perm = %o, want %o", got, store.DirPerm)
	}
}

func TestWriteSecure_BadPath(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocker, nil, 0600); err != nil {
		t.Fatal(err)
	}
	err := store.WriteSecure(filepath.Join(blocker, "impossible", "file"), []byte("x"))
	if err == nil {
		t.Fatal("expected error for bad path")
	}
}

func TestEnsureDir_BadPath(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocker, nil, 0600); err != nil {
		t.Fatal(err)
	}
	err := store.EnsureDir(filepath.Join(blocker, "sub"))
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
