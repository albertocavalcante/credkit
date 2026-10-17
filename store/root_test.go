package store_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/albertocavalcante/credkit/profile"
	"github.com/albertocavalcante/credkit/store"
)

func TestProfileCredentialDirectoryCannotEscapeRoot(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	symlinkOrSkip(t, outside, filepath.Join(root, "credentials"))
	err := profile.NewManagerWithDir(root).SaveCredential("work", []byte("synthetic"))
	if err == nil {
		t.Fatal("credential escaped configured application root")
	}
	if _, err := os.Stat(filepath.Join(outside, "work")); !os.IsNotExist(err) {
		t.Fatalf("outside file was created: %v", err)
	}
}

func TestProfileRejectsInternalDirectorySymlink(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "other"), 0700); err != nil {
		t.Fatal(err)
	}
	symlinkOrSkip(t, "other", filepath.Join(root, "credentials"))
	if err := profile.NewManagerWithDir(root).SaveCredential("work", nil); err == nil {
		t.Fatal("accepted descendant directory symlink")
	}
}

func TestProfileAllowsIntentionalRootSymlink(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	link := filepath.Join(root, "configured-root")
	symlinkOrSkip(t, outside, link)
	if err := profile.NewManagerWithDir(link).SaveCredential("work", []byte("synthetic")); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(outside, "credentials", "work"))
	if err != nil || string(got) != "synthetic" {
		t.Fatalf("got %q %v", got, err)
	}
}

func TestSecureWriteStillAtomicallyReplacesRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	if err := store.WriteSecure(path, []byte("old")); err != nil {
		t.Fatal(err)
	}
	if err := store.WriteSecure(path, []byte("new")); err != nil {
		t.Fatal(err)
	}
	got, err := store.ReadSecure(path)
	if err != nil || string(got) != "new" {
		t.Fatalf("got %q %v", got, err)
	}
}

func TestProfileReadCannotFollowCredentialDirectorySymlink(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	if err := store.EnsureDir(root); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "work"), []byte("outside"), 0600); err != nil {
		t.Fatal(err)
	}
	symlinkOrSkip(t, outside, filepath.Join(root, "credentials"))
	if _, err := profile.NewManagerWithDir(root).LoadCredential("work"); err == nil {
		t.Fatal("read credential outside configured root")
	}
	if err := profile.NewManagerWithDir(root).Delete("work"); err == nil {
		t.Fatal("deleted through credential directory symlink")
	}
	if _, err := os.Stat(filepath.Join(outside, "work")); err != nil {
		t.Fatal("outside credential was removed")
	}
}

func TestProfileSecuresExistingRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mode repair; Windows unsafe ACL boundaries are rejected")
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0777); err != nil {
		t.Fatal(err)
	}
	if err := profile.NewManagerWithDir(root).SaveCredential("work", nil); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0700 {
		t.Fatalf("configured root remains %o", info.Mode().Perm())
	}
}

func TestRootedOperationsRejectTraversalAndFileSymlinks(t *testing.T) {
	t.Run("traversal", func(t *testing.T) {
		root := t.TempDir()
		for _, name := range []string{"../outside", "/outside"} {
			if err := store.WriteSecureAt(root, name, nil); err == nil {
				t.Errorf("write accepted %q", name)
			}
			if _, err := store.ReadSecureAt(root, name); err == nil {
				t.Errorf("read accepted %q", name)
			}
			if err := store.RemoveSecureAt(root, name); err == nil {
				t.Errorf("remove accepted %q", name)
			}
		}
	})
	t.Run("file symlink", func(t *testing.T) {
		root := t.TempDir()

		if err := store.WriteSecureAt(root, "target", []byte("untouched")); err != nil {
			t.Fatal(err)
		}
		symlinkOrSkip(t, "target", filepath.Join(root, "link"))
		if _, err := store.ReadSecureAt(root, "link"); err == nil {
			t.Fatal("read followed file symlink")
		}
		if err := store.WriteSecureAt(root, "link", nil); err == nil {
			t.Fatal("write accepted file symlink")
		}
		if err := store.RemoveSecureAt(root, "link"); err == nil {
			t.Fatal("remove accepted file symlink")
		}
		if store.ExistsSecureAt(root, "link") {
			t.Fatal("file symlink reported safe")
		}
	})
}

func TestConcurrentRootedWritesCreateSharedParents(t *testing.T) {
	root := t.TempDir()
	start := make(chan struct{})
	done := make(chan error, 64)
	for range 64 {
		go func() { <-start; done <- store.WriteSecureAt(root, "shared/deep/secret", []byte("complete")) }()
	}
	close(start)
	for range 64 {
		if err := <-done; err != nil {
			t.Error(err)
		}
	}
	data, err := store.ReadSecureAt(root, "shared/deep/secret")
	if err != nil || string(data) != "complete" {
		t.Fatalf("data=%q err=%v", data, err)
	}
}
