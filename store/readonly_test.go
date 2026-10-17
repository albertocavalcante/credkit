//go:build !windows

package store_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/albertocavalcante/credkit/store"
)

func TestReadOnlyOperationsRejectUnsafeModesWithoutRepair(t *testing.T) {
	operations := []struct {
		name string
		run  func(string) error
	}{
		{"read", func(root string) error { _, err := store.ReadSecureAt(root, "managed/secret"); return err }},
		{"list", func(root string) error { _, err := store.ReadDirSecureAt(root, "managed"); return err }},
		{"exists", func(root string) error {
			if store.ExistsSecureAt(root, "managed/secret") {
				return nil
			}
			return store.ErrUnsafePath
		}},
	}
	for _, operation := range operations {
		for _, kind := range []string{"root", "directory", "file"} {
			// Listing validates its directory, not the modes of un-opened entries.
			if operation.name == "list" && kind == "file" {
				continue
			}
			t.Run(operation.name+"/"+kind, func(t *testing.T) {
				root := t.TempDir()
				if err := store.WriteSecureAt(root, "managed/secret", []byte("synthetic")); err != nil {
					t.Fatal(err)
				}
				target, mode := root, os.FileMode(0755)
				switch kind {
				case "directory":
					target = filepath.Join(root, "managed")
				case "file":
					target, mode = filepath.Join(root, "managed/secret"), 0644
				}
				if err := os.Chmod(target, mode); err != nil {
					t.Fatal(err)
				}
				err := operation.run(root)
				if !errors.Is(err, store.ErrUnsafePath) {
					t.Errorf("got %v, want ErrUnsafePath", err)
				}
				info, err := os.Stat(target)
				if err != nil {
					t.Fatal(err)
				}
				if info.Mode().Perm() != mode {
					t.Errorf("read-only %s changed %s mode from %o to %o", operation.name, kind, mode, info.Mode().Perm())
				}
			})
		}
	}
}

func TestReadOnlyOperationsPreservePrivateReadOnlyModes(t *testing.T) {
	root := t.TempDir()
	if err := store.WriteSecureAt(root, "managed/secret", []byte("synthetic")); err != nil {
		t.Fatal(err)
	}
	for path, mode := range map[string]os.FileMode{filepath.Join(root, "managed/secret"): 0400, filepath.Join(root, "managed"): 0500, root: 0500} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_ = os.Chmod(root, 0700)
		_ = os.Chmod(filepath.Join(root, "managed"), 0700)
	})
	link := filepath.Join(t.TempDir(), "trusted-root")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	for _, boundary := range []string{root, link} {
		data, err := store.ReadSecureAt(boundary, "managed/secret")
		if err != nil || string(data) != "synthetic" {
			t.Fatalf("private read-only storage unreadable: %q %v", data, err)
		}
		entries, err := store.ReadDirSecureAt(boundary, "managed")
		if err != nil || len(entries) != 1 || !store.ExistsSecureAt(boundary, "managed/secret") {
			t.Fatalf("private listing/existence failed: entries=%v err=%v", entries, err)
		}
	}
	for path, want := range map[string]os.FileMode{filepath.Join(root, "managed/secret"): 0400, filepath.Join(root, "managed"): 0500, root: 0500} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != want {
			t.Fatalf("private read-only mode changed: %s %v %v", path, info, err)
		}
	}
}

func TestExplicitWritesStillRepairUnsafePermissions(t *testing.T) {
	for _, appendMode := range []bool{false, true} {
		t.Run(map[bool]string{false: "rooted replacement", true: "append"}[appendMode], func(t *testing.T) {
			root := t.TempDir()
			name := "managed/secret"
			if appendMode {
				name = "secret"
			}
			if err := store.WriteSecureAt(root, name, []byte("old")); err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(root, name)
			if err := os.Chmod(file, 0644); err != nil {
				t.Fatal(err)
			}
			parents := []string{root}
			if !appendMode {
				parents = append(parents, filepath.Join(root, "managed"))
			}
			for _, parent := range parents {
				if err := os.Chmod(parent, 0755); err != nil {
					t.Fatal(err)
				}
			}
			if appendMode {
				f, err := store.OpenAppendSecure(file)
				if err != nil {
					t.Fatal(err)
				}
				_, writeErr := f.WriteString("new")
				closeErr := f.Close()
				if writeErr != nil || closeErr != nil {
					t.Fatalf("append: %v, close: %v", writeErr, closeErr)
				}
			} else if err := store.WriteSecureAt(root, name, []byte("new")); err != nil {
				t.Fatal(err)
			}
			for _, parent := range parents {
				info, err := os.Stat(parent)
				if err != nil || info.Mode().Perm() != store.DirPerm {
					t.Fatalf("write did not secure parent: %s %v %v", parent, info, err)
				}
			}
			info, err := os.Stat(file)
			if err != nil || info.Mode().Perm() != store.FilePerm {
				t.Fatalf("write did not secure file: %v %v", info, err)
			}
		})
	}
}

func TestRemovalDoesNotRepairParentPermissions(t *testing.T) {
	root := t.TempDir()
	if err := store.WriteSecureAt(root, "secret", []byte("synthetic")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0755); err != nil {
		t.Fatal(err)
	}
	if err := store.RemoveSecureAt(root, "secret"); !errors.Is(err, store.ErrUnsafePath) {
		t.Fatalf("got %v, want unsafe parent rejection", err)
	}
	info, err := os.Stat(root)
	if err != nil || info.Mode().Perm() != 0755 {
		t.Fatalf("removal repaired parent: %v %v", info, err)
	}
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	// Removing a broadly readable leaf requires no exposure of its contents.
	if err := os.Chmod(filepath.Join(root, "secret"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := store.RemoveSecureAt(root, "secret"); err != nil {
		t.Fatal(err)
	}
}

func TestEnsureDirCanRepairOwnerInaccessibleMode(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(root, 0700) })
	if err := store.EnsureDir(root); err != nil {
		t.Fatalf("explicit directory repair failed: %v", err)
	}
	info, err := os.Stat(root)
	if err != nil || info.Mode().Perm() != store.DirPerm {
		t.Fatalf("directory remains inaccessible: %v %v", info, err)
	}
}
