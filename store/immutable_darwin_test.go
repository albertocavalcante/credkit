package store_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/albertocavalcante/credkit/store"
)

func TestSecureReadDoesNotChmodAlreadySafeImmutableStorage(t *testing.T) {
	for _, kind := range []string{"file", "directory"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(root, "secret")
			if err := os.WriteFile(path, []byte("synthetic"), 0400); err != nil {
				t.Fatal(err)
			}
			target := path
			if kind == "directory" {
				target = root
			}
			if err := exec.Command("/usr/bin/chflags", "uchg", target).Run(); err != nil {
				t.Skipf("immutable fixture unsupported: %v", err)
			}
			t.Cleanup(func() {
				if err := exec.Command("/usr/bin/chflags", "nouchg", target).Run(); err != nil {
					t.Errorf("clear immutable fixture: %v", err)
				}
			})
			if got, err := os.ReadFile(path); err != nil || string(got) != "synthetic" {
				t.Fatalf("fixture unreadable: %q %v", got, err)
			}
			got, err := store.ReadSecureAt(root, "secret")
			if err != nil || string(got) != "synthetic" {
				t.Fatalf("safe immutable storage unreadable: %q %v", got, err)
			}
		})
	}
}
