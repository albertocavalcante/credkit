package audit_test

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/albertocavalcante/credkit/audit"
)

func TestLogRepairsExistingFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mode repair; Windows append ACLs are checked by the native store suite")
	}
	path := filepath.Join(t.TempDir(), "audit.log")
	if err := os.WriteFile(path, nil, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if err := audit.NewLogger(path).Log(audit.Entry{Action: "login"}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("permissions remain %o", info.Mode().Perm())
	}
}

func TestLogRejectsSymlinkAndNonregularTargets(t *testing.T) {
	t.Run("symlink", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "target")
		link := filepath.Join(dir, "audit.log")
		if err := os.WriteFile(target, []byte("untouched"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, link); err != nil {
			if runtime.GOOS == "windows" && errors.Is(err, syscall.Errno(1314)) {
				t.Skipf("Windows symlink fixture requires privilege: %v", err)
			}
			t.Fatal(err)
		}
		if err := audit.NewLogger(link).Log(audit.Entry{Action: "login"}); err == nil {
			t.Fatal("followed audit symlink")
		}
		got, err := os.ReadFile(target)
		if err != nil || string(got) != "untouched" {
			t.Fatalf("target changed: %q %v", got, err)
		}
	})
	t.Run("directory", func(t *testing.T) {
		if err := audit.NewLogger(t.TempDir()).Log(audit.Entry{Action: "login"}); err == nil {
			t.Fatal("accepted directory as log")
		}
	})
}

func TestConcurrentLogCreationDoesNotLoseEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	start := make(chan struct{})
	done := make(chan error, 32)
	for range 32 {
		go func() { <-start; done <- audit.NewLogger(path).Log(audit.Entry{Action: "login"}) }()
	}
	close(start)
	for range 32 {
		if err := <-done; err != nil {
			t.Error(err)
		}
	}
	entries, err := audit.NewLogger(path).Query(time.Time{}, "")
	if err != nil || len(entries) != 32 {
		t.Fatalf("entries=%d err=%v", len(entries), err)
	}
}
