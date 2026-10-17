package store_test

import (
	"errors"
	"os"
	"runtime"
	"syscall"
	"testing"
)

func symlinkOrSkip(t *testing.T, oldPath, newPath string) {
	t.Helper()
	if err := os.Symlink(oldPath, newPath); err != nil {
		// ERROR_PRIVILEGE_NOT_HELD: an unavailable fixture, not permission to
		// skip errors on platforms where symlink creation normally works.
		if runtime.GOOS == "windows" && errors.Is(err, syscall.Errno(1314)) {
			t.Skipf("Windows symlink fixture requires privilege: %v", err)
		}
		t.Fatal(err)
	}
}
