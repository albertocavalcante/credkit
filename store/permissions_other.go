//go:build !windows

package store

import "os"

// securePermissions validates read-only access and repairs modes only for IO
// that explicitly writes. Already-private owner read-only intent is preserved.
func securePermissions(f *os.File, info os.FileInfo, permitted os.FileMode, write bool) error {
	mode := info.Mode().Perm() & permitted
	if write {
		mode = permitted
	}
	if mode == info.Mode().Perm() {
		return nil
	}
	if !write {
		return ErrUnsafePath
	}
	return f.Chmod(mode)
}
