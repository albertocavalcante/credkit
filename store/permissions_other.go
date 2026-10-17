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

// Preserve explicit POSIX repair even when the owner cannot open a directory
// until its permission bits are restored.
func secureDirectoryPath(path string, _ os.FileInfo) error {
	return os.Chmod(path, DirPerm)
}
