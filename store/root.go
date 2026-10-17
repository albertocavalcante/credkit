package store

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// openDirectory treats rootDir as a caller-trusted boundary, including an
// intentional symlink there. Descendants must be real directories within it.
func openDirectory(rootDir, name string, create bool) (*os.Root, error) {
	if !filepath.IsLocal(name) {
		return nil, ErrUnsafePath
	}
	if create {
		if err := os.MkdirAll(rootDir, DirPerm); err != nil {
			return nil, fmt.Errorf("create storage root: %w", err)
		}
	}
	r, err := os.OpenRoot(rootDir)
	if err != nil {
		return nil, fmt.Errorf("open storage root: %w", err)
	}
	if err := secureDirectory(r, nil, create); err != nil {
		_ = r.Close()
		return nil, err
	}
	for _, part := range strings.Split(filepath.Clean(name), string(filepath.Separator)) {
		if part == "." {
			continue
		}
		info, err := r.Lstat(part)
		if errors.Is(err, fs.ErrNotExist) && create {
			if err = r.Mkdir(part, DirPerm); err == nil || errors.Is(err, fs.ErrExist) {
				info, err = r.Lstat(part)
			}
		}
		if err != nil {
			_ = r.Close()
			return nil, fmt.Errorf("inspect storage directory: %w", err)
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			_ = r.Close()
			return nil, ErrUnsafePath
		}
		next, err := r.OpenRoot(part)
		_ = r.Close()
		if err != nil {
			return nil, fmt.Errorf("open storage directory: %w", err)
		}
		r = next
		if err := secureDirectory(r, info, create); err != nil {
			_ = r.Close()
			return nil, err
		}
	}
	return r, nil
}

func secureDirectory(r *os.Root, expected os.FileInfo, create bool) error {
	f, err := r.Open(".")
	if err != nil {
		return fmt.Errorf("open directory handle: %w", err)
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("inspect directory handle: %w", err)
	}
	if !info.IsDir() || (expected != nil && !os.SameFile(info, expected)) {
		return ErrUnsafePath
	}
	mode := info.Mode().Perm() & DirPerm
	if create {
		mode = DirPerm
	}
	if mode != info.Mode().Perm() {
		if !create {
			return ErrUnsafePath
		}
		if err := f.Chmod(mode); err != nil {
			return fmt.Errorf("secure directory handle: %w", err)
		}
	}
	return nil
}

func openParent(rootDir, name string, create bool) (*os.Root, string, error) {
	if !filepath.IsLocal(name) {
		return nil, "", ErrUnsafePath
	}
	r, err := openDirectory(rootDir, filepath.Dir(name), create)
	return r, filepath.Base(name), err
}

func regularInfo(r *os.Root, name string) (os.FileInfo, error) {
	info, err := r.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, ErrUnsafePath
	}
	return info, nil
}

// WriteSecureAt atomically replaces a regular file beneath a trusted root.
// name must be relative. Managed descendant directories cannot be symlinks.
func WriteSecureAt(rootDir, name string, data []byte) error {
	r, base, err := openParent(rootDir, name, true)
	if err != nil {
		return err
	}
	defer func() { _ = r.Close() }()
	if _, err = regularInfo(r, base); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("inspect destination: %w", err)
	}
	temporary := ".credkit-write-" + rand.Text()
	f, err := r.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, FilePerm)
	if err != nil {
		return fmt.Errorf("create temporary credential file: %w", err)
	}
	defer func() { _ = r.Remove(temporary) }()
	defer func() { _ = f.Close() }()
	if err := f.Chmod(FilePerm); err != nil {
		return fmt.Errorf("secure temporary credential file: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("write credential file: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync credential file: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close credential file: %w", err)
	}
	if err := r.Rename(temporary, base); err != nil {
		return fmt.Errorf("replace credential file: %w", err)
	}
	return nil
}

// openManagedFile verifies file identity before chmod or IO. Exclusive creation
// prevents a missing-file check from following a subsequently inserted symlink.
func openManagedFile(r *os.Root, name string, flags int, create bool) (*os.File, error) {
	for range 2 {
		info, err := regularInfo(r, name)
		openFlags := flags
		if errors.Is(err, fs.ErrNotExist) && create {
			openFlags |= os.O_CREATE | os.O_EXCL
		} else if err != nil {
			return nil, err
		}
		f, err := r.OpenFile(name, openFlags, FilePerm)
		if errors.Is(err, fs.ErrExist) && info == nil {
			continue
		}
		if err != nil {
			return nil, err
		}
		opened, err := f.Stat()
		if err != nil {
			_ = f.Close()
			return nil, err
		}
		if !opened.Mode().IsRegular() || (info != nil && !os.SameFile(info, opened)) {
			_ = f.Close()
			return nil, ErrUnsafePath
		}
		mode := opened.Mode().Perm() & FilePerm
		if flags&(os.O_WRONLY|os.O_RDWR) != 0 {
			mode = FilePerm
		}
		if mode != opened.Mode().Perm() {
			if flags&(os.O_WRONLY|os.O_RDWR) == 0 {
				_ = f.Close()
				return nil, ErrUnsafePath
			}
			if err := f.Chmod(mode); err != nil {
				_ = f.Close()
				return nil, err
			}
		}
		return f, nil
	}
	return nil, fmt.Errorf("secure file changed during creation: %w", ErrUnsafePath)
}

// ReadSecureAt reads an owner-only regular file beneath the trusted root.
// Unsafe permissions return ErrUnsafePath; reads never repair permissions.
func ReadSecureAt(rootDir, name string) ([]byte, error) {
	r, base, err := openParent(rootDir, name, false)
	if err != nil {
		return nil, err
	}
	defer func() { _ = r.Close() }()
	f, err := openManagedFile(r, base, os.O_RDONLY, false)
	if err != nil {
		return nil, fmt.Errorf("open credential file: %w", err)
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("read credential file: %w", err)
	}
	return data, nil
}

// RemoveSecureAt removes a regular file beneath the trusted root.
// Parent directories must already be owner-only; removal never repairs modes.
func RemoveSecureAt(rootDir, name string) error {
	r, base, err := openParent(rootDir, name, false)
	if err != nil {
		return err
	}
	defer func() { _ = r.Close() }()
	if _, err := regularInfo(r, base); err != nil {
		return err
	}
	return r.Remove(base)
}

// ReadDirSecureAt lists a real managed directory in filename order.
// The root and managed directories must already be owner-only. Modes are unchanged.
func ReadDirSecureAt(rootDir, name string) ([]fs.DirEntry, error) {
	r, err := openDirectory(rootDir, name, false)
	if err != nil {
		return nil, err
	}
	defer func() { _ = r.Close() }()
	return fs.ReadDir(r.FS(), ".")
}

// ExistsSecureAt reports whether an owner-only regular file exists beneath the root.
// Unsafe paths or permissions report false without changing filesystem modes.
func ExistsSecureAt(rootDir, name string) bool {
	r, base, err := openParent(rootDir, name, false)
	if err != nil {
		return false
	}
	defer func() { _ = r.Close() }()
	info, err := regularInfo(r, base)
	return err == nil && info.Mode().Perm()&^FilePerm == 0
}

// OpenAppendSecure opens an owner-only regular file for append. Its parent is
// caller-trusted; existing file symlinks and nonregular targets are rejected.
// The caller owns closing the returned file.
func OpenAppendSecure(path string) (*os.File, error) {
	dir := filepath.Dir(path)
	if err := EnsureDir(dir); err != nil {
		return nil, err
	}
	r, base, err := openParent(dir, filepath.Base(path), true)
	if err != nil {
		return nil, err
	}
	defer func() { _ = r.Close() }()
	f, err := openManagedFile(r, base, os.O_APPEND|os.O_WRONLY, true)
	if err != nil {
		return nil, fmt.Errorf("open secure append file: %w", err)
	}
	return f, nil
}
