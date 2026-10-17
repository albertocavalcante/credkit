package store_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/albertocavalcante/credkit/store"

	"golang.org/x/sys/windows"
)

func TestWindowsPrivateInheritedStorageRoundTrip(t *testing.T) {
	parent := windowsPrivateRoot(t)
	root, err := os.MkdirTemp(parent, "inherited-")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("inherited private root descriptor: %s", windowsDescriptor(t, root))
	if err := store.WriteSecureAt(root, "managed/secret", []byte("synthetic")); err != nil {
		t.Fatal(err)
	}
	data, err := store.ReadSecureAt(root, "managed/secret")
	if err != nil || string(data) != "synthetic" {
		t.Fatalf("private inherited storage unreadable: %q %v", data, err)
	}
}

func TestWindowsPrivateACLReadOnlyAccessDoesNotMutate(t *testing.T) {
	root := windowsPrivateRoot(t)
	name := "managed/secret"
	if err := store.WriteSecureAt(root, name, []byte("synthetic")); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, name)
	f, err := store.OpenAppendSecure(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(" appended"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0400); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0600) })
	before := windowsDescriptor(t, path)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	data, err := store.ReadSecureAt(root, name)
	if err != nil || string(data) != "synthetic appended" {
		t.Fatalf("private read-only value unreadable: %q %v", data, err)
	}
	entries, err := store.ReadDirSecureAt(root, "managed")
	if err != nil || len(entries) != 1 || !store.ExistsSecureAt(root, name) {
		t.Fatalf("private listing/existence failed: %v %v", entries, err)
	}
	after, err := os.Stat(path)
	if err != nil || after.Mode() != info.Mode() || windowsDescriptor(t, path) != before {
		t.Fatal("read-only access changed file attributes or security descriptor")
	}
}

func TestWindowsBroadACLReadsFailWithoutMutation(t *testing.T) {
	for _, kind := range []string{"root", "directory", "file"} {
		t.Run(kind, func(t *testing.T) {
			root := windowsPrivateRoot(t)
			if err := store.WriteSecureAt(root, "managed/secret", []byte("synthetic")); err != nil {
				t.Fatal(err)
			}
			target := root
			switch kind {
			case "directory":
				target = filepath.Join(root, "managed")
			case "file":
				target = filepath.Join(root, "managed/secret")
			}
			windowsSetDACL(t, target, windowsPrivateDACL(t)+"(A;OICI;GR;;;WD)")
			before := windowsDescriptor(t, target)
			data, err := store.ReadSecureAt(root, "managed/secret")
			if !errors.Is(err, store.ErrUnsafePath) || len(data) != 0 {
				t.Fatalf("broad ACL exposed credential: %q %v", data, err)
			}
			if store.ExistsSecureAt(root, "managed/secret") {
				t.Fatal("broad ACL reported as securely existing")
			}
			if kind != "file" {
				if _, err := store.ReadDirSecureAt(root, "managed"); !errors.Is(err, store.ErrUnsafePath) {
					t.Fatalf("listing accepted broad ACL: %v", err)
				}
			}
			if windowsDescriptor(t, target) != before {
				t.Fatal("read-only access changed ACL")
			}
		})
	}
}

func TestWindowsBroadParentCannotCreateCredential(t *testing.T) {
	for _, grant := range []string{"(A;OICI;GR;;;WD)", "(A;OICIIO;GR;;;WD)"} {
		t.Run(grant, func(t *testing.T) {
			root := windowsPrivateRoot(t)
			windowsSetDACL(t, root, windowsPrivateDACL(t)+grant)
			before := windowsDescriptor(t, root)
			if err := store.WriteSecureAt(root, "secret", []byte("synthetic")); !errors.Is(err, store.ErrUnsafePath) {
				t.Fatalf("unsafe ACL write returned %v", err)
			}
			if _, err := os.Stat(filepath.Join(root, "secret")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("write created a credential in unsafe ACL boundary: %v", err)
			}
			if windowsDescriptor(t, root) != before {
				t.Fatal("write silently repaired unsupported ACL policy")
			}
		})
	}
}

func TestWindowsNullDACLIsUnsafe(t *testing.T) {
	root := windowsPrivateRoot(t)
	if err := store.WriteSecureAt(root, "secret", []byte("synthetic")); err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(root, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	before := windowsDescriptor(t, root)
	data, err := store.ReadSecureAt(root, "secret")
	if !errors.Is(err, store.ErrUnsafePath) || !bytes.Equal(data, nil) {
		t.Fatalf("null DACL accepted: %q %v", data, err)
	}
	if windowsDescriptor(t, root) != before {
		t.Fatal("read repaired null DACL")
	}
}

func windowsPrivateRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	windowsSetDACL(t, root, windowsPrivateDACL(t))
	return root
}

func windowsPrivateDACL(t *testing.T) string {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	return "D:P(A;OICI;FA;;;" + user.User.Sid.String() + ")(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
}

func windowsSetDACL(t *testing.T, path, sddl string) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
}

func windowsDescriptor(t *testing.T, path string) string {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	return sd.String()
}
