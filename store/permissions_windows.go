package store

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows mode bits describe the read-only attribute, not access control.
// Validate the opened object's ACL for both reads and writes. ACL provisioning
// is explicit: this package never repairs DACLs or changes read-only attributes.
func securePermissions(f *os.File, _ os.FileInfo, _ os.FileMode, _ bool) error {
	user, err := windows.GetCurrentThreadEffectiveToken().GetTokenUser()
	if err != nil {
		return fmt.Errorf("query effective Windows user: %w", err)
	}
	sd, err := windows.GetSecurityInfo(windows.Handle(f.Fd()), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("query storage security descriptor: %w", err)
	}
	return validateWindowsDescriptor(sd, user.User.Sid)
}

func validateWindowsDescriptor(sd *windows.SECURITY_DESCRIPTOR, currentUser *windows.SID) error {
	if sd == nil || !sd.IsValid() || currentUser == nil || !currentUser.IsValid() {
		return ErrUnsafePath
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil || !owner.IsValid() || !trustedWindowsPrincipal(owner, currentUser) {
		return ErrUnsafePath
	}
	dacl, _, err := sd.DACL()
	// An absent or null DACL allows unrestricted access. A present empty ACL
	// grants nothing; unlike a null ACL, it is safe (but IO may be denied).
	if err != nil || dacl == nil {
		return ErrUnsafePath
	}
	control, _, err := sd.Control()
	if err != nil || control&windows.SE_SELF_RELATIVE == 0 {
		return ErrUnsafePath
	}
	base, length := uintptr(unsafe.Pointer(sd)), uintptr(sd.Length())
	for i := range int(dacl.AceCount) {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(i), &ace); err != nil || ace == nil {
			return ErrUnsafePath
		}
		// The descriptors returned by GetSecurityInfo and the SDDL parser are
		// self-relative. Bound native ACE views to that owned descriptor buffer.
		address := uintptr(unsafe.Pointer(ace))
		if address < base || address-base > length || uintptr(unsafe.Sizeof(windows.ACE_HEADER{})) > length-(address-base) {
			return ErrUnsafePath
		}
		size := int(ace.Header.AceSize)
		if size < int(unsafe.Sizeof(windows.ACE_HEADER{})) || uintptr(size) > length-(address-base) {
			return ErrUnsafePath
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE:
			continue
		case windows.ACCESS_ALLOWED_ACE_TYPE:
			// The layout is ACE_HEADER, ACCESS_MASK, then a variable-sized SID.
			// Check its encoded length before passing it to Windows SID helpers.
			offset := int(unsafe.Offsetof(ace.SidStart))
			if size < offset+8 {
				return ErrUnsafePath
			}
			data := unsafe.Slice((*byte)(unsafe.Pointer(ace)), size)
			sidLength := 8 + 4*int(data[offset+1])
			if sidLength > size-offset {
				return ErrUnsafePath
			}
			sid := (*windows.SID)(unsafe.Pointer(&data[offset]))
			if !sid.IsValid() || !trustedWindowsPrincipal(sid, currentUser) {
				return ErrUnsafePath
			}
		default:
			// Object-specific, conditional and other ACE forms need additional
			// interpretation; fail closed rather than guess their effect.
			return ErrUnsafePath
		}
		// Do not skip INHERIT_ONLY grants. Broad child inheritance can expose
		// files created under a currently private directory.
	}
	return nil
}

func trustedWindowsPrincipal(sid, currentUser *windows.SID) bool {
	return sid.Equals(currentUser) || sid.IsWellKnown(windows.WinLocalSystemSid) || sid.IsWellKnown(windows.WinBuiltinAdministratorsSid)
}
