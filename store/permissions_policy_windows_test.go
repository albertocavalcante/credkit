package store

import (
	"errors"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsDescriptorPolicy(t *testing.T) {
	user, err := windows.GetCurrentThreadEffectiveToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	current := user.User.Sid.String()
	for _, tc := range []struct {
		name, sddl string
		unsafe     bool
	}{
		{"current user", "O:" + current + "D:P(A;;FA;;;" + current + ")", false},
		{"private read only", "O:" + current + "D:P(A;;FR;;;" + current + ")", false},
		{"privileged owner and principals", "O:BAD:P(A;;FA;;;" + current + ")(A;;FA;;;SY)(A;;FA;;;BA)", false},
		{"untrusted owner", "O:WDD:P(A;;FA;;;" + current + ")", true},
		{"another user owner", "O:S-1-5-21-1-2-3-1234D:P(A;;FA;;;" + current + ")", true},
		{"another user grant", "O:" + current + "D:P(A;;FA;;;" + current + ")(A;;FR;;;S-1-5-21-1-2-3-1234)", true},
		{"everyone", "O:" + current + "D:P(A;;FA;;;" + current + ")(A;;FR;;;WD)", true},
		{"inherit only broad grant", "O:" + current + "D:P(A;;FA;;;" + current + ")(A;OICIIO;FR;;;WD)", true},
		{"object-specific allow", "O:" + current + "D:P(OA;;FR;00000000-0000-0000-0000-000000000001;;" + current + ")", true},
		{"present empty DACL", "O:" + current + "D:P", false},
		{"missing DACL", "O:" + current, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sd, err := windows.SecurityDescriptorFromString(tc.sddl)
			if err != nil {
				t.Fatal(err)
			}
			if tc.name == "object-specific allow" {
				dacl, _, err := sd.DACL()
				if err != nil {
					t.Fatal(err)
				}
				var ace *windows.ACCESS_ALLOWED_ACE
				if err := windows.GetAce(dacl, 0, &ace); err != nil {
					t.Fatal(err)
				}
				// ACCESS_ALLOWED_OBJECT_ACE_TYPE from WinNT.h is 5.
				if ace.Header.AceType != 5 {
					t.Fatalf("object-specific fixture normalized to ACE type %d", ace.Header.AceType)
				}
			}
			err = validateWindowsDescriptor(sd, user.User.Sid)
			if tc.unsafe && !errors.Is(err, ErrUnsafePath) {
				t.Fatalf("unsafe descriptor accepted: %v", err)
			}
			if !tc.unsafe && err != nil {
				t.Fatalf("private descriptor refused: %v", err)
			}
		})
	}
}
