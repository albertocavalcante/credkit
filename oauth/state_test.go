package oauth

import (
	"strings"
	"testing"
)

func TestNewStateLengthAndCharset(t *testing.T) {
	s, err := NewState()
	if err != nil {
		t.Fatalf("NewState: %v", err)
	}
	// RFC 6749 §10.12 does not mandate a length, but the state must be
	// unguessable. base64url(random(32)) gives 43 characters of entropy.
	if len(s) < 32 {
		t.Errorf("state too short: %d", len(s))
	}
	const allowed = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	for _, r := range s {
		if !strings.ContainsRune(allowed, r) {
			t.Errorf("state contains disallowed rune %q", r)
		}
	}
}

func TestNewStateUnique(t *testing.T) {
	seen := make(map[string]struct{}, 16)
	for i := 0; i < 16; i++ {
		s, err := NewState()
		if err != nil {
			t.Fatalf("NewState: %v", err)
		}
		if _, dup := seen[s]; dup {
			t.Fatalf("duplicate state generated: %s", s)
		}
		seen[s] = struct{}{}
	}
}

func TestVerifyStateMatch(t *testing.T) {
	if err := VerifyState("abc", "abc"); err != nil {
		t.Errorf("equal states should verify, got %v", err)
	}
}

func TestVerifyStateMismatch(t *testing.T) {
	if err := VerifyState("abc", "xyz"); err == nil {
		t.Error("mismatched states should not verify")
	}
}

func TestVerifyStateEmpty(t *testing.T) {
	// Empty expected state is a programming error — caller forgot to
	// supply one. Treat as mismatch rather than allowing through.
	if err := VerifyState("", "anything"); err == nil {
		t.Error("empty expected state should not verify against any callback value")
	}
}
