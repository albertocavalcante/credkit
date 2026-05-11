package oauth

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
)

func TestNewVerifierLengthAndAlphabet(t *testing.T) {
	v, err := NewVerifier()
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	// RFC 7636 §4.1: verifier length MUST be 43..128.
	if len(v) < 43 || len(v) > 128 {
		t.Errorf("verifier length %d outside [43,128]", len(v))
	}
	// Alphabet: A-Z / a-z / 0-9 / -._~
	allowed := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
	for _, r := range v {
		if !strings.ContainsRune(allowed, r) {
			t.Errorf("verifier contains disallowed rune %q", r)
		}
	}
}

func TestNewVerifierUnique(t *testing.T) {
	seen := make(map[string]struct{}, 16)
	for i := 0; i < 16; i++ {
		v, err := NewVerifier()
		if err != nil {
			t.Fatalf("NewVerifier: %v", err)
		}
		if _, dup := seen[v]; dup {
			t.Fatalf("duplicate verifier generated: %s", v)
		}
		seen[v] = struct{}{}
	}
}

func TestChallengeS256(t *testing.T) {
	v := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" // RFC 7636 §4.4 example
	c, err := Challenge(v, MethodS256)
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	want := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	if c != want {
		t.Errorf("Challenge(S256) = %q, want %q", c, want)
	}
	// Recompute for sanity.
	sum := sha256.Sum256([]byte(v))
	check := base64.RawURLEncoding.EncodeToString(sum[:])
	if c != check {
		t.Errorf("Challenge does not match base64url(sha256(verifier))")
	}
}

func TestChallengePlainRejected(t *testing.T) {
	// We deliberately do NOT support the deprecated "plain" method to keep
	// callers on the secure path. Document the contract via a test.
	_, err := Challenge("verifier", MethodPlain)
	if err == nil {
		t.Fatal("expected error for MethodPlain (deprecated by RFC 7636 best practice)")
	}
}

func TestChallengeUnknownMethod(t *testing.T) {
	_, err := Challenge("verifier", Method("S128"))
	if err == nil {
		t.Fatal("expected error for unknown method")
	}
}

func TestVerifierChallengePair(t *testing.T) {
	pair, err := NewPKCE()
	if err != nil {
		t.Fatalf("NewPKCE: %v", err)
	}
	if pair.Verifier == "" || pair.Challenge == "" {
		t.Fatal("NewPKCE returned empty fields")
	}
	if pair.Method != MethodS256 {
		t.Errorf("expected Method=%q, got %q", MethodS256, pair.Method)
	}
	// Challenge must reproduce from verifier.
	c, err := Challenge(pair.Verifier, pair.Method)
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	if c != pair.Challenge {
		t.Errorf("Challenge does not match Verifier: %q vs %q", c, pair.Challenge)
	}
}
