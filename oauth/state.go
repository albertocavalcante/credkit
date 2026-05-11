package oauth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
)

// stateBytes is the random-byte length passed to base64url. 32 random
// bytes encode to 43 base64url characters — sufficient to be unguessable
// per RFC 6749 §10.12.
const stateBytes = 32

// NewState returns a cryptographically random opaque value suitable for
// the OAuth 2.0 `state` parameter. Callers must store this value with the
// pending login (typically in the calling process's memory) and verify it
// matches the `state` returned to the redirect endpoint, to prevent CSRF
// per RFC 6749 §10.12.
func NewState() (string, error) {
	b := make([]byte, stateBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("oauth: read random: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// VerifyState compares the state value the caller generated (expected)
// against the state echoed back by the authorization server (got) using
// constant-time comparison. An empty expected value never verifies — the
// caller is responsible for tracking what state they sent.
//
// Use this after CallbackServer.Wait returns a CallbackResult:
//
//	expected, _ := oauth.NewState()
//	authURL := cfg.AuthCodeURL(expected, pkce)
//	// ... open authURL in browser; wait for callback ...
//	res, err := srv.Wait(ctx)
//	if err != nil { ... }
//	if err := oauth.VerifyState(expected, res.State); err != nil {
//	    // possible CSRF attempt: abort
//	}
func VerifyState(expected, got string) error {
	if expected == "" {
		return errors.New("oauth: expected state is empty (caller did not track state)")
	}
	if subtle.ConstantTimeCompare([]byte(expected), []byte(got)) != 1 {
		return errors.New("oauth: state mismatch (possible CSRF)")
	}
	return nil
}
