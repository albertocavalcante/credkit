// Package oauth provides OAuth 2.0 client primitives for credkit:
// PKCE, authorization-code flow, token refresh, and provider configuration.
//
// Designed to be the credential-acquisition layer that complements credkit's
// existing storage (store), lookup (resolve), profile (profile), and audit
// (audit) packages. Issued tokens can be recorded in token.Ledger for
// expiry monitoring.
//
// Subscription auth (Anthropic Claude Pro/Max, ChatGPT Plus Codex) is the
// primary motivating use case; the package is provider-agnostic and any
// OAuth 2.0 + PKCE compliant authorization server is supported.
package oauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
)

// Method is the PKCE code-challenge method.
type Method string

const (
	// MethodS256 is the only secure PKCE method (RFC 7636 §4.2). Always prefer this.
	MethodS256 Method = "S256"

	// MethodPlain is deprecated and rejected by this package. The constant
	// is exported so callers can detect and explicitly reject it.
	MethodPlain Method = "plain"
)

// PKCE pairs a code verifier with its derived challenge.
type PKCE struct {
	Verifier  string
	Challenge string
	Method    Method
}

// pkceVerifierBytes is the random-byte length passed to base64url encoding.
// 32 random bytes encode to 43 base64url characters (no padding), which is
// the minimum verifier length per RFC 7636 §4.1.
const pkceVerifierBytes = 32

// NewVerifier returns a freshly-generated PKCE code verifier per RFC 7636 §4.1.
// The verifier is 43 unreserved characters drawn from base64url(random(32)).
func NewVerifier() (string, error) {
	b := make([]byte, pkceVerifierBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("pkce: read random: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Challenge derives the PKCE code challenge for the given verifier and method.
// Only MethodS256 is supported; MethodPlain and unknown methods return an error.
func Challenge(verifier string, method Method) (string, error) {
	switch method {
	case MethodS256:
		sum := sha256.Sum256([]byte(verifier))
		return base64.RawURLEncoding.EncodeToString(sum[:]), nil
	case MethodPlain:
		return "", errors.New("pkce: MethodPlain is deprecated by RFC 7636 §7.2; use MethodS256")
	default:
		return "", fmt.Errorf("pkce: unknown method %q", method)
	}
}

// NewPKCE generates a fresh verifier and its S256 challenge.
func NewPKCE() (PKCE, error) {
	v, err := NewVerifier()
	if err != nil {
		return PKCE{}, err
	}
	c, err := Challenge(v, MethodS256)
	if err != nil {
		return PKCE{}, err
	}
	return PKCE{Verifier: v, Challenge: c, Method: MethodS256}, nil
}
