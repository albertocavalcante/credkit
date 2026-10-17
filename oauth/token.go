package oauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"
)

// Token is an OAuth 2.0 token returned by an authorization server.
//
// Extra preserves provider-specific fields (e.g. "id_token" for OIDC,
// vendor-specific claims) that the standard fields do not model. Callers
// can extract these as needed for provider adapters.
type Token struct {
	AccessToken  string         `json:"-"`
	RefreshToken string         `json:"-"`
	TokenType    string         `json:"-"`
	Scope        string         `json:"-"`
	ExpiresAt    time.Time      `json:"-"`
	Extra        map[string]any `json:"-"`
}

// Expired reports whether the access token's known expiry is in the past.
// A zero ExpiresAt is treated as "no known expiry" and reports false; the
// authorization server is the source of truth in that case.
func (t *Token) Expired() bool {
	if t.ExpiresAt.IsZero() {
		return false
	}
	return time.Now().After(t.ExpiresAt)
}

// tokenWire is the JSON shape per RFC 6749 §5.1. Used for both parse and
// the public Token.Extra population. ExpiresIn is relative-seconds; we
// convert to absolute ExpiresAt at parse time.
type tokenWire struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	Scope        string `json:"scope"`
	ExpiresIn    int64  `json:"expires_in"`
}

// UnmarshalJSON parses a standard OAuth 2.0 token response and preserves
// any non-standard fields in Extra. Called by encoding/json automatically;
// also used directly by Exchange/Refresh. Successful parsing replaces the
// previous value, including derived expiry and Extra fields; failure leaves it intact.
func (t *Token) UnmarshalJSON(data []byte) error {
	var wire tokenWire
	if err := json.Unmarshal(data, &wire); err != nil {
		return fmt.Errorf("oauth: unmarshal token: %w", err)
	}
	var all map[string]any
	if err := json.Unmarshal(data, &all); err != nil {
		return fmt.Errorf("oauth: unmarshal token extras: %w", err)
	}
	for _, k := range []string{"access_token", paramRefreshToken, "token_type", "scope", "expires_in"} {
		delete(all, k)
	}
	if wire.ExpiresIn > math.MaxInt64/int64(time.Second) {
		return errors.New("oauth: expires_in exceeds supported duration")
	}
	parsed := Token{AccessToken: wire.AccessToken, RefreshToken: wire.RefreshToken, TokenType: wire.TokenType, Scope: wire.Scope}
	if wire.ExpiresIn > 0 {
		parsed.ExpiresAt = time.Now().Add(time.Duration(wire.ExpiresIn) * time.Second)
	}
	if len(all) > 0 {
		parsed.Extra = all
	}
	*t = parsed
	return nil
}

// TokenError is a structured error returned by the authorization server.
// It implements RFC 6749 §5.2 (OAuth 2.0 error response) when the response
// body is parseable, and falls back to HTTPStatus + Body for non-compliant
// servers.
type TokenError struct {
	Code        string // RFC 6749 §5.2 error code (e.g. "invalid_grant")
	Description string // optional human-readable description
	URI         string // optional documentation URI
	HTTPStatus  int    // HTTP status code from the token endpoint
	Body        []byte // raw response body for diagnostics
}

func (e *TokenError) Error() string {
	switch {
	case e.Code != "" && e.Description != "":
		return fmt.Sprintf("oauth: token endpoint returned %s: %s", e.Code, e.Description)
	case e.Code != "":
		return fmt.Sprintf("oauth: token endpoint returned %s", e.Code)
	case e.HTTPStatus != 0:
		return fmt.Sprintf("oauth: token endpoint returned HTTP %d", e.HTTPStatus)
	default:
		return "oauth: token endpoint error"
	}
}
