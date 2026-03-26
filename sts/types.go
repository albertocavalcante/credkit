package sts

import "time"

// IssueRequest describes the token to create.
type IssueRequest struct {
	Name       string            // Optional; provider may auto-generate.
	Scope      map[string]string // Provider-specific scoping (e.g., {"project": "myapp"}, {"zone": "example.com"}).
	TTL        time.Duration     // 0 = provider default or no expiry.
	Labels     map[string]string // Optional metadata stored alongside the token.
	AllowedIPs []string          // Optional IP restrictions (CIDR).
}

// Token is the result of a successful issuance or a list entry.
type Token struct {
	Value     string            // The secret value (only present on Issue, empty on List).
	Name      string            // Human-readable token name.
	ID        string            // Provider-native identifier (used for Revoke).
	Provider  string            // Provider name (e.g., "cloudflare").
	Scope     map[string]string // Scoping parameters.
	IssuedAt  time.Time         // When the token was created.
	ExpiresAt *time.Time        // When the token expires (nil = never).
}

// RotateResult holds the outcome of an atomic rotation.
type RotateResult struct {
	Old *Token // The revoked token (Value is empty).
	New *Token // The newly issued token.
}

// HealthReport summarizes the validation state of tracked tokens.
type HealthReport struct {
	Provider     string        // Provider name.
	Valid        []TokenStatus // Tokens that validated successfully.
	Invalid      []TokenStatus // Tokens that failed validation.
	Expired      []TokenStatus // Tokens past their ExpiresAt.
	ExpiringSoon []TokenStatus // Tokens expiring within the check window.
}

// TokenStatus pairs a token name/ID with its validation outcome.
type TokenStatus struct {
	Name  string
	ID    string
	Error string // Empty if valid.
}

// Counts returns total, valid, invalid, expired, expiring-soon counts.
func (r *HealthReport) Counts() (total, valid, invalid, expired, expiringSoon int) {
	valid = len(r.Valid)
	invalid = len(r.Invalid)
	expired = len(r.Expired)
	expiringSoon = len(r.ExpiringSoon)
	total = valid + invalid + expired + expiringSoon
	return
}
