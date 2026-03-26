// Package sts defines a portable Security Token Service contract.
//
// Providers implement the [Provider] interface to issue, revoke, list, and validate
// scoped tokens for a specific service (e.g., Cloudflare, SonarCloud).
// Auth credentials are injected at provider construction, keeping the interface clean.
package sts

import "context"

// Provider issues, revokes, lists, and validates tokens for a specific service.
// Implementations receive their authentication (e.g., master/GOD token) at
// construction time, so method signatures stay clean.
type Provider interface {
	// Name returns the provider identifier (e.g., "cloudflare", "sonarcloud").
	Name() string

	// Issue creates a new scoped token.
	Issue(ctx context.Context, req *IssueRequest) (*Token, error)

	// Revoke deletes a token by its provider-native identifier.
	Revoke(ctx context.Context, tokenID string) error

	// List returns all tokens managed by this provider.
	List(ctx context.Context) ([]*Token, error)

	// Validate checks whether a token value is still valid.
	Validate(ctx context.Context, tokenValue string) error
}
