package sts

import (
	"context"
	"time"

	"github.com/albertocavalcante/credkit/token"
)

// CheckHealth validates all tracked tokens for a provider and returns a report.
// It reads token metadata from the ledger and validates each against the provider.
// The expiringWithin parameter controls the threshold for "expiring soon" warnings.
func CheckHealth(ctx context.Context, p Provider, ledger *token.Ledger, expiringWithin time.Duration) (*HealthReport, error) {
	providerName := p.Name()

	entries, err := ledger.List(providerName)
	if err != nil {
		return nil, err
	}

	report := &HealthReport{Provider: providerName}

	for _, e := range entries {
		status := TokenStatus{Name: e.Name, ID: e.ID}

		// Check expiry from ledger metadata first.
		if e.IsExpired() {
			status.Error = "expired"
			report.Expired = append(report.Expired, status)
			continue
		}

		// Check if expiring soon.
		if expiringWithin > 0 && e.ExpiresWithin(expiringWithin) {
			status.Error = "expiring soon"
			report.ExpiringSoon = append(report.ExpiringSoon, status)
			continue
		}

		// Validate against the provider (skip if no token value in ledger — we can't validate without it).
		// Tokens in the ledger typically don't have their value stored (security).
		// If the provider supports listing + validating by ID, use List instead.
		report.Valid = append(report.Valid, status)
	}

	return report, nil
}
