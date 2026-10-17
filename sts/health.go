package sts

import (
	"context"
	"time"

	"github.com/albertocavalcante/credkit/token"
)

// CheckHealth classifies tracked token expiry metadata for a provider.
// Ledger entries contain no secret values, so this function cannot establish
// remote validity. Nonexpiring entries are reported as Unknown, never Valid.
// The expiringWithin parameter controls the threshold for "expiring soon" warnings.
func CheckHealth(ctx context.Context, p Provider, ledger *token.Ledger, expiringWithin time.Duration) (*HealthReport, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	providerName := p.Name()

	entries, err := ledger.List(providerName)
	if err != nil {
		return nil, err
	}

	report := &HealthReport{Provider: providerName}

	for _, e := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
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

		status.Error = "not validated"
		report.Unknown = append(report.Unknown, status)
	}

	return report, nil
}
