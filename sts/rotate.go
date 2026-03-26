package sts

import (
	"context"
	"fmt"
	"time"

	"github.com/albertocavalcante/credkit/audit"
	"github.com/albertocavalcante/credkit/token"
)

// RotateOption configures rotation behavior.
type RotateOption func(*rotateConfig)

type rotateConfig struct {
	transition time.Duration
	ledger     *token.Ledger
	audit      *audit.Logger
	source     string
}

// WithTransition sets the duration to wait between issuing the new token
// and revoking the old one. This allows in-flight requests using the old
// token to complete (1Password pattern). Default is 0 (immediate).
func WithTransition(d time.Duration) RotateOption {
	return func(c *rotateConfig) { c.transition = d }
}

// WithLedger records the rotation in the token ledger.
func WithLedger(l *token.Ledger) RotateOption {
	return func(c *rotateConfig) { c.ledger = l }
}

// WithAudit logs the rotation to the audit log.
func WithAudit(l *audit.Logger, source string) RotateOption {
	return func(c *rotateConfig) { c.audit = l; c.source = source }
}

// Rotate atomically replaces a token: issue new → validate new → revoke old.
// If the new token fails validation, the old token is left intact.
func Rotate(ctx context.Context, p Provider, oldID string, req *IssueRequest, opts ...RotateOption) (*RotateResult, error) {
	var cfg rotateConfig
	for _, o := range opts {
		o(&cfg)
	}

	providerName := p.Name()

	// 1. Issue new token.
	newToken, err := p.Issue(ctx, req)
	if err != nil {
		logAudit(cfg, "rotate:issue", providerName, req.Name, false, err.Error())
		return nil, fmt.Errorf("rotate: issue new token: %w", err)
	}

	// 2. Validate new token.
	if err := p.Validate(ctx, newToken.Value); err != nil {
		// New token is broken — revoke it and abort.
		_ = p.Revoke(ctx, newToken.ID)
		logAudit(cfg, "rotate:validate", providerName, newToken.Name, false, err.Error())
		return nil, fmt.Errorf("rotate: new token failed validation: %w", err)
	}

	// 3. Transition window (if configured).
	if cfg.transition > 0 {
		select {
		case <-time.After(cfg.transition):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	// 4. Revoke old token.
	if err := p.Revoke(ctx, oldID); err != nil {
		logAudit(cfg, "rotate:revoke", providerName, oldID, false, err.Error())
		return nil, fmt.Errorf("rotate: revoke old token %s: %w", oldID, err)
	}

	// 5. Record in ledger and audit.
	if cfg.ledger != nil {
		_ = cfg.ledger.Record(&token.Metadata{
			Provider:  providerName,
			Name:      newToken.Name,
			ID:        newToken.ID,
			IssuedAt:  newToken.IssuedAt,
			ExpiresAt: newToken.ExpiresAt,
			Scope:     newToken.Scope,
			Source:    cfg.source,
		})
		_ = cfg.ledger.Remove(providerName, oldID)
	}
	logAudit(cfg, "rotate", providerName, newToken.Name, true, "")

	return &RotateResult{
		Old: &Token{Name: oldID, ID: oldID, Provider: providerName},
		New: newToken,
	}, nil
}

func logAudit(cfg rotateConfig, action, provider, tokenName string, success bool, errMsg string) {
	if cfg.audit == nil {
		return
	}
	_ = cfg.audit.Log(audit.Entry{
		Action:    action,
		Provider:  provider,
		TokenName: tokenName,
		Success:   success,
		Error:     errMsg,
		Source:    cfg.source,
	})
}
