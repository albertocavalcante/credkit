package sts

import (
	"context"
	"errors"
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

// Rotate replaces a token with recoverable progress: issue, validate, record,
// transition, revoke old, and update records. After issuance, a non-nil result
// is returned even on failure; callers must inspect it before retrying. Provider
// operations and local persistence cannot form an atomic transaction.
func Rotate(ctx context.Context, p Provider, oldID string, req *IssueRequest, opts ...RotateOption) (*RotateResult, error) {
	if p == nil || req == nil || oldID == "" {
		return nil, errors.New("rotate: provider, request and old token ID are required")
	}
	var cfg rotateConfig
	for _, o := range opts {
		if o != nil {
			o(&cfg)
		}
	}
	if cfg.transition < 0 {
		return nil, errors.New("rotate: transition must not be negative")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	providerName := p.Name()
	var result *RotateResult
	finish := func(action, name string, cause error) (*RotateResult, error) {
		if cfg.audit != nil {
			auditErr := cfg.audit.Log(audit.Entry{Action: action, Provider: providerName, TokenName: name, Success: cause == nil, Error: errorText(cause), Source: cfg.source})
			if auditErr != nil {
				cause = errors.Join(cause, fmt.Errorf("rotate: audit: %w", auditErr))
			} else if result != nil {
				result.AuditLogged = true
			}
		}
		return result, cause
	}
	newToken, err := p.Issue(ctx, req)
	if err != nil {
		return finish("rotate:issue", req.Name, fmt.Errorf("rotate: issue new token: %w", err))
	}
	result = &RotateResult{Old: &Token{Name: oldID, ID: oldID, Provider: providerName}, New: newToken}
	if newToken == nil || newToken.ID == "" || newToken.Value == "" || newToken.ID == oldID {
		return finish("rotate:issue", req.Name, errors.New("rotate: provider returned an invalid replacement token"))
	}
	if err := p.Validate(ctx, newToken.Value); err != nil {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		rollbackErr := p.Revoke(cleanup, newToken.ID)
		cancel()
		result.NewRevoked = rollbackErr == nil
		cause := fmt.Errorf("rotate: new token failed validation: %w", err)
		if rollbackErr != nil {
			cause = errors.Join(cause, fmt.Errorf("rotate: revoke failed replacement: %w", rollbackErr))
		}
		return finish("rotate:validate", newToken.Name, cause)
	}
	result.NewValidated = true
	if cfg.ledger != nil {
		err := cfg.ledger.Record(&token.Metadata{Provider: providerName, Name: newToken.Name, ID: newToken.ID, IssuedAt: newToken.IssuedAt, ExpiresAt: newToken.ExpiresAt, Scope: newToken.Scope, Source: cfg.source})
		if err != nil {
			return finish("rotate:record", newToken.Name, fmt.Errorf("rotate: record replacement: %w", err))
		}
		result.LedgerRecorded = true
	}
	if cfg.transition > 0 {
		timer := time.NewTimer(cfg.transition)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			return finish("rotate:transition", newToken.Name, ctx.Err())
		}
	}
	if err := ctx.Err(); err != nil {
		return finish("rotate:transition", newToken.Name, err)
	}
	if err := p.Revoke(ctx, oldID); err != nil {
		return finish("rotate:revoke", oldID, fmt.Errorf("rotate: revoke old token: %w", err))
	}
	result.OldRevoked = true
	if cfg.ledger != nil {
		if err := cfg.ledger.RemoveByID(providerName, oldID); err != nil {
			return finish("rotate:record", newToken.Name, fmt.Errorf("rotate: remove old ledger entry: %w", err))
		}
		result.OldLedgerRemoved = true
	}
	return finish("rotate", newToken.Name, nil)
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
