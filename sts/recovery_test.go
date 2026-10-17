package sts_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/albertocavalcante/credkit/audit"
	"github.com/albertocavalcante/credkit/sts"
	"github.com/albertocavalcante/credkit/token"
)

func TestRotateReturnsReplacementOnRevocationFailure(t *testing.T) {
	p := newMockProvider()
	cause := errors.New("old revoke failed")
	p.revokeFunc = func(context.Context, string) error { return cause }
	got, err := sts.Rotate(t.Context(), p, "old-id", &sts.IssueRequest{Name: "new"})
	if !errors.Is(err, cause) || got == nil || got.New == nil || got.New.Value == "" {
		t.Fatalf("lost recovery state: got=%+v err=%v", got, err)
	}
	if !got.NewValidated || got.OldRevoked {
		t.Fatalf("incorrect progress: %+v", got)
	}
}

func TestRotateCanceledTransitionReturnsReplacement(t *testing.T) {
	p := newMockProvider()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	p.validateFunc = func(context.Context, string) error { cancel(); return nil }
	got, err := sts.Rotate(ctx, p, "old-id", &sts.IssueRequest{Name: "new"}, sts.WithTransition(time.Hour))
	if !errors.Is(err, context.Canceled) || got == nil || got.New == nil || got.OldRevoked {
		t.Fatalf("got=%+v err=%v", got, err)
	}
}

func TestRotateRollbackPreservesBothErrors(t *testing.T) {
	p := newMockProvider()
	validation := errors.New("validation failed")
	rollback := errors.New("rollback failed")
	p.validateFunc = func(context.Context, string) error { return validation }
	p.revokeFunc = func(context.Context, string) error { return rollback }
	got, err := sts.Rotate(t.Context(), p, "old-id", &sts.IssueRequest{Name: "new"})
	if !errors.Is(err, validation) || !errors.Is(err, rollback) || got == nil || got.New == nil || got.NewRevoked {
		t.Fatalf("got=%+v err=%v", got, err)
	}
}

func TestRotateRollbackUsesLiveBoundedContext(t *testing.T) {
	p := newMockProvider()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	cleaned := false
	p.validateFunc = func(context.Context, string) error { cancel(); return context.Canceled }
	p.revokeFunc = func(cleanup context.Context, id string) error {
		if cleanup.Err() != nil {
			return cleanup.Err()
		}
		deadline, ok := cleanup.Deadline()
		if !ok || time.Until(deadline) > 6*time.Second {
			t.Error("cleanup context is not bounded")
		}
		cleaned = id == "new-id"
		return nil
	}
	got, err := sts.Rotate(ctx, p, "old-id", &sts.IssueRequest{Name: "new"})
	if !errors.Is(err, context.Canceled) || !cleaned || got == nil || !got.NewRevoked {
		t.Fatalf("got=%+v cleaned=%v err=%v", got, cleaned, err)
	}
}

func TestRotateStopsBeforeOldRevocationWhenRecordingFails(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, nil, 0600); err != nil {
		t.Fatal(err)
	}
	p := newMockProvider()
	revokedOld := false
	p.revokeFunc = func(_ context.Context, id string) error { revokedOld = id == "old-id"; return nil }
	got, err := sts.Rotate(t.Context(), p, "old-id", &sts.IssueRequest{Name: "new"}, sts.WithLedger(token.NewLedger(filepath.Join(blocker, "ledger.json"))))
	if err == nil || revokedOld || got == nil || got.New == nil || got.LedgerRecorded {
		t.Fatalf("got=%+v revokedOld=%v err=%v", got, revokedOld, err)
	}
}

func TestRotateReturnsPostRevocationPersistenceFailures(t *testing.T) {
	for _, kind := range []string{"remove", "audit"} {
		t.Run(kind, func(t *testing.T) {
			p := newMockProvider()
			path := filepath.Join(t.TempDir(), "ledger.json")
			ledger := token.NewLedger(path)
			opts := []sts.RotateOption{sts.WithLedger(ledger)}
			if kind == "remove" {
				p.revokeFunc = func(context.Context, string) error { return os.WriteFile(path, []byte("broken"), 0600) }
			} else {
				blocker := filepath.Join(t.TempDir(), "file")
				if err := os.WriteFile(blocker, nil, 0600); err != nil {
					t.Fatal(err)
				}
				opts = append(opts, sts.WithAudit(audit.NewLogger(filepath.Join(blocker, "log")), "test"))
			}
			got, err := sts.Rotate(t.Context(), p, "old-id", &sts.IssueRequest{Name: "new"}, opts...)
			if err == nil || got == nil || !got.OldRevoked || !got.LedgerRecorded {
				t.Fatalf("got=%+v err=%v", got, err)
			}
		})
	}
}

func TestRotateRejectsInvalidReplacementWithoutRevokingOld(t *testing.T) {
	for _, replacement := range []*sts.Token{nil, {ID: "old-id", Value: "new"}, {ID: "new-id"}, {Value: "new"}} {
		p := newMockProvider()
		p.issueFunc = func(context.Context, *sts.IssueRequest) (*sts.Token, error) { return replacement, nil }
		revoked := false
		p.revokeFunc = func(context.Context, string) error { revoked = true; return nil }
		got, err := sts.Rotate(t.Context(), p, "old-id", &sts.IssueRequest{Name: "new"})
		if err == nil || got == nil || revoked {
			t.Fatalf("got=%+v err=%v revoked=%v", got, err, revoked)
		}
	}
}

func TestRotateReportsCompletedProgress(t *testing.T) {
	dir := t.TempDir()
	got, err := sts.Rotate(t.Context(), newMockProvider(), "old-id", &sts.IssueRequest{Name: "new"}, sts.WithLedger(token.NewLedger(filepath.Join(dir, "ledger.json"))), sts.WithAudit(audit.NewLogger(filepath.Join(dir, "audit.log")), "test"))
	if err != nil {
		t.Fatal(err)
	}
	if !got.NewValidated || got.NewRevoked || !got.OldRevoked || !got.LedgerRecorded || !got.OldLedgerRemoved || !got.AuditLogged {
		t.Fatalf("incorrect completed progress: %+v", got)
	}
}
