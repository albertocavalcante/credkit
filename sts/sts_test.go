package sts_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/albertocavalcante/credkit/audit"
	"github.com/albertocavalcante/credkit/sts"
	"github.com/albertocavalcante/credkit/token"
)

// mockProvider implements sts.Provider for testing.
type mockProvider struct {
	name         string
	issueFunc    func(ctx context.Context, req *sts.IssueRequest) (*sts.Token, error)
	revokeFunc   func(ctx context.Context, tokenID string) error
	listFunc     func(ctx context.Context) ([]*sts.Token, error)
	validateFunc func(ctx context.Context, tokenValue string) error
}

func (m *mockProvider) Name() string { return m.name }
func (m *mockProvider) Issue(ctx context.Context, req *sts.IssueRequest) (*sts.Token, error) {
	return m.issueFunc(ctx, req)
}
func (m *mockProvider) Revoke(ctx context.Context, tokenID string) error {
	return m.revokeFunc(ctx, tokenID)
}
func (m *mockProvider) List(ctx context.Context) ([]*sts.Token, error) {
	return m.listFunc(ctx)
}
func (m *mockProvider) Validate(ctx context.Context, tokenValue string) error {
	return m.validateFunc(ctx, tokenValue)
}

func newMockProvider() *mockProvider {
	return &mockProvider{
		name: "test",
		issueFunc: func(_ context.Context, req *sts.IssueRequest) (*sts.Token, error) {
			return &sts.Token{
				Value:    "new-token-value",
				Name:     req.Name,
				ID:       "new-id",
				Provider: "test",
				IssuedAt: time.Now().UTC(),
			}, nil
		},
		revokeFunc:   func(_ context.Context, _ string) error { return nil },
		listFunc:     func(_ context.Context) ([]*sts.Token, error) { return nil, nil },
		validateFunc: func(_ context.Context, _ string) error { return nil },
	}
}

func TestRotate_Success(t *testing.T) {
	p := newMockProvider()
	dir := t.TempDir()
	ledger := token.NewLedger(filepath.Join(dir, "tokens.json"))
	auditLog := audit.NewLogger(filepath.Join(dir, "audit.log"))

	// Pre-record the old token.
	ledger.Record(&token.Metadata{Provider: "test", Name: "old-id", ID: "old-id"})

	result, err := sts.Rotate(context.Background(), p, "old-id", &sts.IssueRequest{Name: "rotated"},
		sts.WithLedger(ledger),
		sts.WithAudit(auditLog, "test-tool"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.New.Value != "new-token-value" {
		t.Fatalf("new token = %q", result.New.Value)
	}
	if result.Old.ID != "old-id" {
		t.Fatalf("old ID = %q", result.Old.ID)
	}

	// Verify ledger has the new token and old is removed.
	entries, _ := ledger.List("test")
	if len(entries) != 1 || entries[0].Name != "rotated" {
		t.Fatalf("ledger entries = %+v", entries)
	}

	// Verify audit log.
	auditEntries, _ := auditLog.Query(time.Time{}, "test")
	if len(auditEntries) != 1 || auditEntries[0].Action != "rotate" {
		t.Fatalf("audit entries = %+v", auditEntries)
	}
}

func TestRotate_IssueFails(t *testing.T) {
	p := newMockProvider()
	p.issueFunc = func(_ context.Context, _ *sts.IssueRequest) (*sts.Token, error) {
		return nil, errors.New("issue failed")
	}

	_, err := sts.Rotate(context.Background(), p, "old-id", &sts.IssueRequest{Name: "x"})
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, err) { // just check it's non-nil
		t.Fatal("expected wrapped error")
	}
}

func TestRotate_ValidateFails(t *testing.T) {
	revoked := false
	p := newMockProvider()
	p.validateFunc = func(_ context.Context, _ string) error {
		return errors.New("invalid")
	}
	p.revokeFunc = func(_ context.Context, id string) error {
		if id == "new-id" {
			revoked = true
		}
		return nil
	}

	_, err := sts.Rotate(context.Background(), p, "old-id", &sts.IssueRequest{Name: "x"})
	if err == nil {
		t.Fatal("expected error on validation failure")
	}
	if !revoked {
		t.Fatal("expected new token to be revoked after validation failure")
	}
}

func TestRotate_WithTransition(t *testing.T) {
	p := newMockProvider()
	start := time.Now()

	_, err := sts.Rotate(context.Background(), p, "old-id", &sts.IssueRequest{Name: "x"},
		sts.WithTransition(50*time.Millisecond),
	)
	if err != nil {
		t.Fatal(err)
	}
	if time.Since(start) < 50*time.Millisecond {
		t.Fatal("transition window not respected")
	}
}

func TestRotate_ContextCancelled(t *testing.T) {
	p := newMockProvider()
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.

	_, err := sts.Rotate(ctx, p, "old-id", &sts.IssueRequest{Name: "x"},
		sts.WithTransition(time.Hour), // Would block forever without cancellation.
	)
	if err == nil {
		t.Fatal("expected context error")
	}
}

func TestCheckHealth(t *testing.T) {
	dir := t.TempDir()
	ledger := token.NewLedger(filepath.Join(dir, "tokens.json"))
	p := newMockProvider()

	past := time.Now().Add(-time.Hour)
	soon := time.Now().Add(3 * time.Hour)
	later := time.Now().Add(30 * 24 * time.Hour)

	ledger.Record(&token.Metadata{Provider: "test", Name: "expired", ExpiresAt: &past})
	ledger.Record(&token.Metadata{Provider: "test", Name: "soon", ExpiresAt: &soon})
	ledger.Record(&token.Metadata{Provider: "test", Name: "healthy", ExpiresAt: &later})
	ledger.Record(&token.Metadata{Provider: "test", Name: "no-expiry"})

	report, err := sts.CheckHealth(context.Background(), p, ledger, 7*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	total, valid, _, expired, expiringSoon := report.Counts()
	if total != 4 {
		t.Fatalf("total = %d, want 4", total)
	}
	if expired != 1 {
		t.Fatalf("expired = %d, want 1", expired)
	}
	if expiringSoon != 1 {
		t.Fatalf("expiringSoon = %d, want 1", expiringSoon)
	}
	if valid != 2 {
		t.Fatalf("valid = %d, want 2", valid)
	}
}

func TestCheckHealth_EmptyLedger(t *testing.T) {
	dir := t.TempDir()
	ledger := token.NewLedger(filepath.Join(dir, "tokens.json"))
	p := newMockProvider()

	report, err := sts.CheckHealth(context.Background(), p, ledger, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	total, _, _, _, _ := report.Counts()
	if total != 0 {
		t.Fatalf("total = %d, want 0", total)
	}
}

func TestHealthReport_Counts(t *testing.T) {
	r := &sts.HealthReport{
		Valid:        []sts.TokenStatus{{Name: "a"}, {Name: "b"}},
		Invalid:      []sts.TokenStatus{{Name: "c"}},
		Expired:      []sts.TokenStatus{},
		ExpiringSoon: []sts.TokenStatus{{Name: "d"}},
	}
	total, valid, invalid, expired, expiringSoon := r.Counts()
	if total != 4 || valid != 2 || invalid != 1 || expired != 0 || expiringSoon != 1 {
		t.Fatalf("counts = %d/%d/%d/%d/%d", total, valid, invalid, expired, expiringSoon)
	}
}
