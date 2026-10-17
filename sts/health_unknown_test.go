package sts_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/albertocavalcante/credkit/sts"
	"github.com/albertocavalcante/credkit/token"
)

func TestHealthReportsLedgerOnlyTokensAsUnknown(t *testing.T) {
	l := token.NewLedger(filepath.Join(privateTestDir(t), "ledger.json"))
	if err := l.Record(&token.Metadata{Provider: "test", ID: "unobserved", Name: "unobserved"}); err != nil {
		t.Fatal(err)
	}
	p := newMockProvider()
	p.validateFunc = func(context.Context, string) error { return errors.New("revoked") }
	r, err := sts.CheckHealth(t.Context(), p, l, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Valid) != 0 || len(r.Unknown) != 1 {
		t.Fatalf("valid=%v unknown=%v", r.Valid, r.Unknown)
	}
	total, valid, _, _, _ := r.Counts()
	if total != 1 || valid != 0 {
		t.Fatalf("total=%d valid=%d", total, valid)
	}
}

func TestHealthCountsIncludeUnknown(t *testing.T) {
	r := sts.HealthReport{Unknown: []sts.TokenStatus{{Name: "a"}, {Name: "b"}}}
	total, _, _, _, _ := r.Counts()
	if total != 2 {
		t.Fatalf("total=%d, want 2", total)
	}
}

func TestHealthRespectsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := sts.CheckHealth(ctx, newMockProvider(), token.NewLedger(filepath.Join(privateTestDir(t), "ledger.json")), time.Hour)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want cancellation", err)
	}
}
