package sts_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/albertocavalcante/credkit/sts"
	"github.com/albertocavalcante/credkit/token"
)

func TestRotateRemovesLedgerEntryByProviderAndID(t *testing.T) {
	ledger := token.NewLedger(filepath.Join(t.TempDir(), "ledger.json"))
	for _, entry := range []token.Metadata{
		{Provider: "test", Name: "production", ID: "old-id"},
		{Provider: "test", Name: "old-id", ID: "keep-id"},
		{Provider: "other", Name: "production", ID: "old-id"},
	} {
		if err := ledger.Record(&entry); err != nil {
			t.Fatal(err)
		}
	}
	provider := newMockProvider()
	if _, err := sts.Rotate(context.Background(), provider, "old-id", &sts.IssueRequest{Name: "replacement"}, sts.WithLedger(ledger)); err != nil {
		t.Fatal(err)
	}
	entries, err := ledger.List("")
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, entry := range entries {
		found[entry.Provider+"/"+entry.ID] = true
	}
	if len(entries) != 3 || found["test/old-id"] || !found["test/new-id"] || !found["test/keep-id"] || !found["other/old-id"] {
		t.Fatalf("rotation removed entries by name rather than provider+ID: %+v", entries)
	}
}
