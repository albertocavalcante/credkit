package token_test

import (
	"testing"

	"github.com/albertocavalcante/credkit/token"
)

func TestRemoveByIDPreservesNamesAndOtherProviders(t *testing.T) {
	ledger := newLedger(t)
	for _, entry := range []token.Metadata{
		{Provider: "a", Name: "target-name", ID: "target-id"},
		{Provider: "a", Name: "target-id", ID: "other-id"},
		{Provider: "b", Name: "target-name", ID: "target-id"},
		{Provider: "a", Name: "legacy-without-id"},
	} {
		if err := ledger.Record(&entry); err != nil {
			t.Fatal(err)
		}
	}
	if err := ledger.RemoveByID("a", "target-id"); err != nil {
		t.Fatal(err)
	}
	entries, err := ledger.List("")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("remaining entries=%+v", entries)
	}
	for _, entry := range entries {
		if entry.Provider == "a" && entry.ID == "target-id" {
			t.Fatal("target entry still present")
		}
	}
	if err := ledger.RemoveByID("a", ""); err == nil {
		t.Fatal("empty ID must not remove legacy entries")
	}
	if err := ledger.RemoveByID("a", "missing-id"); err != nil {
		t.Fatal(err)
	}
	// The existing name-based API retains its previous behavior.
	if err := ledger.Remove("a", "target-id"); err != nil {
		t.Fatal(err)
	}
	entries, err = ledger.List("")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("name-based removal changed: %+v", entries)
	}
}
