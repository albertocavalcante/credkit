package token_test

import (
	"path/filepath"
	"testing"

	"github.com/albertocavalcante/credkit/token"
)

func TestFindByIDUsesExactProviderNativeID(t *testing.T) {
	l := token.NewLedger(filepath.Join(t.TempDir(), "ledger.json"))
	for _, entry := range []token.Metadata{
		{Provider: "test", Name: "target-id", ID: "different-id"},
		{Provider: "other", Name: "other", ID: "target-id"},
		{Provider: "test", Name: "target-name", ID: "target-id"},
		{Provider: "test", Name: "legacy"},
	} {
		if err := l.Record(&entry); err != nil {
			t.Fatal(err)
		}
	}
	got, err := l.FindByID("test", "target-id")
	if err != nil || got.ID != "target-id" {
		t.Fatalf("got=%+v err=%v", got, err)
	}
	for _, id := range []string{"legacy", "target-name", ""} {
		if _, err := l.FindByID("test", id); err == nil {
			t.Errorf("non-ID %q matched", id)
		}
	}
}
