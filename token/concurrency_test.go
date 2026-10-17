package token_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/albertocavalcante/credkit/token"
)

func TestIndependentLedgersPreserveConcurrentRecords(t *testing.T) {
	for _, alias := range []bool{false, true} {
		t.Run(fmt.Sprintf("parent_symlink_%v", alias), func(t *testing.T) {
			root := t.TempDir()
			firstPath := filepath.Join(root, "new", "tokens.json")
			secondPath := firstPath
			if alias {
				link := filepath.Join(t.TempDir(), "root")
				if err := os.Symlink(root, link); err != nil {
					t.Fatal(err)
				}
				secondPath = filepath.Join(link, "new", "tokens.json")
			}
			ledgers := []*token.Ledger{token.NewLedger(firstPath), token.NewLedger(secondPath)}
			start := make(chan struct{})
			done := make(chan error, 2)
			for worker, ledger := range ledgers {
				go func() {
					<-start
					for i := range 32 {
						if err := ledger.Record(&token.Metadata{Provider: "test", ID: fmt.Sprintf("%d-%d", worker, i)}); err != nil {
							done <- err
							return
						}
					}
					done <- nil
				}()
			}
			close(start)
			for range ledgers {
				if err := <-done; err != nil {
					t.Error(err)
				}
			}
			entries, err := ledgers[0].List("")
			if err != nil {
				t.Fatal(err)
			}
			seen := make(map[string]bool)
			for _, entry := range entries {
				if seen[entry.ID] {
					t.Fatalf("duplicate ID %q", entry.ID)
				}
				seen[entry.ID] = true
			}
			if len(seen) != 64 {
				t.Fatalf("lost concurrent records: got %d, want 64", len(seen))
			}
		})
	}
}
