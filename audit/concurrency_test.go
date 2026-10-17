package audit_test

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/albertocavalcante/credkit/audit"
)

func TestIndependentLoggersAppendCompleteLargeRecords(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	start := make(chan struct{})
	done := make(chan error, 8)
	for worker := range 8 {
		go func() {
			logger := audit.NewLogger(path)
			<-start
			for i := range 8 {
				entry := audit.Entry{Action: "test", TokenName: fmt.Sprintf("%d-%d", worker, i), Source: strings.Repeat("x", 16*1024)}
				if err := logger.Log(entry); err != nil {
					done <- err
					return
				}
			}
			done <- nil
		}()
	}
	close(start)
	for range 8 {
		if err := <-done; err != nil {
			t.Error(err)
		}
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	seen := make(map[string]bool)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var entry audit.Entry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			t.Fatalf("interleaved or incomplete JSON record: %v", err)
		}
		if seen[entry.TokenName] || entry.Source != strings.Repeat("x", 16*1024) {
			t.Fatalf("duplicate or incomplete record %q", entry.TokenName)
		}
		seen[entry.TokenName] = true
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 64 {
		t.Fatalf("got %d complete records, want 64", len(seen))
	}
}
