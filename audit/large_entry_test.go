package audit_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/albertocavalcante/credkit/audit"
)

func TestQueryReadsLargeLoggedEntriesAndFollowingRecord(t *testing.T) {
	for _, size := range []int{64 * 1024, 70 * 1024, 512 * 1024} {
		t.Run(fmt.Sprintf("%d_bytes", size), func(t *testing.T) {
			logger := audit.NewLogger(filepath.Join(t.TempDir(), "audit.log"))
			message := strings.Repeat("e", size)
			if err := logger.Log(audit.Entry{Action: "issue", Provider: "test", Error: message}); err != nil {
				t.Fatal(err)
			}
			if err := logger.Log(audit.Entry{Action: "revoke", Provider: "test"}); err != nil {
				t.Fatal(err)
			}
			entries, err := logger.Query(time.Time{}, "test")
			if err != nil || len(entries) != 2 {
				t.Fatalf("Query after successful Log: entries=%d err=%v", len(entries), err)
			}
			if entries[0].Error != message || entries[1].Action != "revoke" {
				t.Fatal("large entry or following record did not round-trip")
			}
		})
	}
}

func sizedEntry(t *testing.T, size int) audit.Entry {
	t.Helper()
	entry := audit.Entry{Timestamp: time.Unix(0, 0).UTC(), Action: "issue", Error: "e"}
	encoded, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	entry.Error = strings.Repeat("e", size-len(encoded)+1)
	return entry
}

func TestAuditEntrySizeBound(t *testing.T) {
	for _, size := range []int{audit.MaxEntrySize - 1, audit.MaxEntrySize, audit.MaxEntrySize + 1} {
		t.Run(fmt.Sprintf("%d_bytes", size), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "audit.log")
			logger := audit.NewLogger(path)
			entry := sizedEntry(t, size)
			err := logger.Log(entry)
			if size > audit.MaxEntrySize {
				if !errors.Is(err, audit.ErrEntryTooLarge) {
					t.Fatalf("Log error=%v, want ErrEntryTooLarge", err)
				}
				if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("oversized Log created a file: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			entries, err := logger.Query(time.Time{}, "")
			if err != nil || len(entries) != 1 || entries[0].Error != entry.Error {
				t.Fatalf("entry of exactly %d bytes failed round-trip: entries=%d err=%v", size, len(entries), err)
			}
		})
	}
}

func TestQueryOversizedRecordReturnsPriorEntriesAndError(t *testing.T) {
	for _, newline := range []bool{false, true} {
		t.Run(fmt.Sprintf("newline_%t", newline), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "audit.log")
			logger := audit.NewLogger(path)
			if err := logger.Log(audit.Entry{Action: "first"}); err != nil {
				t.Fatal(err)
			}
			file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
			if err != nil {
				t.Fatal(err)
			}
			oversized := strings.Repeat("e", audit.MaxEntrySize+1)
			if newline {
				oversized += "\n"
			}
			_, writeErr := file.WriteString(oversized)
			closeErr := file.Close()
			if writeErr != nil || closeErr != nil {
				t.Fatalf("write=%v close=%v", writeErr, closeErr)
			}
			entries, err := logger.Query(time.Time{}, "")
			if !errors.Is(err, audit.ErrEntryTooLarge) || len(entries) != 1 || entries[0].Action != "first" {
				t.Fatalf("Query oversized record entries=%+v err=%v; want prior entry and ErrEntryTooLarge", entries, err)
			}
		})
	}
}

func TestQueryMaxEntryLineEndings(t *testing.T) {
	for _, ending := range []string{"", "\n", "\r\n"} {
		t.Run(fmt.Sprintf("ending_%q", ending), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "audit.log")
			entry := sizedEntry(t, audit.MaxEntrySize)
			encoded, err := json.Marshal(entry)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, append(encoded, ending...), 0600); err != nil {
				t.Fatal(err)
			}
			entries, err := audit.NewLogger(path).Query(time.Time{}, "")
			if err != nil || len(entries) != 1 || entries[0].Error != entry.Error {
				t.Fatalf("max-sized entry with ending %q: count=%d err=%v", ending, len(entries), err)
			}
		})
	}
}
