package audit_test

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/albertocavalcante/credkit/audit"
)

func TestLogAndQuery(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	logger := audit.NewLogger(path)

	e1 := audit.Entry{
		Timestamp: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		Action:    "issue",
		Provider:  "sonarcloud",
		TokenName: "token-1",
		Success:   true,
		Source:    "cofre",
	}
	e2 := audit.Entry{
		Timestamp: time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC),
		Action:    "revoke",
		Provider:  "cloudflare",
		TokenName: "token-2",
		Success:   true,
		Source:    "flare",
	}

	if err := logger.Log(e1); err != nil {
		t.Fatal(err)
	}
	if err := logger.Log(e2); err != nil {
		t.Fatal(err)
	}

	// All entries.
	entries, err := logger.Query(time.Time{}, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2, got %d", len(entries))
	}
}

func TestQuery_ByProvider(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	logger := audit.NewLogger(path)

	logger.Log(audit.Entry{Timestamp: time.Now(), Provider: "sonarcloud", Action: "issue", Source: "s"})
	logger.Log(audit.Entry{Timestamp: time.Now(), Provider: "cloudflare", Action: "issue", Source: "f"})

	entries, _ := logger.Query(time.Time{}, "sonarcloud")
	if len(entries) != 1 || entries[0].Provider != "sonarcloud" {
		t.Fatalf("filter by provider failed: %+v", entries)
	}
}

func TestQuery_BySince(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	logger := audit.NewLogger(path)

	logger.Log(audit.Entry{Timestamp: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), Provider: "a", Action: "x", Source: "s"})
	logger.Log(audit.Entry{Timestamp: time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC), Provider: "b", Action: "y", Source: "s"})

	entries, _ := logger.Query(time.Date(2025, 3, 1, 0, 0, 0, 0, time.UTC), "")
	if len(entries) != 1 || entries[0].Provider != "b" {
		t.Fatalf("time filter failed: %+v", entries)
	}
}

func TestLog_AutoTimestamp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	logger := audit.NewLogger(path)

	before := time.Now().UTC()
	logger.Log(audit.Entry{Action: "validate", Provider: "test", Source: "test"})

	entries, _ := logger.Query(time.Time{}, "")
	if len(entries) != 1 {
		t.Fatalf("expected 1, got %d", len(entries))
	}
	if entries[0].Timestamp.Before(before) {
		t.Fatal("auto-timestamp should be >= now")
	}
}

func TestLog_ErrorField(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	logger := audit.NewLogger(path)

	logger.Log(audit.Entry{
		Action:   "issue",
		Provider: "sonarcloud",
		Success:  false,
		Error:    "401 unauthorized",
		Source:   "cofre",
	})

	entries, _ := logger.Query(time.Time{}, "")
	if entries[0].Error != "401 unauthorized" {
		t.Fatalf("error = %q", entries[0].Error)
	}
	if entries[0].Success {
		t.Fatal("should be failed")
	}
}

func TestQuery_EmptyLog(t *testing.T) {
	logger := audit.NewLogger(filepath.Join(t.TempDir(), "nonexistent.log"))
	entries, err := logger.Query(time.Time{}, "")
	if err != nil {
		t.Fatal(err)
	}
	if entries != nil {
		t.Fatalf("expected nil, got %v", entries)
	}
}

func TestQuery_MalformedLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	// Write a mix of valid and invalid lines.
	content := `{"ts":"2025-01-01T00:00:00Z","action":"issue","provider":"a","token_name":"t","success":true,"source":"s"}
not-json
{"ts":"2025-06-01T00:00:00Z","action":"revoke","provider":"b","token_name":"t2","success":true,"source":"s"}

`
	os.WriteFile(path, []byte(content), 0o600)

	logger := audit.NewLogger(path)
	entries, err := logger.Query(time.Time{}, "")
	if err != nil {
		t.Fatal(err)
	}
	// Should skip the bad line and empty line, return 2 valid entries.
	if len(entries) != 2 {
		t.Fatalf("expected 2 valid entries, got %d", len(entries))
	}
}

func TestLog_CreatesParentDirs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "dir", "audit.log")
	logger := audit.NewLogger(path)

	if err := logger.Log(audit.Entry{Action: "test", Provider: "p", Source: "s"}); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("file should exist: %v", err)
	}
}

func TestLog_BadDir(t *testing.T) {
	logger := audit.NewLogger("/dev/null/impossible/audit.log")
	err := logger.Log(audit.Entry{Action: "test", Provider: "p", Source: "s"})
	if err == nil {
		t.Fatal("expected error for bad directory")
	}
}

func TestLog_ConcurrentSafety(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	logger := audit.NewLogger(path)

	var wg sync.WaitGroup
	for i := range 20 {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			logger.Log(audit.Entry{
				Action:   "issue",
				Provider: "test",
				Source:   "test",
			})
			_ = n
		}(i)
	}
	wg.Wait()

	entries, _ := logger.Query(time.Time{}, "")
	if len(entries) != 20 {
		t.Fatalf("expected 20 entries from concurrent writes, got %d", len(entries))
	}
}
