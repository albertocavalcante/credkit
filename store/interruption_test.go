package store_test

import (
	"bytes"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/albertocavalcante/credkit/store"
)

func TestTerminatedReplacementWriterPreservesCompleteCredential(t *testing.T) {
	root := t.TempDir()
	old := []byte("previous complete value")
	if err := store.WriteSecureAt(root, "secret", old); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestReplacementWriterProcess$")
	cmd.Env = append(os.Environ(), "CREDKIT_ATOMIC_WRITER_ROOT="+root)
	var diagnostic bytes.Buffer
	cmd.Stderr = &diagnostic
	cmd.Stdout = &diagnostic
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	t.Cleanup(func() {
		if !waited {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	})
	// Observe an actual staged replacement before terminating the writer.
	// Rename may race the kill; either the old or new complete value is safe.
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	staged := false
	for !staged {
		select {
		case <-deadline.C:
			t.Fatal("writer did not stage a replacement before deadline")
		case <-tick.C:
			entries, err := os.ReadDir(root)
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				staged = staged || strings.HasPrefix(entry.Name(), ".credkit-write-")
			}
		}
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	waitErr := cmd.Wait()
	waited = true
	if waitErr == nil {
		t.Fatal("writer completed normally instead of being terminated")
	}
	if diagnostic.Len() != 0 {
		t.Fatalf("writer failed before termination: %s", &diagnostic)
	}
	got, err := store.ReadSecureAt(root, "secret")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, old) && !bytes.Equal(got, bytes.Repeat([]byte("x"), 16*1024*1024)) {
		t.Fatalf("termination left an incomplete credential (%d bytes)", len(got))
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			t.Fatal(err)
		}
		if !info.Mode().IsRegular() || (runtime.GOOS != "windows" && info.Mode().Perm() != store.FilePerm) {
			t.Fatalf("termination left an unsafe storage entry: %s %v", entry.Name(), info.Mode())
		}
	}
	if runtime.GOOS == "windows" {
		for _, entry := range entries {
			if _, err := store.ReadSecureAt(root, entry.Name()); err != nil {
				t.Fatalf("termination left an unsafe Windows storage ACL: %v", err)
			}
		}
	}
	// Abrupt termination may leave its owner-only staging file. No cleanup or
	// power-loss durability guarantee is inferred from atomic replacement.
}

func TestReplacementWriterProcess(t *testing.T) {
	root := os.Getenv("CREDKIT_ATOMIC_WRITER_ROOT")
	if root == "" {
		return
	}
	payload := bytes.Repeat([]byte("x"), 16*1024*1024)
	for {
		if err := store.WriteSecureAt(root, "secret", payload); err != nil {
			t.Fatal(err)
		}
	}
}
