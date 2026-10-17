package store_test

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/albertocavalcante/credkit/store"
)

func TestAtomicReplacementReadersObserveCompleteValues(t *testing.T) {
	root := t.TempDir()
	values := [][]byte{bytes.Repeat([]byte("a"), 128*1024), bytes.Repeat([]byte("b"), 128*1024)}
	if err := store.WriteSecureAt(root, "secret", values[0]); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	stop := make(chan struct{})
	done := make(chan error, 4)
	for range 4 {
		go func() {
			<-start
			for {
				data, err := os.ReadFile(filepath.Join(root, "secret"))
				if err != nil {
					done <- err
					return
				}
				if !bytes.Equal(data, values[0]) && !bytes.Equal(data, values[1]) {
					done <- fmt.Errorf("reader observed incomplete replacement (%d bytes)", len(data))
					return
				}
				select {
				case <-stop:
					done <- nil
					return
				default:
				}
			}
		}()
	}
	close(start)
	for i := range 32 {
		if err := store.WriteSecureAt(root, "secret", values[i%2]); err != nil {
			t.Error(err)
			break
		}
	}
	close(stop)
	for range 4 {
		if err := <-done; err != nil {
			t.Error(err)
		}
	}
}
