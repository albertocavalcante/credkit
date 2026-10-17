package store_test

import (
	"bytes"
	"errors"
	"fmt"
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
			readValue := func() error {
				data, err := store.ReadSecureAt(root, "secret")
				if err != nil {
					return err
				}
				if !bytes.Equal(data, values[0]) && !bytes.Equal(data, values[1]) {
					return fmt.Errorf("reader observed incomplete replacement (%d bytes)", len(data))
				}
				return nil
			}
			for {
				select {
				case <-stop:
					// Writers have stopped. Every reader must complete a clean
					// read; persistent unsafe state must fail rather than spin.
					done <- readValue()
					return
				default:
				}
				if err := readValue(); err != nil && !errors.Is(err, store.ErrUnsafePath) {
					done <- err
					return
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
