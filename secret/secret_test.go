package secret_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/albertocavalcante/credkit/secret"
	"github.com/albertocavalcante/credkit/store"
)

func TestFileStoreLifecycle(t *testing.T) {
	backend := secret.FileStore{Dir: filepath.Join(t.TempDir(), "secrets")}
	key := secret.Key{Service: "meliboot", Account: "app-secret"}
	want := []byte("top-secret")
	if err := backend.Put(t.Context(), key, want); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	got, err := backend.Get(t.Context(), key)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("Get() = %q, want %q", got, want)
	}
	entries, err := os.ReadDir(backend.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("secret file count = %d, want 1", len(entries))
	}
	info, err := entries[0].Info()
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != store.FilePerm {
		t.Fatalf("secret file mode = %o, want %o", got, store.FilePerm)
	}
	if err := backend.Delete(t.Context(), key); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if _, err := backend.Get(t.Context(), key); !errors.Is(err, secret.ErrNotFound) {
		t.Fatalf("Get() after Delete error = %v, want ErrNotFound", err)
	}
	if err := backend.Delete(t.Context(), key); err != nil {
		t.Fatalf("second Delete() error = %v", err)
	}
}

func TestStoresValidateKeysAndContext(t *testing.T) {
	backend := secret.FileStore{Dir: t.TempDir()}
	if err := backend.Put(t.Context(), secret.Key{}, []byte("x")); !errors.Is(err, secret.ErrInvalidKey) {
		t.Fatalf("Put() error = %v, want ErrInvalidKey", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := backend.Put(ctx, secret.Key{Service: "svc", Account: "acct"}, []byte("x")); !errors.Is(err, context.Canceled) {
		t.Fatalf("Put() error = %v, want context.Canceled", err)
	}
}
