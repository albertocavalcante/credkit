package session_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/albertocavalcante/credkit/session"
)

func TestManagerRejectsUnsafeProvidersBeforeIO(t *testing.T) {
	for _, name := range []string{".", "..", "x/../../victim", "nested/provider", `nested\provider`, "/absolute", "provider\x00", "provider\n"} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "victim.json")
			data := []byte(`{"key":"outside","created_at":"2099-01-01T00:00:00Z","ttl_seconds":3600}`)
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			mgr := session.NewManager(filepath.Join(root, "config"), time.Hour)
			for _, operation := range []struct {
				name string
				run  func() error
			}{
				{"Save", func() error { return mgr.Save(name, "synthetic") }},
				{"Load", func() error { _, err := mgr.Load(name); return err }},
				{"Clear", func() error { return mgr.Clear(name) }},
				{"Resolve", func() error { _, err := mgr.Resolve(name, ""); return err }},
			} {
				t.Run(operation.name, func(t *testing.T) {
					if err := operation.run(); err == nil {
						t.Errorf("%s(%q) succeeded; want invalid-provider error", operation.name, name)
					}
				})
			}
			after, err := os.ReadFile(path)
			if err != nil || string(after) != string(data) {
				t.Errorf("outside session changed: data=%q err=%v", after, err)
			}
		})
	}
}

func TestDefaultAndNamedProvidersRoundTrip(t *testing.T) {
	for _, name := range []string{"", "cloudflare", "sonarcloud", "provider-v2", "provider.v2"} {
		t.Run(name, func(t *testing.T) {
			mgr := session.NewManager(t.TempDir(), time.Hour)
			if err := mgr.Save(name, "synthetic"); err != nil {
				t.Fatal(err)
			}
			loaded, err := mgr.Load(name)
			if err != nil {
				t.Fatal(err)
			}
			if loaded.Key != "synthetic" {
				t.Fatalf("Load key=%q", loaded.Key)
			}
			key, err := mgr.Resolve(name, "")
			if err != nil || key != "synthetic" {
				t.Fatalf("Resolve key=%q err=%v", key, err)
			}
			if err := mgr.Clear(name); err != nil {
				t.Fatal(err)
			}
			key, err = mgr.Resolve(name, "")
			if err != nil || key != "" {
				t.Fatalf("Resolve after Clear key=%q err=%v", key, err)
			}
		})
	}
}
