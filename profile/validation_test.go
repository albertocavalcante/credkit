package profile_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/albertocavalcante/credkit/profile"
)

func TestManagerRejectsInvalidNamesBeforeIO(t *testing.T) {
	names := []string{"", ".", "..", "../../victim", "nested/victim", `nested\victim`, "/absolute", "work ", "work\n", "work\x00", "work\nname"}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			config := filepath.Join(root, "config")
			mgr := profile.NewManagerWithDir(config)
			for _, suffix := range []string{"", ".json"} {
				if err := os.WriteFile(filepath.Join(root, "victim"+suffix), []byte(`{"name":"outside"}`), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := profile.ValidateName(name); err == nil {
				t.Errorf("ValidateName(%q) succeeded; want error", name)
			}
			if mgr.Exists(name) {
				t.Errorf("Exists(%q) = true; want false", name)
			}
			operations := []struct {
				name string
				run  func() error
			}{
				{"Save", func() error { return mgr.Save(name, &profile.Profile{}) }},
				{"Load", func() error { _, err := mgr.Load(name); return err }},
				{"Delete", func() error { return mgr.Delete(name) }},
				{"SaveCredential", func() error { return mgr.SaveCredential(name, []byte("synthetic")) }},
				{"LoadCredential", func() error { _, err := mgr.LoadCredential(name); return err }},
				{"UpdateLastUsed", func() error { return mgr.UpdateLastUsed(name) }},
			}
			for _, operation := range operations {
				t.Run(operation.name, func(t *testing.T) {
					if err := operation.run(); err == nil {
						t.Errorf("%s(%q) succeeded; want invalid-name error", operation.name, name)
					}
				})
			}
			if name != "" {
				if err := mgr.SetActive(name); err == nil {
					t.Errorf("SetActive(%q) succeeded; want invalid-name error", name)
				}
			}
			for _, suffix := range []string{"", ".json"} {
				data, err := os.ReadFile(filepath.Join(root, "victim"+suffix))
				if err != nil || string(data) != `{"name":"outside"}` {
					t.Errorf("outside victim%s changed: data=%q err=%v", suffix, data, err)
				}
			}
		})
	}
}

func TestActiveSelectionUsesValidNames(t *testing.T) {
	for _, name := range []string{"work-prod", "work prod", "A1", "9lives", ""} {
		t.Run(name, func(t *testing.T) {
			mgr := profile.NewManagerWithDir(t.TempDir())
			if name != "" {
				if err := mgr.Save(name, &profile.Profile{}); err != nil {
					t.Fatal(err)
				}
			}
			if err := mgr.SetActive(name); err != nil {
				t.Fatal(err)
			}
			active, err := mgr.Active()
			if err != nil {
				t.Fatal(err)
			}
			want := name
			if want == "" {
				want = profile.DefaultName
			}
			if active != want {
				t.Fatalf("Active()=%q, want %q", active, want)
			}
		})
	}
}

func TestActiveRejectsInvalidStoredName(t *testing.T) {
	for _, name := range []string{"../../victim", "work ", "work\nname"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "active-profile"), []byte(name+"\n"), 0600); err != nil {
				t.Fatal(err)
			}
			if active, err := profile.NewManagerWithDir(dir).Active(); err == nil {
				t.Fatalf("Active()=%q without error for invalid persisted name %q", active, name)
			}
		})
	}
}
