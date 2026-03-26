package profile_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/albertocavalcante/credkit/profile"
)

func newTestManager(t *testing.T) *profile.Manager {
	t.Helper()
	return profile.NewManagerWithDir(t.TempDir())
}

func TestNewManager(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	m, err := profile.NewManager("test-app")
	if err != nil {
		t.Fatal(err)
	}
	if m == nil {
		t.Fatal("expected non-nil manager")
	}
}

func TestList_Empty(t *testing.T) {
	m := newTestManager(t)
	list, err := m.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 0 {
		t.Fatalf("expected 0, got %d", len(list))
	}
}

func TestSaveAndLoad(t *testing.T) {
	m := newTestManager(t)
	now := time.Now().UTC().Truncate(time.Second)

	p := &profile.Profile{
		Fields:    map[string]string{"org": "acme", "zone": "example.com"},
		CreatedAt: now,
	}
	if err := m.Save("work", p); err != nil {
		t.Fatal(err)
	}

	loaded, err := m.Load("work")
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Name != "work" {
		t.Fatalf("name = %q, want %q", loaded.Name, "work")
	}
	if loaded.Fields["org"] != "acme" {
		t.Fatalf("org = %q, want %q", loaded.Fields["org"], "acme")
	}
	if loaded.Fields["zone"] != "example.com" {
		t.Fatalf("zone = %q", loaded.Fields["zone"])
	}
}

func TestLoad_NotFound(t *testing.T) {
	m := newTestManager(t)
	_, err := m.Load("nonexistent")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestLoad_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	m := profile.NewManagerWithDir(dir)

	// Write invalid JSON to profile file.
	profileDir := filepath.Join(dir, "profiles")
	if err := os.MkdirAll(profileDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(profileDir, "bad.json"), []byte("{invalid"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := m.Load("bad")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestList_SortedAndSkipsInvalid(t *testing.T) {
	dir := t.TempDir()
	m := profile.NewManagerWithDir(dir)

	// Save two valid profiles out of order.
	m.Save("zebra", &profile.Profile{Fields: map[string]string{}})
	m.Save("alpha", &profile.Profile{Fields: map[string]string{}})

	// Write an invalid profile that should be skipped.
	profileDir := filepath.Join(dir, "profiles")
	os.WriteFile(filepath.Join(profileDir, "broken.json"), []byte("{bad"), 0o600)

	// Write a non-.json file that should be skipped.
	os.WriteFile(filepath.Join(profileDir, "readme.txt"), []byte("hi"), 0o600)

	list, err := m.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("expected 2 valid profiles, got %d", len(list))
	}
	if list[0].Name != "alpha" || list[1].Name != "zebra" {
		t.Fatalf("sort order wrong: %v, %v", list[0].Name, list[1].Name)
	}
}

func TestList_DirNotExist(t *testing.T) {
	m := profile.NewManagerWithDir(filepath.Join(t.TempDir(), "nope"))
	list, err := m.List()
	if err != nil {
		t.Fatal(err)
	}
	if list != nil {
		t.Fatalf("expected nil, got %v", list)
	}
}

func TestSave_InvalidName(t *testing.T) {
	m := newTestManager(t)
	err := m.Save("", &profile.Profile{})
	if err == nil {
		t.Fatal("expected error for empty name")
	}
}

func TestDelete(t *testing.T) {
	m := newTestManager(t)
	m.Save("doomed", &profile.Profile{Fields: map[string]string{}})
	m.SaveCredential("doomed", []byte("secret"))
	m.SetActive("doomed")

	if err := m.Delete("doomed"); err != nil {
		t.Fatal(err)
	}
	if m.Exists("doomed") {
		t.Fatal("expected profile to be deleted")
	}

	// Active should be cleared.
	active, _ := m.Active()
	if active != profile.DefaultName {
		t.Fatalf("active = %q, want %q after deleting active profile", active, profile.DefaultName)
	}
}

func TestDelete_NonexistentIsOK(t *testing.T) {
	m := newTestManager(t)
	if err := m.Delete("ghost"); err != nil {
		t.Fatalf("deleting nonexistent should succeed, got %v", err)
	}
}

func TestDelete_ActiveNotCleared_WhenDifferent(t *testing.T) {
	m := newTestManager(t)
	m.Save("keep", &profile.Profile{Fields: map[string]string{}})
	m.Save("remove", &profile.Profile{Fields: map[string]string{}})
	m.SetActive("keep")

	m.Delete("remove")

	active, _ := m.Active()
	if active != "keep" {
		t.Fatalf("active = %q, want %q", active, "keep")
	}
}

func TestActive_DefaultWhenUnset(t *testing.T) {
	m := newTestManager(t)
	active, err := m.Active()
	if err != nil {
		t.Fatal(err)
	}
	if active != profile.DefaultName {
		t.Fatalf("active = %q, want %q", active, profile.DefaultName)
	}
}

func TestActive_DefaultWhenEmpty(t *testing.T) {
	m := newTestManager(t)
	m.SetActive("")

	active, _ := m.Active()
	if active != profile.DefaultName {
		t.Fatalf("active = %q, want %q (empty should default)", active, profile.DefaultName)
	}
}

func TestSetAndGetActive(t *testing.T) {
	m := newTestManager(t)
	if err := m.SetActive("staging"); err != nil {
		t.Fatal(err)
	}
	active, err := m.Active()
	if err != nil {
		t.Fatal(err)
	}
	if active != "staging" {
		t.Fatalf("active = %q, want %q", active, "staging")
	}
}

func TestExists(t *testing.T) {
	m := newTestManager(t)
	if m.Exists("work") {
		t.Fatal("should not exist")
	}
	m.Save("work", &profile.Profile{Fields: map[string]string{}})
	if !m.Exists("work") {
		t.Fatal("should exist")
	}
}

func TestCredentialStorage(t *testing.T) {
	m := newTestManager(t)
	data := []byte(`{"type":"token","value":"abc123"}`)

	if err := m.SaveCredential("work", data); err != nil {
		t.Fatal(err)
	}
	got, err := m.LoadCredential("work")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(data) {
		t.Fatalf("got %q, want %q", got, data)
	}
}

func TestLoadCredential_NotFound(t *testing.T) {
	m := newTestManager(t)
	_, err := m.LoadCredential("missing")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestUpdateLastUsed(t *testing.T) {
	m := newTestManager(t)
	before := time.Now().UTC().Add(-time.Second)

	m.Save("test", &profile.Profile{
		Fields:    map[string]string{},
		CreatedAt: before,
	})

	if err := m.UpdateLastUsed("test"); err != nil {
		t.Fatal(err)
	}

	p, _ := m.Load("test")
	if p.LastUsed.Before(before) {
		t.Fatal("LastUsed should have been updated")
	}
}

func TestUpdateLastUsed_NotFound(t *testing.T) {
	m := newTestManager(t)
	err := m.UpdateLastUsed("ghost")
	if err == nil {
		t.Fatal("expected error for missing profile")
	}
}

func TestValidateName(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		{"default", false},
		{"work-prod", false},
		{"a", false},
		{"A1", false},
		{"9lives", false},
		{"", true},
		{".", true},
		{"..", true},
		{"has/slash", true},
		{"has\\back", true},
		{"has:colon", true},
		{"has*star", true},
		{"has?q", true},
		{"has\"quote", true},
		{"has<lt", true},
		{"has>gt", true},
		{"has|pipe", true},
		{"-starts-with-dash", true},
		{"_underscore", true},
		{string(make([]byte, 65)), true},
	}

	for _, tt := range tests {
		err := profile.ValidateName(tt.name)
		if (err != nil) != tt.wantErr {
			t.Errorf("ValidateName(%q) err=%v, wantErr=%v", tt.name, err, tt.wantErr)
		}
	}
}

func TestNewManager_Error(t *testing.T) {
	// Unset HOME and XDG to trigger error.
	t.Setenv("HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	_, err := profile.NewManager("test-app")
	if err == nil {
		t.Fatal("expected error when HOME is unset")
	}
}

func TestList_ReadDirError(t *testing.T) {
	// Point profiles dir at a file (not a directory).
	dir := t.TempDir()
	profilesDir := filepath.Join(dir, "profiles")
	os.WriteFile(profilesDir, []byte("not-a-dir"), 0o600)

	m := profile.NewManagerWithDir(dir)
	_, err := m.List()
	if err == nil {
		t.Fatal("expected error when profiles is a file")
	}
}

func TestDelete_RemoveError(t *testing.T) {
	dir := t.TempDir()
	m := profile.NewManagerWithDir(dir)
	m.Save("victim", &profile.Profile{Fields: map[string]string{}})

	// Make profiles dir read-only to cause Remove error.
	profilesDir := filepath.Join(dir, "profiles")
	os.Chmod(profilesDir, 0o500)
	t.Cleanup(func() { os.Chmod(profilesDir, 0o700) })

	err := m.Delete("victim")
	if err == nil {
		t.Fatal("expected error deleting from read-only dir")
	}
}

func TestProfileJSON_Roundtrip(t *testing.T) {
	p := profile.Profile{
		Name:      "test",
		Fields:    map[string]string{"key": "val"},
		CreatedAt: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var p2 profile.Profile
	if err := json.Unmarshal(data, &p2); err != nil {
		t.Fatal(err)
	}
	if p2.Name != p.Name || p2.Fields["key"] != "val" {
		t.Fatalf("roundtrip mismatch: %+v", p2)
	}
}
