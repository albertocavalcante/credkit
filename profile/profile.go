// Package profile provides multi-profile credential management with XDG compliance.
//
// Profiles are stored as JSON files under ~/.config/<app>/profiles/<name>.json
// with credentials in ~/.config/<app>/credentials/<name>.
package profile

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/albertocavalcante/credkit/store"
)

// DefaultName is the name used when no profile is specified.
const DefaultName = "default"

// Profile represents a named authentication context.
type Profile struct {
	Name      string            `json:"name"`
	Fields    map[string]string `json:"fields,omitempty"`
	CreatedAt time.Time         `json:"created_at"`
	LastUsed  time.Time         `json:"last_used"`
}

// Manager handles profile CRUD operations.
type Manager struct {
	configDir string
}

// NewManager creates a profile manager for the given application.
// The config directory is resolved via XDG_CONFIG_HOME.
func NewManager(appName string) (*Manager, error) {
	dir, err := store.XDGConfigDir(appName)
	if err != nil {
		return nil, err
	}
	return &Manager{configDir: dir}, nil
}

// NewManagerWithDir creates a profile manager rooted at the given directory.
func NewManagerWithDir(dir string) *Manager {
	return &Manager{configDir: dir}
}

func (m *Manager) profilesDir() string    { return filepath.Join(m.configDir, "profiles") }
func (m *Manager) credentialsDir() string { return filepath.Join(m.configDir, "credentials") }

func (m *Manager) activeProfilePath() string {
	return filepath.Join(m.configDir, "active-profile")
}

// List returns all profiles sorted by name.
func (m *Manager) List() ([]Profile, error) {
	dir := m.profilesDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("list profiles: %w", err)
	}

	var profiles []Profile
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		name := strings.TrimSuffix(e.Name(), ".json")
		p, err := m.Load(name)
		if err != nil {
			continue
		}
		profiles = append(profiles, *p)
	}

	slices.SortFunc(profiles, func(a, b Profile) int {
		return strings.Compare(a.Name, b.Name)
	})
	return profiles, nil
}

// Load reads a profile by name.
func (m *Manager) Load(name string) (*Profile, error) {
	path := filepath.Join(m.profilesDir(), name+".json")
	data, err := store.ReadSecure(path)
	if err != nil {
		return nil, fmt.Errorf("profile not found: %s", name)
	}

	var p Profile
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("invalid profile %s: %w", name, err)
	}
	p.Name = name
	return &p, nil
}

// Save writes a profile to disk.
func (m *Manager) Save(name string, p *Profile) error {
	if err := ValidateName(name); err != nil {
		return err
	}

	// Copy to avoid mutating the caller's struct.
	toSave := *p
	toSave.Name = name

	data, err := json.MarshalIndent(&toSave, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal profile: %w", err)
	}

	path := filepath.Join(m.profilesDir(), name+".json")
	return store.WriteSecure(path, append(data, '\n'))
}

// Delete removes a profile and its credentials.
func (m *Manager) Delete(name string) error {
	profilePath := filepath.Join(m.profilesDir(), name+".json")
	credPath := filepath.Join(m.credentialsDir(), name)

	if err := os.Remove(profilePath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove profile: %w", err)
	}
	if err := os.Remove(credPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove credentials: %w", err)
	}

	active, _ := m.Active()
	if active == name {
		_ = m.SetActive("")
	}
	return nil
}

// Active returns the currently active profile name.
// Returns DefaultName if no active profile is set.
func (m *Manager) Active() (string, error) {
	data, err := os.ReadFile(m.activeProfilePath())
	if err != nil {
		return DefaultName, nil
	}
	name := strings.TrimSpace(string(data))
	if name == "" {
		return DefaultName, nil
	}
	return name, nil
}

// SetActive sets the active profile.
func (m *Manager) SetActive(name string) error {
	return store.WriteSecure(m.activeProfilePath(), []byte(name+"\n"))
}

// Exists checks if a profile exists.
func (m *Manager) Exists(name string) bool {
	path := filepath.Join(m.profilesDir(), name+".json")
	return store.Exists(path)
}

// SaveCredential stores credential data for a profile.
func (m *Manager) SaveCredential(profileName string, data []byte) error {
	path := filepath.Join(m.credentialsDir(), profileName)
	return store.WriteSecure(path, data)
}

// LoadCredential reads credential data for a profile.
func (m *Manager) LoadCredential(profileName string) ([]byte, error) {
	path := filepath.Join(m.credentialsDir(), profileName)
	return store.ReadSecure(path)
}

// UpdateLastUsed updates the last_used timestamp for a profile.
func (m *Manager) UpdateLastUsed(name string) error {
	p, err := m.Load(name)
	if err != nil {
		return err
	}
	p.LastUsed = time.Now().UTC()
	return m.Save(name, p)
}

// ValidateName checks if a profile name is valid for use as a filename.
func ValidateName(name string) error {
	if name == "" {
		return errors.New("profile name cannot be empty")
	}
	if len(name) > 64 {
		return errors.New("profile name too long (max 64 characters)")
	}
	if name == "." || name == ".." {
		return fmt.Errorf("invalid profile name: %s", name)
	}
	if strings.ContainsAny(name, "/\\:*?\"<>|") {
		return errors.New("profile name contains invalid characters")
	}
	c := name[0]
	if !isAlphanumeric(c) {
		return errors.New("profile name must start with a letter or number")
	}
	return nil
}

func isAlphanumeric(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}
