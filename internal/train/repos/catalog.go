package repos

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Catalog is the discovery repo list shipped with the factory.
type Catalog struct {
	SchemaVersion int    `json:"schema_version"`
	Description   string `json:"description,omitempty"`
	Repositories  []Repo `json:"repositories"`
}

// Repo is one discovery/validation target.
type Repo struct {
	Owner     string   `json:"owner"`
	Name      string   `json:"name"`
	Languages []string `json:"languages"`
	Role      string   `json:"role,omitempty"` // discovery | validation | hidden
	Notes     string   `json:"notes,omitempty"`
	Enabled   *bool    `json:"enabled,omitempty"` // default true when nil
}

// FullName returns owner/name.
func (r Repo) FullName() string {
	return r.Owner + "/" + r.Name
}

// IsEnabled reports whether the repo is active.
func (r Repo) IsEnabled() bool {
	return r.Enabled == nil || *r.Enabled
}

// MatchesLanguages is true if the repo speaks any of the filter languages.
// Empty filter = match all (engineering-review).
func (r Repo) MatchesLanguages(filter []string) bool {
	if len(filter) == 0 {
		return true
	}
	want := map[string]bool{}
	for _, l := range filter {
		want[strings.ToLower(strings.TrimSpace(l))] = true
	}
	// "any" means no filter
	if want["any"] || want["*"] {
		return true
	}
	for _, l := range r.Languages {
		if want[strings.ToLower(strings.TrimSpace(l))] {
			return true
		}
	}
	return false
}

// Load reads a repositories.json catalog.
func Load(path string) (*Catalog, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Catalog
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if len(c.Repositories) == 0 {
		return nil, fmt.Errorf("%s: no repositories", path)
	}
	return &c, nil
}

// DefaultPath returns factoryRepoRoot/config/repositories.json.
func DefaultPath(factoryRepoRoot string) string {
	return filepath.Join(factoryRepoRoot, "config", "repositories.json")
}

// Filter returns enabled repos matching role and languages.
// role empty = any role; languages empty = any language.
// When role is "discovery", includes repos with role discovery or empty role.
func (c *Catalog) Filter(role string, languages []string) []Repo {
	if c == nil {
		return nil
	}
	var out []Repo
	for _, r := range c.Repositories {
		if !r.IsEnabled() {
			continue
		}
		if r.Owner == "" || r.Name == "" {
			continue
		}
		if role != "" {
			rr := strings.ToLower(strings.TrimSpace(r.Role))
			want := strings.ToLower(strings.TrimSpace(role))
			if rr != "" && rr != want {
				continue
			}
		}
		if !r.MatchesLanguages(languages) {
			continue
		}
		out = append(out, r)
	}
	return out
}
