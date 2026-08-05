// Package workspace implements adversary train config, init, and draft attribution.
package workspace

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	DefaultConfigName = "adversary.train.yaml"
	DefaultStateDir   = ".adversary-train"
)

// Config is the committed train policy (adversary.train.yaml).
type Config struct {
	Version     int               `yaml:"version"`
	Adversaries AdversariesConfig `yaml:"adversaries"`
	Official    OfficialConfig    `yaml:"official"`
	Sources     SourcesConfig     `yaml:"sources"`
	Run         RunConfig         `yaml:"run"`
	StateDir    string            `yaml:"state_dir"`
}

type AdversariesConfig struct {
	Root      string            `yaml:"root"`
	Path      string            `yaml:"path"`
	Overrides map[string]string `yaml:"overrides"`
}

type OfficialConfig struct {
	Enabled  *bool    `yaml:"enabled"` // nil => true
	AutoPull bool     `yaml:"auto_pull"`
	Channel  string   `yaml:"channel"`
	Include  []string `yaml:"include"`
	Exclude  []string `yaml:"exclude"`
}

type SourcesConfig struct {
	Host string `yaml:"host"`
	// Discovery selects how train finds PRs:
	//   "repos" (default) — hunt listed sources.repos / org catalog
	//   "author_reviews"  — GitHub search for PRs reviewed/commented by authors_only (no repo list required)
	// Empty: auto — author_reviews when authors_only set and repos empty; else repos.
	Discovery string `yaml:"discovery"`
	Org       string `yaml:"org"`
	// Orgs bounds author_reviews search (gh --owner). Optional.
	Orgs            []string `yaml:"orgs"`
	Repos           []string `yaml:"repos"`
	Languages       []string `yaml:"languages"`
	Since           string   `yaml:"since"`
	ReposAllowlist  []string `yaml:"repos_allowlist"`
	AuthorsIgnore   []string `yaml:"authors_ignore"`
	AuthorsOnly     []string `yaml:"authors_only"`
	// AuthorRoles for author_reviews: reviewed-by (default), commenter, author.
	AuthorRoles []string `yaml:"author_roles"`
}

type RunConfig struct {
	MaxPRs   int      `yaml:"max_prs"`
	MaxTurns int      `yaml:"max_turns"`
	// Concurrency is parallel PR collect workers (gh). 0 = default (4). Cap 16.
	// Local package runs stay serialized under a per-path lock.
	Concurrency int      `yaml:"concurrency"`
	Only        []string `yaml:"only"`
}

// OfficialEnabled returns whether the official jury is on (default true).
func (c Config) OfficialEnabled() bool {
	if c.Official.Enabled == nil {
		return true
	}
	return *c.Official.Enabled
}

// StateDirResolved returns state dir relative to workspace.
func (c Config) StateDirResolved() string {
	if strings.TrimSpace(c.StateDir) == "" {
		return DefaultStateDir
	}
	return c.StateDir
}

// DiscoveryMode returns the effective discovery strategy.
func (c Config) DiscoveryMode() string {
	d := strings.ToLower(strings.TrimSpace(c.Sources.Discovery))
	switch d {
	case "repos", "repo", "catalog":
		return "repos"
	case "author_reviews", "author", "authors", "person", "reviewed-by":
		return "author_reviews"
	case "":
		// Auto: person-first when authors_only is set and no explicit repo list.
		if len(trimNonEmpty(c.Sources.AuthorsOnly)) > 0 && len(trimNonEmpty(c.Sources.Repos)) == 0 {
			return "author_reviews"
		}
		return "repos"
	default:
		return d
	}
}

// Validate reports config errors (empty sources, etc.).
func (c Config) Validate() error {
	if c.Version != 0 && c.Version != 1 {
		return fmt.Errorf("unsupported config version %d (want 1)", c.Version)
	}
	if strings.TrimSpace(c.Adversaries.Root) == "" && strings.TrimSpace(c.Adversaries.Path) == "" {
		return fmt.Errorf("adversaries.root or adversaries.path is required")
	}
	mode := c.DiscoveryMode()
	switch mode {
	case "author_reviews":
		if len(trimNonEmpty(c.Sources.AuthorsOnly)) == 0 {
			return fmt.Errorf("sources.discovery=author_reviews requires sources.authors_only (GitHub logins)")
		}
	case "repos":
		if !c.HasRepoSources() {
			return fmt.Errorf("sources are empty: set sources.repos and/or sources.org, or use sources.authors_only for author_reviews discovery")
		}
	default:
		return fmt.Errorf("unknown sources.discovery %q (want repos or author_reviews)", c.Sources.Discovery)
	}
	if c.Run.MaxPRs < 0 || c.Run.MaxTurns < 0 {
		return fmt.Errorf("run.max_prs and run.max_turns must be non-negative")
	}
	return nil
}

// HasHistorySources reports whether any history target is configured.
func (c Config) HasHistorySources() bool {
	if c.DiscoveryMode() == "author_reviews" && len(trimNonEmpty(c.Sources.AuthorsOnly)) > 0 {
		return true
	}
	return c.HasRepoSources()
}

// HasRepoSources reports org or explicit repos.
func (c Config) HasRepoSources() bool {
	if strings.TrimSpace(c.Sources.Org) != "" {
		return true
	}
	for _, r := range c.Sources.Repos {
		if strings.TrimSpace(r) != "" {
			return true
		}
	}
	return false
}

func trimNonEmpty(in []string) []string {
	var out []string
	for _, s := range in {
		if strings.TrimSpace(s) != "" {
			out = append(out, strings.TrimSpace(s))
		}
	}
	return out
}

// Load reads and validates adversary.train.yaml from workspace (or path).
func Load(path string) (Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var c Config
	if err := yaml.Unmarshal(raw, &c); err != nil {
		return Config{}, fmt.Errorf("parse %s: %w", path, err)
	}
	if c.Version == 0 {
		c.Version = 1
	}
	if c.Sources.Host == "" {
		c.Sources.Host = "github.com"
	}
	if c.Run.MaxPRs == 0 {
		c.Run.MaxPRs = 50
	}
	if c.Run.MaxTurns == 0 {
		c.Run.MaxTurns = 200
	}
	if c.StateDir == "" {
		c.StateDir = DefaultStateDir
	}
	return c, nil
}

// FindConfig walks from dir upward for adversary.train.yaml.
func FindConfig(start string) (string, error) {
	dir, err := filepath.Abs(start)
	if err != nil {
		return "", err
	}
	for {
		cand := filepath.Join(dir, DefaultConfigName)
		if st, err := os.Stat(cand); err == nil && !st.IsDir() {
			return cand, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("%s not found from %s", DefaultConfigName, start)
		}
		dir = parent
	}
}

// OfficialIncluded reports whether an official package id is in the jury.
func (c Config) OfficialIncluded(id string) bool {
	if !c.OfficialEnabled() {
		return false
	}
	id = normalizeID(id)
	for _, ex := range c.Official.Exclude {
		if normalizeID(ex) == id {
			return false
		}
	}
	if len(c.Official.Include) == 0 {
		return true
	}
	for _, in := range c.Official.Include {
		if normalizeID(in) == id {
			return true
		}
	}
	return false
}

// LocalOverride returns the local package id if official id is overridden.
func (c Config) LocalOverride(officialID string) (string, bool) {
	if c.Adversaries.Overrides == nil {
		return "", false
	}
	for k, v := range c.Adversaries.Overrides {
		if normalizeID(k) == normalizeID(officialID) {
			return v, true
		}
	}
	return "", false
}

func normalizeID(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	s = strings.ReplaceAll(s, "_", "-")
	return s
}
