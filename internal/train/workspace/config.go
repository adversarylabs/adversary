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
	Host            string   `yaml:"host"`
	Org             string   `yaml:"org"`
	Repos           []string `yaml:"repos"`
	Languages       []string `yaml:"languages"`
	Since           string   `yaml:"since"`
	ReposAllowlist  []string `yaml:"repos_allowlist"`
	AuthorsIgnore   []string `yaml:"authors_ignore"`
	AuthorsOnly     []string `yaml:"authors_only"`
}

type RunConfig struct {
	MaxPRs   int      `yaml:"max_prs"`
	MaxTurns int      `yaml:"max_turns"`
	Only     []string `yaml:"only"`
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

// Validate reports config errors (empty sources, etc.).
func (c Config) Validate() error {
	if c.Version != 0 && c.Version != 1 {
		return fmt.Errorf("unsupported config version %d (want 1)", c.Version)
	}
	if strings.TrimSpace(c.Adversaries.Root) == "" && strings.TrimSpace(c.Adversaries.Path) == "" {
		return fmt.Errorf("adversaries.root or adversaries.path is required")
	}
	if !c.HasHistorySources() {
		return fmt.Errorf("sources are empty: set sources.org and/or sources.repos in %s", DefaultConfigName)
	}
	if c.Run.MaxPRs < 0 || c.Run.MaxTurns < 0 {
		return fmt.Errorf("run.max_prs and run.max_turns must be non-negative")
	}
	return nil
}

// HasHistorySources reports whether any history target is configured.
func (c Config) HasHistorySources() bool {
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
