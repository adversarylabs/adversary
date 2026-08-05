package workspace

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadAndValidateEmptySources(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, DefaultConfigName)
	body := `
version: 1
adversaries:
  path: .
sources:
  host: github.com
  repos: []
run:
  max_prs: 10
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected empty sources validation error")
	}
}

func TestAuthorReviewsDiscoveryValidates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, DefaultConfigName)
	body := `
version: 1
adversaries:
  path: ../person-x
official:
  enabled: false
sources:
  discovery: author_reviews
  authors_only: [mitchellh]
  orgs: [hashicorp]
  author_roles: [reviewed-by]
run:
  max_prs: 20
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.DiscoveryMode() != "author_reviews" {
		t.Fatalf("mode=%s", cfg.DiscoveryMode())
	}
}

func TestAuthorOnlyAutoDiscoveryMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, DefaultConfigName)
	body := `
version: 1
adversaries:
  path: .
sources:
  authors_only: [dhh]
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DiscoveryMode() != "author_reviews" {
		t.Fatalf("auto mode want author_reviews got %s", cfg.DiscoveryMode())
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestAuthorReviewsRequiresAuthors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, DefaultConfigName)
	body := `
version: 1
adversaries:
  path: .
sources:
  discovery: author_reviews
  repos: []
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error")
	}
}

func TestLoadValidConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, DefaultConfigName)
	body := `
version: 1
adversaries:
  root: ./adversaries
official:
  enabled: true
  exclude: [engineering-review]
sources:
  host: github.com
  repos: [acme/payments]
  authors_only: [alice]
  authors_ignore: [bob]
run:
  max_prs: 5
  max_turns: 20
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if !cfg.OfficialEnabled() {
		t.Fatal("official should be enabled")
	}
	if cfg.OfficialIncluded("engineering-review") {
		t.Fatal("engineering-review should be excluded")
	}
	if !cfg.OfficialIncluded("go-testing") {
		t.Fatal("go-testing should be included by default")
	}
	if !cfg.FilterAuthor("alice") {
		t.Fatal("alice should be allowed")
	}
	if cfg.FilterAuthor("bob") {
		t.Fatal("bob should be ignored")
	}
	if cfg.FilterAuthor("carol") {
		t.Fatal("carol not in authors_only")
	}
}

func TestAuthorAllowedIgnoreWins(t *testing.T) {
	if AuthorAllowed("alice", []string{"alice"}, []string{"alice"}) {
		t.Fatal("ignore must win over only")
	}
}

func TestAttributeGoldOfficialCatchSuppressesLocalDraft(t *testing.T) {
	cfg := Config{}
	out := AttributeGold(cfg, "my-policy", RoleLocalTrainable, true, "go-testing", true)
	if out.EmitDraft {
		t.Fatalf("should not draft: %+v", out)
	}
	if !out.OfficialCaught {
		t.Fatal("expected official catch")
	}
}

func TestAttributeGoldLocalMissEmitsDraft(t *testing.T) {
	cfg := Config{}
	out := AttributeGold(cfg, "my-policy", RoleLocalTrainable, true, "", true)
	if !out.EmitDraft || !out.LocalMiss {
		t.Fatalf("expected local draft: %+v", out)
	}
}

func TestAttributeGoldNeverDraftsOfficial(t *testing.T) {
	cfg := Config{}
	out := AttributeGold(cfg, "go-security", RoleOfficialJury, true, "", false)
	if out.EmitDraft {
		t.Fatalf("must not draft for official: %+v", out)
	}
}

func TestPreferLocalOverride(t *testing.T) {
	cfg := Config{Adversaries: AdversariesConfig{Overrides: map[string]string{"go/security": "acme-security"}}}
	id, role := PreferLocalOwner(cfg, "acme-security", "go/security", true, true)
	if id != "acme-security" || role != RoleLocalTrainable {
		t.Fatalf("got %s %s", id, role)
	}
}

func TestInitWritesStub(t *testing.T) {
	dir := t.TempDir()
	res, err := Init(InitOptions{Path: dir})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Created {
		t.Fatal("expected config created")
	}
	raw, err := os.ReadFile(res.Config)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, want := range []string{"version: 1", "sources:", "authors_ignore", "official:", "state_dir:", "adversaries:"} {
		if !strings.Contains(text, want) {
			t.Fatalf("stub missing %q", want)
		}
	}
	if _, err := os.Stat(filepath.Join(res.StateDir, "state", "discovery")); err != nil {
		t.Fatal(err)
	}
	gi, err := os.ReadFile(filepath.Join(dir, ".gitignore"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(gi), DefaultStateDir) {
		t.Fatal("gitignore missing state dir")
	}
	// Second init does not clobber
	if err := os.WriteFile(res.Config, []byte("version: 1\nadversaries:\n  path: .\nsources:\n  repos: [a/b]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	res2, err := Init(InitOptions{Path: dir})
	if err != nil {
		t.Fatal(err)
	}
	if res2.Created {
		t.Fatal("second init should not recreate")
	}
	raw2, _ := os.ReadFile(res.Config)
	if !strings.Contains(string(raw2), "a/b") {
		t.Fatal("user config was clobbered")
	}
}
