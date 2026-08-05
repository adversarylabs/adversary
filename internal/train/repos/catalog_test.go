package repos

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadAndFilter(t *testing.T) {
	// Prefer repo-root catalog when present.
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	path := DefaultPath(root)
	if _, err := os.Stat(path); err != nil {
		t.Skip("catalog not found:", path)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Repositories) < 50 {
		t.Fatalf("expected a large catalog, got %d", len(c.Repositories))
	}
	goOnly := c.Filter("discovery", []string{"go"})
	if len(goOnly) < 10 {
		t.Fatalf("expected many go repos, got %d", len(goOnly))
	}
	for _, r := range goOnly {
		if !r.MatchesLanguages([]string{"go"}) {
			t.Fatalf("%s should match go", r.FullName())
		}
	}
	any := c.Filter("discovery", nil)
	if len(any) < len(goOnly) {
		t.Fatalf("any filter should be >= go-only")
	}
	// engineering-review: empty languages = all
	py := Repo{Languages: []string{"python"}}
	if !py.MatchesLanguages(nil) {
		t.Fatal("empty filter should match all")
	}
	if py.MatchesLanguages([]string{"go"}) {
		t.Fatal("python should not match go filter")
	}
}
