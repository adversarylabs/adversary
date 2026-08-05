package repos

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadAndFilter(t *testing.T) {
	// Catalog ships under internal/train/config/repositories.json
	path := filepath.Join("..", "config", "repositories.json")
	if _, err := os.Stat(path); err != nil {
		// also try DefaultPath from module root
		root, _ := filepath.Abs(filepath.Join("..", "..", ".."))
		path = filepath.Join(root, "internal", "train", "config", "repositories.json")
	}
	if _, err := os.Stat(path); err != nil {
		t.Skip("catalog not found:", path)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Repositories) < 1 {
		t.Fatalf("expected repositories, got %d", len(c.Repositories))
	}
	goOnly := c.Filter("discovery", []string{"go"})
	if len(goOnly) < 1 {
		// catalog may use empty languages = any
		goOnly = c.Filter("discovery", nil)
	}
	if len(goOnly) < 1 {
		t.Fatalf("expected discovery repos, got %d", len(goOnly))
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
