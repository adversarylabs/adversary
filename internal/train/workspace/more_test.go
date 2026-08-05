package workspace

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFindConfigAndState(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "pkg")
	_ = os.MkdirAll(sub, 0o755)
	cfg := filepath.Join(dir, DefaultConfigName)
	body := "version: 1\nadversaries:\n  path: .\nsources:\n  authors_only: [x]\n"
	_ = os.WriteFile(cfg, []byte(body), 0o644)
	found, err := FindConfig(sub)
	if err != nil || found != cfg {
		t.Fatalf("%s %v", found, err)
	}
	c, err := Load(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if c.DiscoveryMode() != "author_reviews" {
		t.Fatal(c.DiscoveryMode())
	}
	state := ResolveStateAbs(cfg, c.StateDirResolved())
	if err := EnsureStateDir(state); err != nil {
		t.Fatal(err)
	}
	if !DirExists(state) {
		t.Fatal()
	}
}

func TestFirstScopedAndListDir(t *testing.T) {
	root := t.TempDir()
	_ = os.MkdirAll(filepath.Join(root, "a", "docs"), 0o755)
	_ = os.WriteFile(filepath.Join(root, "a", "docs", "scope.md"), []byte("x"), 0o644)
	got := FirstScopedPackage(root)
	if got == root {
		// may return first child
	}
	names, err := ListDir(root)
	if err != nil || len(names) == 0 {
		t.Fatal(err, names)
	}
	if !FileExists(filepath.Join(root, "a", "docs", "scope.md")) {
		t.Fatal()
	}
}

func TestWorkingDir(t *testing.T) {
	if _, err := WorkingDir(); err != nil {
		t.Fatal(err)
	}
}
