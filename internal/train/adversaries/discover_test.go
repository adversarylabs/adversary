package adversaries

import (
	"os"
	"path/filepath"
	"testing"
)

func writePkg(t *testing.T, root, dirName, id string) string {
	t.Helper()
	dir := filepath.Join(root, dirName)
	if err := os.MkdirAll(filepath.Join(dir, "docs"), 0o755); err != nil {
		t.Fatal(err)
	}
	scope := "# mission\n\nGo concurrency races and lifecycle.\n"
	if err := os.WriteFile(filepath.Join(dir, "docs", "scope.md"), []byte(scope), 0o644); err != nil {
		t.Fatal(err)
	}
	yaml := "name: " + id + "\ndescription: test\ntriggers:\n  files_changed:\n    - '**/*.go'\n"
	if err := os.WriteFile(filepath.Join(dir, "adversary.yaml"), []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestDiscoverRootAndByID(t *testing.T) {
	root := t.TempDir()
	writePkg(t, root, "go-concurrency-adversary", "go-concurrency")
	writePkg(t, root, "go-testing-adversary", "go-testing")
	// no scope — skipped
	_ = os.MkdirAll(filepath.Join(root, "empty-adversary"), 0o755)

	pkgs, err := DiscoverRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 2 {
		t.Fatalf("got %d pkgs: %+v", len(pkgs), pkgs)
	}
	by := ByID(pkgs)
	if _, ok := by["go-concurrency"]; !ok {
		t.Fatal("missing go-concurrency")
	}
	filtered := FilterByIDs(pkgs, []string{"go-testing"})
	if len(filtered) != 1 || filtered[0].ID != "go-testing" {
		t.Fatalf("%+v", filtered)
	}
	// empty filter = all
	if len(FilterByIDs(pkgs, nil)) != 2 {
		t.Fatal("empty only")
	}
}

func TestDiscoverRootSinglePackageWorkspace(t *testing.T) {
	root := t.TempDir()
	// package at root itself
	if err := os.MkdirAll(filepath.Join(root, "docs"), 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(root, "docs", "scope.md"), []byte("# m\n"), 0o644)
	_ = os.WriteFile(filepath.Join(root, "adversary.yaml"), []byte("name: solo\n"), 0o644)
	// Nested agent/scope.md must NOT be discovered as a second package.
	if err := os.MkdirAll(filepath.Join(root, "agent"), 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(root, "agent", "scope.md"), []byte("# agent fragment\nEverything is in scope.\n"), 0o644)
	pkgs, err := DiscoverRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("%+v", pkgs)
	}
	if pkgs[0].ID == "agent" {
		t.Fatal("must not treat agent/ as the package")
	}
	if filepath.Base(pkgs[0].Dir) != filepath.Base(root) {
		t.Fatalf("want package root, got dir=%s", pkgs[0].Dir)
	}
}

func TestDiscoverSiblings(t *testing.T) {
	parent := t.TempDir()
	// factory root
	factory := filepath.Join(parent, "adversary")
	_ = os.MkdirAll(factory, 0o755)
	writePkg(t, parent, "go-security-adversary", "go-security")
	pkgs, err := DiscoverSiblings(factory)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 1 || pkgs[0].ID != "go-security" {
		t.Fatalf("%+v", pkgs)
	}
	// languages from globs
	if len(pkgs[0].Languages) == 0 {
		t.Fatal("expected language inference")
	}
}

func TestLanguagesFromGlobs(t *testing.T) {
	got := languagesFromGlobs([]string{"**/*.go", "Dockerfile"}, "go-foo")
	if len(got) == 0 {
		t.Fatal("expected go")
	}
	any := languagesFromGlobs(nil, "engineering-review")
	if len(any) != 1 || any[0] != "any" {
		t.Fatalf("%v", any)
	}
}
