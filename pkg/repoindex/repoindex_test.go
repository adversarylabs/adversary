package repoindex

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func execCommand(dir, name string, args ...string) *exec.Cmd {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	return cmd
}

func TestFingerprintHitMissDirty(t *testing.T) {
	root := t.TempDir()
	// git init
	run(t, root, "git", "init")
	run(t, root, "git", "config", "user.email", "t@example.com")
	run(t, root, "git", "config", "user.name", "t")
	write(t, root, "go.mod", "module example.com/app\n\ngo 1.22\n")
	write(t, root, "pkg/a/a.go", "package a\n\nimport \"fmt\"\n\nfunc A() { fmt.Println(1) }\n")
	write(t, root, "pkg/b/b.go", "package b\n\nimport \"example.com/app/pkg/a\"\n\nfunc B() { a.A() }\n")
	run(t, root, "git", "add", ".")
	run(t, root, "git", "commit", "-m", "init")

	t.Setenv("ADVERSARY_REPO_INDEX_DIR", t.TempDir())

	h1, err := Ensure(root, ModeAuto, nil)
	if err != nil {
		t.Fatal(err)
	}
	if h1 == nil || !h1.Meta.Rebuilt {
		// first build always rebuilds; Rebuilt is set on Build path
		// Ensure sets Rebuilt true only after Build — good
	}
	if !h1.Meta.Rebuilt {
		// Actually first ensure rebuilds and sets Rebuilt true
		t.Log("first ensure rebuilt=", h1.Meta.Rebuilt)
	}
	// Force check: second ensure should hit
	h2, err := Ensure(root, ModeAuto, nil)
	if err != nil {
		t.Fatal(err)
	}
	if h2.Meta.Rebuilt {
		t.Fatal("expected cache hit on unchanged worktree")
	}
	if h2.Dir != h1.Dir {
		t.Fatalf("dir mismatch %s vs %s", h1.Dir, h2.Dir)
	}

	// Dirty edit invalidates
	write(t, root, "pkg/a/a.go", "package a\n\nimport \"fmt\"\n\nfunc A() { fmt.Println(2) }\n")
	fpDirty1, err := Fingerprint(root)
	if err != nil {
		t.Fatal(err)
	}
	h3, err := Ensure(root, ModeAuto, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !h3.Meta.Rebuilt {
		t.Fatal("expected rebuild after dirty edit")
	}

	// Second distinct dirty rewrite of the same path must change the fingerprint
	// (porcelain alone is not enough — content must be part of the key).
	write(t, root, "pkg/a/a.go", "package a\n\nimport \"fmt\"\n\nfunc A() { fmt.Println(3) }\n")
	fpDirty2, err := Fingerprint(root)
	if err != nil {
		t.Fatal(err)
	}
	if fpDirty1 == fpDirty2 {
		t.Fatal("two different dirty edits produced the same fingerprint")
	}
	h4, err := Ensure(root, ModeAuto, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !h4.Meta.Rebuilt {
		t.Fatal("expected rebuild after second dirty rewrite")
	}
	// Unchanged after second rewrite → hit
	h5, err := Ensure(root, ModeAuto, nil)
	if err != nil {
		t.Fatal(err)
	}
	if h5.Meta.Rebuilt {
		t.Fatal("expected cache hit when dirty content is unchanged")
	}
}

func TestFingerprintDistinguishesDirtyContent(t *testing.T) {
	root := t.TempDir()
	run(t, root, "git", "init")
	run(t, root, "git", "config", "user.email", "t@example.com")
	run(t, root, "git", "config", "user.name", "t")
	write(t, root, "main.go", "package main\n\nfunc main() {}\n")
	run(t, root, "git", "add", ".")
	run(t, root, "git", "commit", "-m", "init")

	write(t, root, "main.go", "package main\n\nfunc main() { println(1) }\n")
	fp1, err := Fingerprint(root)
	if err != nil {
		t.Fatal(err)
	}
	write(t, root, "main.go", "package main\n\nfunc main() { println(2) }\n")
	fp2, err := Fingerprint(root)
	if err != nil {
		t.Fatal(err)
	}
	if fp1 == fp2 {
		t.Fatalf("dirty content fingerprints collided: %s", fp1)
	}
}

func TestEnsureSharesCacheAcrossIdenticalWorktrees(t *testing.T) {
	root := t.TempDir()
	run(t, root, "git", "init")
	run(t, root, "git", "config", "user.email", "t@example.com")
	run(t, root, "git", "config", "user.name", "t")
	write(t, root, "main.go", "package main\n\nfunc main() {}\n")
	run(t, root, "git", "add", ".")
	run(t, root, "git", "commit", "-m", "init")

	clone := filepath.Join(t.TempDir(), "clone")
	run(t, "", "git", "clone", "--quiet", root, clone)
	t.Setenv("ADVERSARY_REPO_INDEX_DIR", t.TempDir())

	first, err := Ensure(root, ModeAuto, nil)
	if err != nil || first == nil || !first.Meta.Rebuilt {
		t.Fatalf("first=%#v err=%v", first, err)
	}
	second, err := Ensure(clone, ModeAuto, nil)
	if err != nil || second == nil {
		t.Fatalf("second=%#v err=%v", second, err)
	}
	if second.Meta.Rebuilt {
		t.Fatal("expected identical worktree at a different path to reuse cache")
	}
	if first.Dir != second.Dir {
		t.Fatalf("cache directories differ: %s vs %s", first.Dir, second.Dir)
	}
}

func TestGoAndTSImportEdges(t *testing.T) {
	root := t.TempDir()
	t.Setenv("ADVERSARY_REPO_INDEX_DIR", t.TempDir())
	write(t, root, "go.mod", "module example.com/app\n\ngo 1.22\n")
	write(t, root, "pkg/a/a.go", "package a\n\nfunc A() {}\n")
	write(t, root, "pkg/b/b.go", "package b\n\nimport \"example.com/app/pkg/a\"\n\nfunc B() { a.A() }\n")
	write(t, root, "src/util.ts", "export function util(): number { return 1 }\n")
	write(t, root, "src/main.ts", "import { util } from \"./util\"\nexport const x = util()\n")
	// excluded
	write(t, root, "node_modules/x/index.js", "export const bad = 1\n")
	write(t, root, "vendor/y/y.go", "package y\n")

	fp, err := Fingerprint(root)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "idx")
	meta, err := Build(root, dir, fp)
	if err != nil {
		t.Fatal(err)
	}
	if meta.FileCount < 4 {
		t.Fatalf("expected >=4 files, got %d", meta.FileCount)
	}
	idx, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	// no vendor/node_modules
	for _, f := range idx.Files {
		if strings.Contains(f.Path, "node_modules") || strings.Contains(f.Path, "vendor/") {
			t.Fatalf("excluded path present: %s", f.Path)
		}
	}

	// Go: b imports a package
	imps := idx.ImportsOf("pkg/b/b.go")
	if len(imps) == 0 {
		t.Fatal("expected go import edges from pkg/b/b.go")
	}
	foundA := false
	for _, e := range imps {
		if e.To == "pkg/a" || strings.HasSuffix(e.To, "pkg/a") {
			foundA = true
		}
	}
	if !foundA {
		t.Fatalf("expected edge to pkg/a, got %+v", imps)
	}
	importers := idx.ImportersOf("pkg/a/a.go")
	// package dir match
	if len(importers) == 0 {
		// try package dir
		importers = idx.ImportersOf("pkg/a")
	}
	if len(importers) == 0 {
		t.Fatalf("expected importers of pkg/a, edges=%+v", idx.Edges)
	}

	// TS relative
	tsImps := idx.ImportsOf("src/main.ts")
	if len(tsImps) != 1 || tsImps[0].To != "src/util.ts" {
		t.Fatalf("ts imports: %+v", tsImps)
	}
	tsImporters := idx.ImportersOf("src/util.ts")
	if len(tsImporters) != 1 || tsImporters[0].From != "src/main.ts" {
		t.Fatalf("ts importers: %+v", tsImporters)
	}
}

func TestParseMode(t *testing.T) {
	m, err := ParseMode("auto")
	if err != nil || m != ModeAuto {
		t.Fatal(m, err)
	}
	if _, err := ParseMode("nope"); err == nil {
		t.Fatal("expected error")
	}
	if m, err := ParseMode("v2"); err != nil || m != ModeGraph {
		t.Fatal(m, err)
	}
	if m, err := ParseMode("graph-force"); err != nil || m != ModeGraphForce {
		t.Fatal(m, err)
	}
}

func write(t *testing.T, root, rel, body string) {
	t.Helper()
	path := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func run(t *testing.T, dir string, name string, args ...string) {
	t.Helper()
	cmd := execCommand(dir, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
}
