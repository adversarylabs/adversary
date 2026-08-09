package adversaries

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExpandUsesRefsNoUses(t *testing.T) {
	dir := t.TempDir()
	pkg := Package{Dir: dir, ID: "plain"}
	refs, err := ExpandUsesRefs(pkg)
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 1 {
		t.Fatalf("%#v", refs)
	}
}

func TestExpandUsesRefsLocalPaths(t *testing.T) {
	root := t.TempDir()
	leaf := filepath.Join(root, "leaf")
	if err := os.MkdirAll(leaf, 0o755); err != nil {
		t.Fatal(err)
	}
	metaYAML := `name: meta/go
version: 0.0.1
uses:
  - path: leaf
  - name: go/security
runtime:
  name: node
  version: "22"
  command: [dist/index.js]
`
	leafYAML := `name: go/leaf
version: 0.0.1
runtime:
  name: node
  version: "22"
  command: [dist/index.js]
`
	if err := os.WriteFile(filepath.Join(root, "adversary.yaml"), []byte(metaYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(leaf, "adversary.yaml"), []byte(leafYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	// loadPackage requires scope.md
	if err := os.MkdirAll(filepath.Join(root, "agent"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "agent", "scope.md"), []byte("# scope\n\nIn scope: everything.\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	pkg, err := loadPackage(root, "meta")
	if err != nil {
		t.Fatal(err)
	}
	if len(pkg.Uses) != 2 {
		t.Fatalf("uses %#v", pkg.Uses)
	}
	refs, err := ExpandUsesRefs(pkg)
	if err != nil {
		t.Fatal(err)
	}
	// root + leaf + go/security name
	if len(refs) < 3 {
		t.Fatalf("want at least 3 refs, got %#v", refs)
	}
	joined := strings.Join(refs, "\n")
	if !strings.Contains(joined, "go/security") {
		t.Fatalf("missing registry member: %s", joined)
	}
	if !strings.Contains(joined, "leaf") && !strings.Contains(joined, leaf) {
		t.Fatalf("missing leaf path: %s", joined)
	}
}

func TestFormatUsesSummary(t *testing.T) {
	s := FormatUsesSummary(Package{Uses: []UseSpec{
		{Name: "go/cli"},
		{Name: "go/security", Version: "0.1.0"},
		{Path: "../x"},
	}})
	if !strings.Contains(s, "go/cli") || !strings.Contains(s, "go/security:0.1.0") || !strings.Contains(s, "path:../x") {
		t.Fatal(s)
	}
}
