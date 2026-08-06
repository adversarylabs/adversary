package compose

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/adversarylabs/adversary/pkg/manifest"
)

type mapLoader struct {
	// ref -> (manifest yaml or path to package dir)
	byRef map[string]string
	dirs  map[string]string // ref -> packageDir
}

func (m mapLoader) Load(ref string) (manifest.Manifest, string, error) {
	raw, ok := m.byRef[ref]
	if !ok {
		// try cleaned path
		for k, v := range m.byRef {
			if filepath.Clean(k) == filepath.Clean(ref) {
				raw, ok = v, true
				ref = k
				break
			}
		}
	}
	if !ok {
		return manifest.Manifest{}, "", fmt.Errorf("not found: %s", ref)
	}
	mf, err := manifest.Parse([]byte(raw))
	if err != nil {
		return manifest.Manifest{}, "", err
	}
	dir := m.dirs[ref]
	if dir == "" {
		dir = filepath.Dir(ref)
	}
	return mf, dir, nil
}

func baseYAML(name string, usesBlock string) string {
	return fmt.Sprintf(`name: %s
version: 0.0.1
%sruntime:
  name: node
  version: "22"
  command: [dist/index.js]
`, name, usesBlock)
}

func TestExpandFlatUses(t *testing.T) {
	rootDir := t.TempDir()
	load := mapLoader{
		byRef: map[string]string{
			rootDir: baseYAML("person/torvalds", `uses:
  - name: review/engineering
  - name: go/concurrency
    version: "0.1.0"
`),
			"review/engineering":   baseYAML("review/engineering", ""),
			"go/concurrency:0.1.0": baseYAML("go/concurrency", ""),
		},
		dirs: map[string]string{rootDir: rootDir},
	}
	got, err := Expand([]string{rootDir}, load, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Refs) != 3 {
		t.Fatalf("refs %#v", got.Refs)
	}
	if got.Refs[0] != rootDir {
		t.Fatalf("root first: %#v", got.Refs)
	}
	if got.Refs[1] != "review/engineering" || got.Refs[2] != "go/concurrency:0.1.0" {
		t.Fatalf("members: %#v", got.Refs)
	}
	if !got.Expanded {
		t.Fatal("expected Expanded")
	}
	if len(got.VoiceRoots) != 1 || got.VoiceRoots[0] != rootDir {
		t.Fatalf("voice roots %#v", got.VoiceRoots)
	}
}

func TestExpandTransitiveMetaPackage(t *testing.T) {
	// person/torvalds → go → go/concurrency, go/security
	load := mapLoader{
		byRef: map[string]string{
			"person/torvalds": baseYAML("person/torvalds", `uses:
  - name: go
  - name: review/engineering
`),
			"go": baseYAML("go", `uses:
  - name: go/concurrency
  - name: go/security
`),
			"go/concurrency":     baseYAML("go/concurrency", ""),
			"go/security":        baseYAML("go/security", ""),
			"review/engineering": baseYAML("review/engineering", ""),
		},
		dirs: map[string]string{},
	}
	got, err := Expand([]string{"person/torvalds"}, load, Options{})
	if err != nil {
		t.Fatal(err)
	}
	// root + go + eng + concurrency + security
	if len(got.Refs) != 5 {
		t.Fatalf("want 5 got %#v", got.Refs)
	}
	// Dedup: go/security listed once even if also direct
	join := strings.Join(got.Refs, ",")
	if strings.Count(join, "go/security") != 1 {
		t.Fatalf("dedupe failed: %s", join)
	}
}

func TestExpandDedupeDiamond(t *testing.T) {
	load := mapLoader{
		byRef: map[string]string{
			"a":      baseYAML("a", "uses:\n  - name: shared\n  - name: b\n"),
			"b":      baseYAML("b", "uses:\n  - name: shared\n"),
			"shared": baseYAML("shared", ""),
		},
	}
	got, err := Expand([]string{"a"}, load, Options{})
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, r := range got.Refs {
		if r == "shared" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("shared count %d in %#v", n, got.Refs)
	}
}

func TestExpandCycle(t *testing.T) {
	load := mapLoader{
		byRef: map[string]string{
			"a": baseYAML("a", "uses:\n  - name: b\n"),
			"b": baseYAML("b", "uses:\n  - name: a\n"),
		},
	}
	got, err := Expand([]string{"a"}, load, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Refs) != 2 {
		t.Fatalf("cycle should still run both once: %#v", got.Refs)
	}
}

func TestExpandRelativePath(t *testing.T) {
	root := t.TempDir()
	member := filepath.Join(root, "members", "nit")
	if err := os.MkdirAll(member, 0o755); err != nil {
		t.Fatal(err)
	}
	load := mapLoader{
		byRef: map[string]string{
			root:   baseYAML("meta/go", "uses:\n  - path: members/nit\n"),
			member: baseYAML("go/nit", ""),
		},
		dirs: map[string]string{root: root, member: member},
	}
	got, err := Expand([]string{root}, load, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Refs) != 2 {
		t.Fatalf("%#v", got.Refs)
	}
	if filepath.Clean(got.Refs[1]) != filepath.Clean(member) {
		t.Fatalf("member path %#v", got.Refs[1])
	}
}

func TestExpandMaxDepth(t *testing.T) {
	load := mapLoader{
		byRef: map[string]string{
			"a": baseYAML("a", "uses:\n  - name: b\n"),
			"b": baseYAML("b", "uses:\n  - name: c\n"),
			"c": baseYAML("c", ""),
		},
	}
	got, err := Expand([]string{"a"}, load, Options{MaxDepth: 1})
	if err != nil {
		t.Fatal(err)
	}
	// depth 0: a, depth 1: b; c not expanded from b
	if len(got.Refs) != 2 {
		t.Fatalf("max depth: %#v", got.Refs)
	}
}

func TestExpandMissingMemberStaysAsLeaf(t *testing.T) {
	// Parent loads; missing child is enqueued then skipped on load (still in Refs).
	load := mapLoader{byRef: map[string]string{
		"a": baseYAML("a", "uses:\n  - name: missing\n"),
	}}
	got, err := Expand([]string{"a"}, load, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Refs) != 2 || got.Refs[1] != "missing" {
		t.Fatalf("%#v", got.Refs)
	}
}
