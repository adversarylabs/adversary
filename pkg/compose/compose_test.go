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

func TestExpandDedupeRelativeRootAndUsesPath(t *testing.T) {
	// Same package tree via relative CLI root and uses.path: . must run once.
	root := t.TempDir()
	member := filepath.Join(root, "leaf")
	if err := os.MkdirAll(member, 0o755); err != nil {
		t.Fatal(err)
	}
	rootYAML := baseYAML("meta/go", "uses:\n  - path: .\n  - path: leaf\n")
	leafYAML := baseYAML("go/leaf", "")
	if err := os.WriteFile(filepath.Join(root, "adversary.yaml"), []byte(rootYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(member, "adversary.yaml"), []byte(leafYAML), 0o644); err != nil {
		t.Fatal(err)
	}

	rootAbs, err := filepath.Abs(root)
	if err != nil {
		t.Fatal(err)
	}
	memberAbs, err := filepath.Abs(member)
	if err != nil {
		t.Fatal(err)
	}

	loader := loadFunc(func(ref string) (manifest.Manifest, string, error) {
		abs, err := filepath.Abs(filepath.Clean(ref))
		if err != nil {
			return manifest.Manifest{}, "", err
		}
		// EvalSymlinks so /var vs /private/var on macOS still matches TempDir.
		if eval, err := filepath.EvalSymlinks(abs); err == nil {
			abs = eval
		}
		rootKey := rootAbs
		if eval, err := filepath.EvalSymlinks(rootAbs); err == nil {
			rootKey = eval
		}
		memberKey := memberAbs
		if eval, err := filepath.EvalSymlinks(memberAbs); err == nil {
			memberKey = eval
		}
		switch abs {
		case rootKey:
			m, err := manifest.Parse([]byte(rootYAML))
			return m, rootKey, err
		case memberKey:
			m, err := manifest.Parse([]byte(leafYAML))
			return m, memberKey, err
		default:
			return manifest.Manifest{}, "", fmt.Errorf("not found: %s (%s)", ref, abs)
		}
	})

	// Expand using absolute root and a relative-style uses.path self-reference
	// (path: .) plus leaf — must not double-run root.
	got, err := Expand([]string{rootAbs}, loader, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Refs) != 2 {
		t.Fatalf("want 2 refs (root+leaf once each), got %#v", got.Refs)
	}
	if got.Refs[0] != rootAbs && got.Refs[0] != filepath.Clean(rootAbs) {
		// loader may return eval'd path
		if a0, e0 := filepath.EvalSymlinks(got.Refs[0]); e0 != nil {
			t.Fatalf("root ref %#v", got.Refs[0])
		} else if aR, _ := filepath.EvalSymlinks(rootAbs); a0 != aR {
			t.Fatalf("root ref %#v want %s", got.Refs[0], rootAbs)
		}
	}
}

func TestNormalizeRefKeyPathAliases(t *testing.T) {
	dir := t.TempDir()
	rel := filepath.Join(".", filepath.Base(dir))
	// Can't join parent easily; compare Abs of dir with itself via Clean+Abs
	a, err := filepath.Abs(dir)
	if err != nil {
		t.Fatal(err)
	}
	b, err := filepath.Abs(filepath.Clean(dir + string(filepath.Separator) + "."))
	if err != nil {
		t.Fatal(err)
	}
	if normalizeRefKey(a) != normalizeRefKey(b) {
		t.Fatalf("%q vs %q", normalizeRefKey(a), normalizeRefKey(b))
	}
	_ = rel
	if normalizeRefKey("go/concurrency") != "go/concurrency" {
		t.Fatal("registry name should stay lower-case name key")
	}
}

type loadFunc func(string) (manifest.Manifest, string, error)

func (f loadFunc) Load(ref string) (manifest.Manifest, string, error) { return f(ref) }
