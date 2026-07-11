package adversary

import (
	"context"
	"github.com/adversarylabs/adversary/pkg/pack"
	"github.com/adversarylabs/adversary/pkg/repository"
	legacy "github.com/adversarylabs/adversary/pkg/store"
	"os"
	"path/filepath"
	"testing"
)

func resolverArtifact(t *testing.T, root, name, content string) pack.Artifact {
	t.Helper()
	_ = os.MkdirAll(filepath.Join(root, "dist"), 0755)
	_ = os.WriteFile(filepath.Join(root, "adversary.yaml"), []byte("name: "+name+"\nversion: 1.0.0\nruntime:\n  name: node\n  version: \"22\"\n  command: [dist/index.js]\n"), 0644)
	_ = os.WriteFile(filepath.Join(root, "dist/index.js"), []byte(content), 0644)
	a, err := pack.Create(context.Background(), pack.Options{Dir: root})
	if err != nil {
		t.Fatal(err)
	}
	return a
}
func TestResolverPrecedenceAndAmbiguity(t *testing.T) {
	root := t.TempDir()
	repoRoot := filepath.Join(root, "repo")
	_ = os.MkdirAll(repoRoot, 0700)
	r := Resolver{Repository: repository.Repository{Root: repoRoot}, Legacy: legacy.Store{Root: filepath.Join(root, "legacy")}}
	a := resolverArtifact(t, t.TempDir(), "one.example/team/tool", "one")
	b := resolverArtifact(t, t.TempDir(), "two.example/other/tool", "two")
	ra, err := r.Repository.ImportPacked(a, "one.example/team/tool:1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Repository.ImportPacked(b, "two.example/other/tool:1.0.0"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Resolve("tool"); err != repository.ErrAmbiguous {
		t.Fatalf("alias err=%v", err)
	}
	got, err := r.Resolve(ra.Digest)
	if err != nil || got.Digest != ra.Digest {
		t.Fatalf("digest=%#v err=%v", got, err)
	}
	local := t.TempDir()
	_ = os.WriteFile(filepath.Join(local, "adversary.yaml"), a.AdversaryManifest, 0644)
	got, err = r.Resolve(local)
	if err != nil || !got.Local {
		t.Fatalf("path precedence=%#v err=%v", got, err)
	}
	if got.Path != local {
		t.Fatalf("path=%s", got.Path)
	}
	makeResolverWritable(repoRoot)
}
func makeResolverWritable(root string) {
	_ = filepath.Walk(root, func(p string, i os.FileInfo, e error) error {
		if e == nil {
			_ = os.Chmod(p, i.Mode().Perm()|0700)
		}
		return nil
	})
}
func TestWindowsPathIsNotRegistryReference(t *testing.T) {
	if isFullyQualified(`C:\work\adversary`) {
		t.Fatal("Windows path classified as registry reference")
	}
}
