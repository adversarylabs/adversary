package adversary

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/adversarylabs/adversary/pkg/oci"
	"github.com/adversarylabs/adversary/pkg/pack"
)

func TestPackageDirectoryIsDeterministic(t *testing.T) {
	dir := t.TempDir()
	writePackageFile(t, dir, "README.md", "# Test\n")
	writePackageFile(t, dir, "dist/index.js", "console.log('ok')\n")
	writePackageFile(t, dir, "adversary.yaml", `name: local/test
version: 1.0.0
runtime:
  image: test:local
  command:
    - node
    - dist/index.js
`)

	first, err := PackageDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
	second, err := PackageDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
	if string(first.Layer) != string(second.Layer) {
		t.Fatal("package layer is not deterministic")
	}
	if first.Blob.Descriptor.Digest != second.Blob.Descriptor.Digest {
		t.Fatal("package digest is not deterministic")
	}
	if got := len(first.Blobs()); got != 2 {
		t.Fatalf("package blobs = %d, want config and layer", got)
	}
}

func TestCacheInstallRejectsInvalidPulledManifest(t *testing.T) {
	dir := t.TempDir()
	writePackageFile(t, dir, "adversary.yaml", "name: local/test\nversion: 1.0.0\nruntime:\n  name: node\n  version: \"22\"\n  command: [dist/index.js]\n")
	writePackageFile(t, dir, "dist/index.js", "")
	artifact, err := pack.Create(context.Background(), pack.Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	ref, err := oci.ParseReference("local/test:1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	pulled := oci.PulledArtifact{Reference: ref, Manifest: artifact.OCIManifest, ManifestDigest: artifact.ManifestDigest, AdversaryManifest: []byte("name: INVALID\n"), Blobs: map[string][]byte{artifact.LayerDigest: artifact.Layer}}
	if _, err := (Cache{Root: t.TempDir()}).Install(pulled); err == nil {
		t.Fatal("Install succeeded")
	}
}

func TestCacheReferenceAliases(t *testing.T) {
	cache := Cache{Root: t.TempDir()}
	record := InstallRecord{
		Name:           "local/security-reviewer",
		Version:        "1.4.2",
		Reference:      "registry.adversarylabs.ai/adversarylabs/security-reviewer:latest",
		ManifestDigest: "sha256:abc",
		Path:           "/tmp/security-reviewer",
	}
	if err := cache.writeRecord(record); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{
		"local/security-reviewer",
		"registry.adversarylabs.ai/adversarylabs/security-reviewer:latest",
		"adversarylabs/security-reviewer",
		"security-reviewer",
	} {
		got, ok := cache.Resolve(key)
		if !ok {
			t.Fatalf("expected cache alias %q", key)
		}
		if got.ManifestDigest != record.ManifestDigest {
			t.Fatalf("alias %q resolved digest %q", key, got.ManifestDigest)
		}
	}
}

func writePackageFile(t *testing.T, dir, rel, content string) {
	t.Helper()
	path := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}
