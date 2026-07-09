package adversary

import (
	"os"
	"path/filepath"
	"testing"
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
