package adversary

import (
	"context"
	"encoding/json"
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
	digest := oci.Digest([]byte("manifest"))
	digestPath, err := oci.DigestPath(digest)
	if err != nil {
		t.Fatal(err)
	}
	record := InstallRecord{
		Name:           "local/security-reviewer",
		Version:        "1.4.2",
		Reference:      "registry.adversarylabs.ai/adversarylabs/security-reviewer:latest",
		ManifestDigest: digest,
		Path:           filepath.Join(cache.Root, "artifacts", digestPath),
	}
	if err := os.MkdirAll(record.Path, 0755); err != nil {
		t.Fatal(err)
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

func TestCacheKeysDoNotCollideAndLegacyRecordsRemainReadable(t *testing.T) {
	if cacheKey("a/b") == cacheKey("a_b") || cacheKey("é") == cacheKey("e\u0301") {
		t.Fatal("v2 cache keys collided")
	}
	cache := Cache{Root: t.TempDir()}
	digest := oci.Digest([]byte("legacy"))
	digestPath, _ := oci.DigestPath(digest)
	record := InstallRecord{Name: "a/b", ManifestDigest: digest, Path: filepath.Join(cache.Root, "artifacts", digestPath)}
	if err := os.MkdirAll(record.Path, 0755); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(record)
	if err := os.MkdirAll(filepath.Join(cache.Root, "index"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cache.Root, "index", sanitize(record.Name)+".json"), data, 0644); err != nil {
		t.Fatal(err)
	}
	if got, ok := cache.Resolve(record.Name); !ok || got.Name != record.Name {
		t.Fatalf("legacy record was not resolved: %#v, %v", got, ok)
	}
}

func TestCacheRejectsLegacyCollisionAndTamperedDigestRecord(t *testing.T) {
	cache := Cache{Root: t.TempDir()}
	digest := oci.Digest([]byte("one"))
	digestPath, _ := oci.DigestPath(digest)
	wrong := InstallRecord{Name: "a_b", ManifestDigest: digest, Path: filepath.Join(cache.Root, "artifacts", digestPath)}
	data, _ := json.Marshal(wrong)
	if err := os.MkdirAll(filepath.Join(cache.Root, "index"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cache.Root, "index", sanitize("a/b")+".json"), data, 0644); err != nil {
		t.Fatal(err)
	}
	if got, ok := cache.Resolve("a/b"); ok {
		t.Fatalf("legacy collision returned %#v", got)
	}

	requested := oci.Digest([]byte("requested"))
	if err := os.MkdirAll(filepath.Join(cache.Root, "digests"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cache.Root, "digests", cacheKey(requested)+".json"), data, 0644); err != nil {
		t.Fatal(err)
	}
	if got, ok := cache.ResolveDigest(requested); ok {
		t.Fatalf("tampered digest record returned %#v", got)
	}
}

func TestCacheRootRejectsEscapingIndexSymlink(t *testing.T) {
	cache := Cache{Root: t.TempDir()}
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(cache.Root, "index")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, ok := cache.Resolve("anything"); ok {
		t.Fatal("resolved through escaping symlink")
	}
}

func TestCacheInstallRejectsEscapingDigestSymlink(t *testing.T) {
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
	pulled := oci.PulledArtifact{Reference: ref, Manifest: artifact.OCIManifest, ManifestDigest: artifact.ManifestDigest, AdversaryManifest: artifact.AdversaryManifest, Blobs: map[string][]byte{artifact.LayerDigest: artifact.Layer}}
	cache := Cache{Root: t.TempDir()}
	outside := t.TempDir()
	if err := os.MkdirAll(filepath.Join(cache.Root, "artifacts"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(cache.Root, "artifacts", "sha256")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := cache.Install(pulled); err == nil {
		t.Fatal("installed through escaping digest symlink")
	}
	entries, err := os.ReadDir(outside)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("outside files created: %v", entries)
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
