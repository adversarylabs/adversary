package store

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/adversarylabs/adversary/pkg/oci"
	"github.com/adversarylabs/adversary/pkg/pack"
)

func TestStoreRefsListInspectAndDedupe(t *testing.T) {
	dir := testProject(t)
	artifact, err := pack.Create(context.Background(), pack.Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	localStore := Store{Root: t.TempDir()}
	record, err := localStore.Put(artifact)
	if err != nil {
		t.Fatal(err)
	}
	if record.RuntimeName != "node" || record.RuntimeVersion != "22" {
		t.Fatalf("runtime requirement = %s@%s", record.RuntimeName, record.RuntimeVersion)
	}
	if got := readRef(t, localStore.Root, "security-reviewer", "0.1.0"); got != record.Digest {
		t.Fatalf("version ref = %q, want %q", got, record.Digest)
	}
	if got := readRef(t, localStore.Root, "security-reviewer", "latest"); got != record.Digest {
		t.Fatalf("latest ref = %q, want %q", got, record.Digest)
	}
	records, err := localStore.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("records = %d, want 1", len(records))
	}
	for _, ref := range []string{"security-reviewer", "security-reviewer:0.1.0", record.Digest} {
		got, err := localStore.Inspect(ref)
		if err != nil {
			t.Fatalf("inspect %q: %v", ref, err)
		}
		if got.Digest != record.Digest {
			t.Fatalf("inspect %q digest = %q", ref, got.Digest)
		}
	}
	before, err := localStore.BlobCount()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := localStore.Put(artifact); err != nil {
		t.Fatal(err)
	}
	after, err := localStore.BlobCount()
	if err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Fatalf("blob count changed after duplicate pack: %d -> %d", before, after)
	}
}

func TestMaterializePreparesVendoredSDK(t *testing.T) {
	dir := testProject(t)
	writeFile(t, dir, "vendor/adversary-sdk/package.json", `{"name":"@adversary/sdk"}`)
	writeFile(t, dir, "vendor/adversary-sdk/dist/index.js", `export const DEFAULT_INPUT_PATH = "/adversary/input.json";
export const DEFAULT_OUTPUT_PATH = "/adversary/output.json";
export class Adversary {
  async run(options = {}) {
    const input = options.input ?? (await parseInput(options.inputPath));
    const repoPath = input.source.path;
  }
}
export async function parseInput(path = DEFAULT_INPUT_PATH) {}
export async function writeOutput(output, path = DEFAULT_OUTPUT_PATH) {}
`)
	artifact, err := pack.Create(context.Background(), pack.Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	localStore := Store{Root: t.TempDir()}
	t.Cleanup(func() { makeStoreWritable(localStore.Root) })
	record, err := localStore.Put(artifact)
	if err != nil {
		t.Fatal(err)
	}
	path, err := localStore.MaterializeRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "new"), []byte("x"), 0644); err == nil {
		t.Fatal("created file in sealed materialization")
	}
	if err := os.Remove(filepath.Join(path, "dist/index.js")); err == nil {
		t.Fatal("deleted file from sealed materialization")
	}
	if _, err := os.Stat(filepath.Join(path, "node_modules", "@adversary", "sdk", "package.json")); err != nil {
		t.Fatalf("expected materialized SDK node module: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(path, "node_modules", "@adversary", "sdk", "dist", "index.js"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, want := range []string{"process.env.ADVERSARY_INPUT", "process.env.ADVERSARY_OUTPUT", "process.env.ADVERSARY_REPO"} {
		if !strings.Contains(text, want) {
			t.Fatalf("patched SDK missing %s:\n%s", want, text)
		}
	}
}

func TestPutRejectsManifestMetadataMismatch(t *testing.T) {
	artifact, err := pack.Create(context.Background(), pack.Options{Dir: testProject(t)})
	if err != nil {
		t.Fatal(err)
	}
	artifact.ManifestName = "another/name"
	if _, err := (Store{Root: t.TempDir()}).Put(artifact); err == nil {
		t.Fatal("Put succeeded")
	}
}

func TestPutSeparatesAliasFromCanonicalManifestName(t *testing.T) {
	artifact, err := pack.Create(context.Background(), pack.Options{Dir: testProject(t), NameOverride: "ghcr.io/other/different-alias"})
	if err != nil {
		t.Fatal(err)
	}
	localStore := Store{Root: t.TempDir()}
	record, err := localStore.Put(artifact)
	if err != nil {
		t.Fatal(err)
	}
	if record.Name != "ghcr.io/other/different-alias" {
		t.Fatalf("record alias = %q", record.Name)
	}
	if record.ManifestName != "local/security-reviewer" {
		t.Fatalf("record manifest name = %q", record.ManifestName)
	}
	persisted, err := localStore.Inspect(record.Digest)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.ManifestName != record.ManifestName {
		t.Fatalf("persisted manifest name = %q", persisted.ManifestName)
	}
}

func TestPersistedAbsolutePathsAreNotTrusted(t *testing.T) {
	artifact, err := pack.Create(context.Background(), pack.Options{Dir: testProject(t)})
	if err != nil {
		t.Fatal(err)
	}
	s := Store{Root: t.TempDir()}
	record, err := s.Put(artifact)
	if err != nil {
		t.Fatal(err)
	}
	record.ManifestPath = filepath.Join(t.TempDir(), "attacker-manifest")
	record.ConfigPath = filepath.Join(t.TempDir(), "attacker-config")
	record.LayerPath = filepath.Join(t.TempDir(), "attacker-layer")
	if _, _, err := s.OCIPayload(record); err != nil {
		t.Fatalf("derived content paths failed: %v", err)
	}
}

func TestStoreRejectsUnsafeRefs(t *testing.T) {
	s := Store{Root: t.TempDir()}
	digest := oci.Digest(nil)
	for _, value := range []string{"../escape", "a//b", `C:\escape`, `\\server`} {
		if err := s.WriteRef(value, "latest", digest); err == nil {
			t.Fatalf("accepted ref %q", value)
		}
	}
}

func TestStoreRootRejectsEscapingRefSymlink(t *testing.T) {
	s := Store{Root: t.TempDir()}
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(s.Root, "refs-v2")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := s.WriteRef("safe/name", "latest", oci.Digest(nil)); err == nil {
		t.Fatal("wrote through escaping symlink")
	}
	entries, err := os.ReadDir(outside)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("outside files created: %v", entries)
	}
}

func TestPutRejectsSameBasenameDifferentCanonicalNamespace(t *testing.T) {
	artifact, err := pack.Create(context.Background(), pack.Options{Dir: testProject(t), NameOverride: "ghcr.io/other/security-reviewer"})
	if err != nil {
		t.Fatal(err)
	}
	artifact.ManifestName = "other/security-reviewer"
	if _, err := (Store{Root: t.TempDir()}).Put(artifact); err == nil {
		t.Fatal("Put succeeded")
	}
}

func TestPutAllowsDefaultTagForOptionalManifestVersion(t *testing.T) {
	dir := testProject(t)
	manifestPath := filepath.Join(dir, "adversary.yaml")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, []byte(strings.Replace(string(data), "version: 0.1.0\n", "", 1)), 0644); err != nil {
		t.Fatal(err)
	}
	artifact, err := pack.Create(context.Background(), pack.Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	record, err := (Store{Root: t.TempDir()}).Put(artifact)
	if err != nil {
		t.Fatal(err)
	}
	if record.Version != "latest" {
		t.Fatalf("record version = %q", record.Version)
	}
}

func TestMaterializeRejectsTamperedPreexistingManifest(t *testing.T) {
	artifact, err := pack.Create(context.Background(), pack.Options{Dir: testProject(t)})
	if err != nil {
		t.Fatal(err)
	}
	localStore := Store{Root: t.TempDir()}
	t.Cleanup(func() { makeStoreWritable(localStore.Root) })
	record, err := localStore.Put(artifact)
	if err != nil {
		t.Fatal(err)
	}
	path, err := localStore.MaterializeRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(path, "adversary.yaml")
	if info, err := os.Stat(manifestPath); err != nil || info.Mode().Perm()&0222 != 0 {
		t.Fatalf("materialized manifest is not read-only: %v mode=%v", err, info)
	}
	if err := os.Chmod(manifestPath, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, []byte("name: wrong/name\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := localStore.MaterializeRecord(record); err == nil {
		t.Fatal("MaterializeRecord accepted tampered manifest")
	}
}

func TestMaterializeExistingFastPathIsReadOnly(t *testing.T) {
	artifact, err := pack.Create(context.Background(), pack.Options{Dir: testProject(t)})
	if err != nil {
		t.Fatal(err)
	}
	s := Store{Root: t.TempDir()}
	record, err := s.Put(artifact)
	if err != nil {
		t.Fatal(err)
	}
	digestPath, _ := oci.DigestPath(record.Digest)
	record.Files = nil // This test isolates fast-path mutation behavior.
	destination := filepath.Join(s.Root, "artifacts", digestPath)
	writeFile(t, destination, "adversary.yaml", string(artifact.AdversaryManifest))
	writeFile(t, destination, "vendor/adversary-sdk/dist/index.js", "const repoPath = input.source.path;")
	before, _ := os.ReadFile(filepath.Join(destination, "vendor/adversary-sdk/dist/index.js"))
	if _, err := s.MaterializeRecord(record); err == nil {
		t.Fatal("accepted writable preexisting materialization")
	}
	after, _ := os.ReadFile(filepath.Join(destination, "vendor/adversary-sdk/dist/index.js"))
	if string(after) != string(before) {
		t.Fatal("existing materialization was patched")
	}
	if _, err := os.Stat(filepath.Join(destination, "node_modules")); !os.IsNotExist(err) {
		t.Fatal("existing materialization was mutated")
	}
}

func TestMaterializeRejectsEscapingDigestSymlink(t *testing.T) {
	artifact, err := pack.Create(context.Background(), pack.Options{Dir: testProject(t)})
	if err != nil {
		t.Fatal(err)
	}
	s := Store{Root: t.TempDir()}
	record, err := s.Put(artifact)
	if err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	sentinel := filepath.Join(outside, "adversary.yaml")
	if err := os.WriteFile(sentinel, []byte("outside"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(s.Root, "artifacts"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(s.Root, "artifacts", "sha256")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := s.MaterializeRecord(record); err == nil {
		t.Fatal("materialized through escaping symlink")
	}
	data, _ := os.ReadFile(sentinel)
	if string(data) != "outside" {
		t.Fatalf("outside file changed: %q", data)
	}
}

func TestMaterializeExtractionRejectsTraversal(t *testing.T) {
	artifact, err := pack.Create(context.Background(), pack.Options{Dir: testProject(t)})
	if err != nil {
		t.Fatal(err)
	}
	s := Store{Root: t.TempDir()}
	record, err := s.Put(artifact)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	data := []byte("escape")
	if err := tw.WriteHeader(&tar.Header{Name: "../escape", Mode: 0644, Size: int64(len(data))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	record.LayerDigest = oci.Digest(buf.Bytes())
	if err := s.writeContent("blobs", record.LayerDigest, buf.Bytes()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.MaterializeRecord(record); err == nil {
		t.Fatal("accepted traversal layer")
	}
	if _, err := os.Stat(filepath.Join(s.Root, "escape")); !os.IsNotExist(err) {
		t.Fatal("traversal wrote outside staging")
	}
}

func TestMaterializeRejectsStagePathSwap(t *testing.T) {
	artifact, err := pack.Create(context.Background(), pack.Options{Dir: testProject(t)})
	if err != nil {
		t.Fatal(err)
	}
	s := Store{Root: t.TempDir()}
	t.Cleanup(func() { makeStoreWritable(s.Root) })
	record, err := s.Put(artifact)
	if err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	sentinel := filepath.Join(outside, "sentinel")
	if err := os.WriteFile(sentinel, []byte("safe"), 0644); err != nil {
		t.Fatal(err)
	}
	beforeStoreMaterializePublish = func(_ *os.Root, stageRel string) {
		stagePath := filepath.Join(s.Root, filepath.FromSlash(stageRel))
		if err := os.Rename(stagePath, stagePath+".held"); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, stagePath); err != nil {
			t.Fatal(err)
		}
	}
	defer func() { beforeStoreMaterializePublish = nil }()
	if _, err := s.MaterializeRecord(record); err == nil {
		t.Fatal("accepted swapped staging pathname")
	}
	data, _ := os.ReadFile(sentinel)
	if string(data) != "safe" {
		t.Fatalf("outside changed: %q", data)
	}
	digestPath, _ := oci.DigestPath(record.Digest)
	if _, err := os.Lstat(filepath.Join(s.Root, "artifacts", digestPath)); !os.IsNotExist(err) {
		t.Fatalf("published entry remains: %v", err)
	}
}

func testProject(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, dir, "adversary.yaml", `name: local/security-reviewer
version: 0.1.0
runtime:
  name: node
  version: "22"
  command:
    - dist/index.js
`)
	writeFile(t, dir, "README.md", "# Security Reviewer\n")
	writeFile(t, dir, "dist/index.js", "console.log('ok')\n")
	return dir
}

func writeFile(t *testing.T, dir, rel, content string) {
	t.Helper()
	path := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func makeStoreWritable(root string) {
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err == nil {
			_ = os.Chmod(path, info.Mode().Perm()|0700)
		}
		return nil
	})
}

func readRef(t *testing.T, root, name, tag string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, "refs-v2", refNameKey(name), tag))
	if err != nil {
		t.Fatal(err)
	}
	return string(data[:len(data)-1])
}
