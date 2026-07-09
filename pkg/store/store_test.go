package store

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
	record, err := localStore.Put(artifact)
	if err != nil {
		t.Fatal(err)
	}
	path, err := localStore.MaterializeRecord(record)
	if err != nil {
		t.Fatal(err)
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

func readRef(t *testing.T, root, name, tag string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, "refs", name, tag))
	if err != nil {
		t.Fatal(err)
	}
	return string(data[:len(data)-1])
}
