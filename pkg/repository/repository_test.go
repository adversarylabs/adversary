package repository

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/adversarylabs/adversary/internal/rootreplace"
	"github.com/adversarylabs/adversary/pkg/blobsource"
	"github.com/adversarylabs/adversary/pkg/oci"
	"github.com/adversarylabs/adversary/pkg/pack"
)

func artifact(t *testing.T, content string) pack.Artifact {
	t.Helper()
	d := t.TempDir()
	write(t, d, "adversary.yaml", "name: local/test\nversion: 1.0.0\nruntime:\n  name: node\n  version: \"22\"\n  command: [dist/index.js]\n")
	write(t, d, "dist/index.js", content)
	a, err := pack.Create(context.Background(), pack.Options{Dir: d})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func artifactLayer(t *testing.T, a pack.Artifact) []byte {
	t.Helper()
	r, err := a.LayerSource.Open()
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(r)
	if closeErr := r.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatal(err)
	}
	return data
}
func write(t *testing.T, root, rel, data string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(data), 0644); err != nil {
		t.Fatal(err)
	}
}

func TestImportResolveVerifyMaterialize(t *testing.T) {
	r := Repository{Root: t.TempDir()}
	a := artifact(t, "one")
	rec, err := r.ImportPacked(a, "registry.example/local/test:1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if rec.Digest != a.ManifestDigest {
		t.Fatal("digest mismatch")
	}
	got, err := r.Resolve(rec.Digest)
	if err != nil || got != rec {
		t.Fatalf("resolve=%#v err=%v", got, err)
	}
	if v := r.Verify(rec); len(v.Missing)+len(v.Corrupt) != 0 {
		t.Fatalf("verify=%#v", v)
	}
	path, err := r.Materialize(rec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(path, "dist/index.js")); err != nil {
		t.Fatal(err)
	}
	if filepath.IsAbs(rec.ManifestDigest) || stringsContainAbs(rec) {
		t.Fatal("record contains absolute derived path")
	}
	makeWritable(path)
}
func stringsContainAbs(r Record) bool {
	return filepath.IsAbs(r.ManifestDigest) || filepath.IsAbs(r.ConfigDigest) || filepath.IsAbs(r.LayerDigest)
}

func TestAliasesBecomeAmbiguous(t *testing.T) {
	r := Repository{Root: t.TempDir()}
	a := artifact(t, "one")
	b := artifact(t, "two")
	if _, err := r.ImportPacked(a, "one.example/team/test:1.0.0"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.ImportPacked(b, "two.example/other/test:1.0.0"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Resolve("test"); err != ErrAmbiguous {
		t.Fatalf("err=%v", err)
	}
}

func TestCASAndConcurrentImports(t *testing.T) {
	r := Repository{Root: t.TempDir()}
	a := artifact(t, "one")
	b := artifact(t, "two")
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for _, x := range []pack.Artifact{a, b} {
		wg.Add(1)
		go func(x pack.Artifact) { defer wg.Done(); _, err := r.ImportPacked(x, ""); errs <- err }(x)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	ref := "registry.example/local/test:1.0.0"
	if err := r.UpdateRef(ref, "", a.ManifestDigest); err != nil {
		t.Fatal(err)
	}
	if err := r.UpdateRef(ref, "", b.ManifestDigest); err != ErrCAS {
		t.Fatalf("CAS err=%v", err)
	}
	if err := r.UpdateRef(ref, a.ManifestDigest, b.ManifestDigest); err != nil {
		t.Fatal(err)
	}
	got, err := r.Resolve(ref)
	if err != nil || got.Digest != b.ManifestDigest {
		t.Fatalf("resolve=%#v err=%v", got, err)
	}
}

func TestVerifyAndRepairCorruption(t *testing.T) {
	r := Repository{Root: t.TempDir()}
	a := artifact(t, "one")
	rec, err := r.ImportPacked(a, "")
	if err != nil {
		t.Fatal(err)
	}
	p := r.content("blobs", rec.LayerDigest)
	if err := os.WriteFile(p, []byte("bad"), 0600); err != nil {
		t.Fatal(err)
	}
	if v := r.Verify(rec); len(v.Corrupt) != 1 {
		t.Fatalf("verify=%#v", v)
	}
	if err := r.Repair(rec, map[string]blobsource.Source{rec.LayerDigest: blobsource.Bytes(artifactLayer(t, a))}); err != nil {
		t.Fatal(err)
	}
	if v := r.Verify(rec); len(v.Corrupt) != 0 {
		t.Fatalf("verify=%#v", v)
	}
}
func makeWritable(root string) {
	_ = filepath.Walk(root, func(p string, i os.FileInfo, e error) error {
		if e == nil {
			_ = os.Chmod(p, i.Mode().Perm()|0700)
		}
		return nil
	})
}

func TestPulledImportPreservesRawManifestIdentity(t *testing.T) {
	a := artifact(t, "one")
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, a.Manifest, "", "  "); err != nil {
		t.Fatal(err)
	}
	raw := pretty.Bytes()
	ref, _ := oci.ParseReference("registry.example/local/test:1.0.0")
	r := Repository{Root: t.TempDir()}
	blobs, err := a.Sources()
	if err != nil {
		t.Fatal(err)
	}
	rec, err := r.ImportSources(SourceImport{Reference: ref.Locator(), Name: a.ManifestName, Version: a.Version, Manifest: blobsource.Bytes(raw), AdversaryManifest: blobsource.Bytes(a.AdversaryManifest), Blobs: blobs})
	if err != nil {
		t.Fatal(err)
	}
	if rec.Digest != oci.Digest(raw) {
		t.Fatal("raw manifest digest was not retained")
	}
}

func TestForgedRecordFieldsAreIgnored(t *testing.T) {
	r := Repository{Root: t.TempDir()}
	a := artifact(t, "one")
	rec, err := r.ImportPacked(a, "")
	if err != nil {
		t.Fatal(err)
	}
	forged := rec
	forged.LayerDigest = oci.Digest([]byte("attacker"))
	forged.ConfigDigest = forged.LayerDigest
	if v := r.Verify(forged); len(v.Missing)+len(v.Corrupt) != 0 {
		t.Fatalf("forged fields influenced verification: %#v", v)
	}
	path, err := r.Materialize(forged)
	if err != nil {
		t.Fatal(err)
	}
	makeWritable(path)
}

func TestCheckpointAndReconcileResume(t *testing.T) {
	r := Repository{Root: t.TempDir()}
	a := artifact(t, "one")
	rec, err := r.ImportPacked(a, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := r.SaveCheckpoint("migration", Checkpoint{LastDigest: rec.Digest, Imported: 1}); err != nil {
		t.Fatal(err)
	}
	got, err := r.LoadCheckpoint("migration")
	if err != nil || got.Imported != 1 {
		t.Fatalf("checkpoint=%#v err=%v", got, err)
	}
	results, err := r.Reconcile("", 10)
	if err != nil || len(results) != 1 {
		t.Fatalf("results=%#v err=%v", results, err)
	}
}
func TestSymlinkedRepositoryAncestorFailsClosed(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	sentinel := filepath.Join(outside, "sentinel")
	write(t, outside, "sentinel", "safe")
	if err := os.Symlink(outside, filepath.Join(root, "records")); err != nil {
		t.Skip(err)
	}
	r := Repository{Root: root}
	if _, err := r.ImportPacked(artifact(t, "one"), ""); err == nil {
		t.Fatal("import followed symlinked records directory")
	}
	data, _ := os.ReadFile(sentinel)
	if string(data) != "safe" {
		t.Fatal("outside repository modified")
	}
}
func TestMalformedAliasFailsClosed(t *testing.T) {
	r := Repository{Root: t.TempDir()}
	if err := r.init(); err != nil {
		t.Fatal(err)
	}
	if err := r.atomic("aliases/"+key("test")+".json", []byte(`["sha256:bad","sha256:bad"]`)); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Resolve("test"); err == nil {
		t.Fatal("malformed alias accepted")
	}
}

func TestInterruptedImportIsInvisibleAndResumable(t *testing.T) {
	for _, step := range []string{"record", "reference", "aliases"} {
		t.Run(step, func(t *testing.T) {
			r := Repository{Root: t.TempDir()}
			a := artifact(t, "one")
			failed := false
			importStepHook = func(got string) error {
				if got == step && !failed {
					failed = true
					return errors.New("injected")
				}
				return nil
			}
			if _, err := r.ImportPacked(a, "registry.example/local/test:1.0.0"); err == nil {
				t.Fatal("injection did not fail")
			}
			if _, err := r.Resolve("registry.example/local/test:1.0.0"); err == nil {
				t.Fatal("incomplete import became visible")
			}
			importStepHook = nil
			if _, err := r.ImportPacked(a, "registry.example/local/test:1.0.0"); err != nil {
				t.Fatal(err)
			}
			if _, err := r.Resolve("registry.example/local/test:1.0.0"); err != nil {
				t.Fatal(err)
			}
		})
	}
	importStepHook = nil
}

func TestCanonicalLoadRejectsTamperedRecord(t *testing.T) {
	r := Repository{Root: t.TempDir()}
	a := artifact(t, "one")
	rec, err := r.ImportPacked(a, "")
	if err != nil {
		t.Fatal(err)
	}
	data, err := r.read("records/" + key(rec.Digest) + ".json")
	if err != nil {
		t.Fatal(err)
	}
	var forged Record
	if json.Unmarshal(data, &forged) != nil {
		t.Fatal("decode")
	}
	forged.Name = "attacker/name"
	bad, _ := json.Marshal(forged)
	if err := r.atomic("records/"+key(rec.Digest)+".json", bad); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Resolve(rec.Digest); err == nil {
		t.Fatal("tampered canonical record accepted")
	}
}

func TestEnumeratePagesExactlyOnce(t *testing.T) {
	r := Repository{Root: t.TempDir()}
	want := map[string]bool{}
	for i := 0; i < 11; i++ {
		a := artifact(t, fmt.Sprintf("content-%02d", (i*7)%11))
		rec, err := r.ImportPacked(a, "")
		if err != nil {
			t.Fatal(err)
		}
		want[rec.Digest] = true
	}
	seen := map[string]bool{}
	after := ""
	for {
		page, err := r.Enumerate(after, 3)
		if err != nil {
			t.Fatal(err)
		}
		if len(page) == 0 {
			break
		}
		for _, rec := range page {
			if rec.Digest <= after || seen[rec.Digest] {
				t.Fatalf("out of order/duplicate %s", rec.Digest)
			}
			seen[rec.Digest] = true
			after = rec.Digest
		}
	}
	if len(seen) != len(want) {
		t.Fatalf("seen=%d want=%d", len(seen), len(want))
	}
}

func TestEnumerateSkipsOrphansAndRejectsCommittedTamper(t *testing.T) {
	r := Repository{Root: t.TempDir()}
	a := artifact(t, "one")
	rec, err := r.ImportPacked(a, "")
	if err != nil {
		t.Fatal(err)
	}
	orphan := Record{Digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	data, _ := json.Marshal(orphan)
	if err := r.atomicImmutable("records/"+key(orphan.Digest)+".json", data); err != nil {
		t.Fatal(err)
	}
	page, err := r.Enumerate("", 10)
	if err != nil || len(page) != 1 {
		t.Fatalf("page=%#v err=%v", page, err)
	}
	stored, err := r.read("records/" + key(rec.Digest) + ".json")
	if err != nil {
		t.Fatal(err)
	}
	var bad Record
	_ = json.Unmarshal(stored, &bad)
	bad.Name = "tampered/name"
	tampered, _ := json.Marshal(bad)
	if err := r.atomic("records/"+key(rec.Digest)+".json", tampered); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Enumerate("", 10); err == nil {
		t.Fatal("committed tamper was skipped")
	}
}

func TestEnumerateRequiresBound(t *testing.T) {
	if _, err := (Repository{Root: t.TempDir()}).Enumerate("", 0); err == nil {
		t.Fatal("unbounded enumeration accepted")
	}
}

func TestInitSyncsRootBeforeImmutablePublish(t *testing.T) {
	r := Repository{Root: t.TempDir()}
	var order []string
	rootreplace.SyncHook = func(step string) error { order = append(order, step); return nil }
	defer func() { rootreplace.SyncHook = nil }()
	if _, err := r.ImportPacked(artifact(t, "one"), ""); err != nil {
		t.Fatal(err)
	}
	firstFile := -1
	for i, s := range order {
		if s == "file" {
			firstFile = i
			break
		}
	}
	if firstFile <= 0 {
		t.Fatalf("sync order=%v", order)
	}
	foundDirectory := false
	for _, s := range order[:firstFile] {
		if s == "directory" {
			foundDirectory = true
		}
	}
	if !foundDirectory {
		t.Fatalf("root directory was not synced before immutable publish: %v", order)
	}
}

func TestRepositoryRootMustBeProvisioned(t *testing.T) {
	root := filepath.Join(t.TempDir(), "missing")
	if _, err := (Repository{Root: root}).ImportPacked(artifact(t, "one"), ""); err == nil {
		t.Fatal("repository created an unprovisioned root")
	}
}

func TestPrepareDerivedSDKCopiesExactBytes(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := root.MkdirAll("vendor/adversary-sdk/dist", 0755); err != nil {
		t.Fatal(err)
	}
	pkg := []byte(`{"name":"@adversary/sdk","version":"0.1.0","type":"module","main":"./dist/index.js"}`)
	source := []byte("export const marker = 'exact';\n")
	if err := root.WriteFile("vendor/adversary-sdk/package.json", pkg, 0644); err != nil {
		t.Fatal(err)
	}
	if err := root.WriteFile("vendor/adversary-sdk/dist/index.js", source, 0755); err != nil {
		t.Fatal(err)
	}
	if err := prepareDerivedSDK(root); err != nil {
		t.Fatal(err)
	}
	derived, err := root.ReadFile("node_modules/@adversary/sdk/dist/index.js")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(source, derived) {
		t.Fatal("derived SDK bytes differ from verified source")
	}
	derivedPackage, err := root.ReadFile("node_modules/@adversary/sdk/package.json")
	if err != nil || !bytes.Equal(pkg, derivedPackage) {
		t.Fatalf("derived package mismatch err=%v", err)
	}
	sourceAfter, _ := root.ReadFile("vendor/adversary-sdk/dist/index.js")
	if !bytes.Equal(source, sourceAfter) {
		t.Fatal("source SDK changed")
	}
	sourceInfo, _ := root.Stat("vendor/adversary-sdk/dist/index.js")
	derivedInfo, _ := root.Stat("node_modules/@adversary/sdk/dist/index.js")
	packageInfo, _ := root.Stat("node_modules/@adversary/sdk/package.json")
	if sourceInfo.Mode().Perm() != 0755 || derivedInfo.Mode().Perm() != 0555 || packageInfo.Mode().Perm() != 0444 {
		t.Fatalf("modes source=%o derived=%o package=%o", sourceInfo.Mode().Perm(), derivedInfo.Mode().Perm(), packageInfo.Mode().Perm())
	}
}
func TestPrepareDerivedSDKRejectsMalformedPackage(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	_ = root.MkdirAll("vendor/adversary-sdk", 0755)
	_ = root.WriteFile("vendor/adversary-sdk/package.json", []byte(`{"name":"attacker/sdk"}`), 0644)
	if err := prepareDerivedSDK(root); err == nil {
		t.Fatal("malformed SDK accepted")
	}
}
func TestPrepareDerivedSDKPropagatesStatErrors(t *testing.T) {
	dir := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(dir, "vendor")); err != nil {
		t.Skip(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := prepareDerivedSDK(root); err == nil {
		t.Fatal("SDK stat error treated as missing")
	}
}
