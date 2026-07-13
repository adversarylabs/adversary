package repository

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/adversarylabs/adversary/pkg/blobsource"
	"github.com/adversarylabs/adversary/pkg/oci"
)

func equivalentManifestFixture(t *testing.T) (Repository, Record, []byte) {
	t.Helper()
	a := artifact(t, "equivalent-manifest")
	layerData := artifactLayer(t, a)
	configSource := digestSource(t, a.Config, "sha512")
	layerSource := digestSource(t, layerData, "sha384")
	adversarySource := digestSource(t, a.AdversaryManifest, "sha512")
	manifest := a.OCIManifest
	manifest.Config.Digest, manifest.Config.Size = configSource.Digest(), configSource.Size()
	manifest.Layers[0].Digest, manifest.Layers[0].Size = layerSource.Digest(), layerSource.Size()
	manifestData, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifestSource := digestSource(t, manifestData, "sha512")
	configBlob, err := oci.NewSourceBlob(manifest.Config, configSource)
	if err != nil {
		t.Fatal(err)
	}
	layerBlob, err := oci.NewSourceBlob(manifest.Layers[0], layerSource)
	if err != nil {
		t.Fatal(err)
	}
	repo := Repository{Root: t.TempDir()}
	rec, err := repo.ImportSources(SourceImport{Reference: "registry.example/local/equivalent:v1", Name: a.ManifestName, Version: a.Version, Manifest: manifestSource, AdversaryManifest: adversarySource, Blobs: []oci.SourceBlob{configBlob, layerBlob}})
	if err != nil {
		t.Fatal(err)
	}
	return repo, rec, manifestData
}

func importIndependentEquivalent(t *testing.T, repo Repository, source Record, manifest, adversaryManifest []byte) Record {
	t.Helper()
	lease, err := repo.PayloadSources(source)
	if err != nil {
		t.Fatal(err)
	}
	copySource := func(source blobsource.Source) blobsource.Source {
		reader, err := source.Open()
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(reader)
		if closeErr := reader.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			t.Fatal(err)
		}
		copied, err := blobsource.New(source.Size(), source.Digest(), func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(data)), nil
		})
		if err != nil {
			t.Fatal(err)
		}
		return copied
	}
	blobs := make([]oci.SourceBlob, len(lease.Blobs))
	for i, blob := range lease.Blobs {
		blobs[i] = blob
		blobs[i].Source = copySource(blob.Source)
	}
	var attached blobsource.Source
	if lease.AdversaryManifest != nil {
		attached = copySource(lease.AdversaryManifest)
	}
	if adversaryManifest != nil {
		attached = blobsource.Bytes(adversaryManifest)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	rec, err := repo.ImportSources(SourceImport{
		Name: source.Name, Version: source.Version,
		Manifest: blobsource.Bytes(manifest),
		Blobs:    blobs, AdversaryManifest: attached,
	})
	if err != nil {
		t.Fatal(err)
	}
	return rec
}

func TestCommitEquivalentManifestReusesIndependentExistingTarget(t *testing.T) {
	repo, root, manifest := equivalentManifestFixture(t)
	target := importIndependentEquivalent(t, repo, root, manifest, nil)
	path := filepath.Join(repo.Root, "records", key(target.Digest)+".json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	got, err := repo.CommitEquivalentManifest(root.Digest, target.Digest, manifest)
	if err != nil {
		t.Fatal(err)
	}
	if got != target || got.CanonicalAliasDigest != "" {
		t.Fatalf("existing target rewritten: got=%#v want=%#v", got, target)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, before) {
		t.Fatal("existing target metadata changed")
	}
	want := root.Digest
	if target.Digest < want {
		want = target.Digest
	}
	for _, alias := range []string{root.Name, root.Name + ":" + root.Version} {
		if resolved, err := repo.Resolve(alias); err != nil || resolved.Digest != want {
			t.Fatalf("resolve %q=%#v err=%v want=%s", alias, resolved, err, want)
		}
	}
}

func TestEquivalentManifestWithDifferentAttachedManifestIsAmbiguous(t *testing.T) {
	repo, root, manifest := equivalentManifestFixture(t)
	different := []byte("name: local/test\nversion: 1.0.0\nruntime:\n  name: node\n  version: \"22\"\n  command: [alternate.js]\n")
	target := importIndependentEquivalent(t, repo, root, manifest, different)
	rootKey, err := repo.recordSemanticKey(root)
	if err != nil {
		t.Fatal(err)
	}
	targetKey, err := repo.recordSemanticKey(target)
	if err != nil {
		t.Fatal(err)
	}
	if rootKey == targetKey {
		t.Fatal("attached manifest identity omitted from semantic key")
	}
	for _, alias := range []string{root.Name, root.Name + ":" + root.Version} {
		if _, err := repo.Resolve(alias); !errors.Is(err, ErrAmbiguous) {
			t.Fatalf("resolve %q error=%v, want ErrAmbiguous", alias, err)
		}
	}
}

func TestCommitEquivalentManifestSameDigestAndCorruptLayer(t *testing.T) {
	repo, rec, manifest := equivalentManifestFixture(t)
	if got, err := repo.CommitEquivalentManifest(rec.Digest, rec.Digest, manifest); err != nil || got != rec {
		t.Fatalf("same digest=%#v err=%v", got, err)
	}
	layerPath := repo.content("blobs", rec.LayerDigest)
	if err := os.Chmod(layerPath, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(layerPath, []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	target := fmt.Sprintf("sha256:%x", sha256.Sum256(manifest))
	if _, err := repo.CommitEquivalentManifest(rec.Digest, target, manifest); err == nil {
		t.Fatal("corrupt retained layer accepted")
	}
}

func TestCommitEquivalentManifestRejectsOversizedInputBeforePersistence(t *testing.T) {
	repo, rec, _ := equivalentManifestFixture(t)
	target := fmt.Sprintf("sha256:%x", sha256.Sum256(make([]byte, (4<<20)+1)))
	if _, err := repo.CommitEquivalentManifest(rec.Digest, target, make([]byte, (4<<20)+1)); err == nil {
		t.Fatal("oversized manifest accepted")
	}
	if _, err := os.Stat(repo.content("manifests", target)); !os.IsNotExist(err) {
		t.Fatalf("target content persisted: %v", err)
	}
}

func TestCommitEquivalentManifestSerializesWithGCWithoutDeadlock(t *testing.T) {
	repo, rec, manifest := equivalentManifestFixture(t)
	plan, err := repo.PlanGC()
	if err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	gcStepHook = func(step string) error {
		if step == "preflight" {
			close(entered)
			<-release
		}
		return nil
	}
	t.Cleanup(func() { gcStepHook = nil })
	gcDone := make(chan error, 1)
	go func() { _, err := repo.ApplyGC(plan, false); gcDone <- err }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("GC did not reach lifecycle-locked preflight")
	}
	target := fmt.Sprintf("sha384:%x", sha512.Sum384(manifest))
	commitDone := make(chan error, 1)
	go func() { _, err := repo.CommitEquivalentManifest(rec.Digest, target, manifest); commitDone <- err }()
	select {
	case err := <-commitDone:
		t.Fatalf("commit bypassed lifecycle serialization: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for name, done := range map[string]<-chan error{"gc": gcDone, "commit": commitDone} {
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
		case <-ctx.Done():
			t.Fatalf("%s deadlocked", name)
		}
	}
	if got, err := repo.Resolve(target); err != nil || got.Digest != target {
		t.Fatalf("target=%#v err=%v", got, err)
	}
	opposite := make(chan error, 2)
	go func() { _, err := repo.CommitEquivalentManifest(rec.Digest, target, manifest); opposite <- err }()
	go func() { _, err := repo.CommitEquivalentManifest(target, rec.Digest, manifest); opposite <- err }()
	for i := 0; i < 2; i++ {
		select {
		case err := <-opposite:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("opposite canonicalizations deadlocked")
		}
	}
}

func TestEquivalentManifestChainAndRootGCFallback(t *testing.T) {
	repo, root, manifest := equivalentManifestFixture(t)
	b := fmt.Sprintf("sha256:%x", sha256.Sum256(manifest))
	c := fmt.Sprintf("sha384:%x", sha512.Sum384(manifest))
	bRec, err := repo.CommitEquivalentManifest(root.Digest, b, manifest)
	if err != nil {
		t.Fatal(err)
	}
	if bRec.CanonicalAliasDigest != root.Digest {
		t.Fatalf("equivalent b=%#v", bRec)
	}
	if err := repo.UpdateRef("registry.example/equivalent-b:v1", "", b); err != nil {
		t.Fatal(err)
	}
	if err := repo.DeleteRef("registry.example/local/equivalent:v1", root.Digest); err != nil {
		t.Fatal(err)
	}
	plan, err := repo.PlanGC()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.ApplyGC(plan, false); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Resolve(root.Digest); !os.IsNotExist(err) {
		t.Fatalf("root survived GC: %v", err)
	}
	cRec, err := repo.CommitEquivalentManifest(bRec.Digest, c, manifest)
	if err != nil {
		t.Fatal(err)
	}
	if cRec.Digest != c || cRec.CanonicalAliasDigest != root.Digest {
		t.Fatalf("post-GC algorithm identity=%#v", cRec)
	}
	if got, err := repo.Resolve(c); err != nil || got.Digest != c {
		t.Fatalf("post-GC digest=%#v err=%v", got, err)
	}
	want := b
	if c < want {
		want = c
	}
	for _, alias := range []string{root.Name, root.Name + ":" + root.Version} {
		if got, err := repo.Resolve(alias); err != nil || got.Digest != want {
			t.Fatalf("fallback %q=%#v err=%v want=%s", alias, got, err, want)
		}
	}
	recreated, err := repo.CommitEquivalentManifest(b, root.Digest, manifest)
	if err != nil {
		t.Fatal(err)
	}
	if recreated.Digest != root.Digest || recreated.CanonicalAliasDigest != "" {
		t.Fatalf("recreated root=%#v", recreated)
	}
	if got, err := repo.Resolve(root.Digest); err != nil || got.Digest != root.Digest {
		t.Fatalf("recreated digest=%#v err=%v", got, err)
	}
}

func TestEquivalentManifestTamperedMetadataRejected(t *testing.T) {
	repo, root, manifest := equivalentManifestFixture(t)
	target := fmt.Sprintf("sha256:%x", sha256.Sum256(manifest))
	rec, err := repo.CommitEquivalentManifest(root.Digest, target, manifest)
	if err != nil {
		t.Fatal(err)
	}
	rec.CanonicalAliasDigest = fmt.Sprintf("sha256:%x", sha256.Sum256([]byte("different")))
	data, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(repo.Root, "records", key(rec.Digest)+".json")
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Resolve(target); err == nil {
		t.Fatal("tampered equivalence metadata accepted")
	}
}
