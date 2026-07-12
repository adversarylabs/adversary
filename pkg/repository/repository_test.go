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
	"strings"
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
	if _, err := r.Resolve("test:1.0.0"); err != ErrAmbiguous {
		t.Fatalf("tagged alias err=%v", err)
	}
}

func TestConcurrentCrossRegistryTaggedAliasFailsClosed(t *testing.T) {
	r := Repository{Root: t.TempDir()}
	a, b := artifact(t, "one"), artifact(t, "two")
	start := make(chan struct{})
	errs := make(chan error, 2)
	for i, item := range []struct {
		artifact pack.Artifact
		ref      string
	}{{a, "one.example/team/test:1.0.0"}, {b, "two.example/team/test:1.0.0"}} {
		_ = i
		go func(item struct {
			artifact pack.Artifact
			ref      string
		}) {
			<-start
			_, err := r.ImportPacked(item.artifact, item.ref)
			errs <- err
		}(item)
	}
	close(start)
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	if _, err := (Repository{Root: r.Root}).Resolve("test:1.0.0"); !errors.Is(err, ErrAmbiguous) {
		t.Fatalf("tagged shorthand err=%v", err)
	}
	for _, ref := range []string{"one.example/team/test:1.0.0", "two.example/team/test:1.0.0"} {
		if _, err := r.Resolve(ref); err != nil {
			t.Fatalf("qualified %s: %v", ref, err)
		}
	}
}

func TestNameOnlyAliasAcrossVersionsFailsClosed(t *testing.T) {
	r := Repository{Root: t.TempDir()}
	a, b := artifact(t, "one"), artifact(t, "two")
	// The immutable configs carry 1.0.0, so use distinct refs with the same
	// name alias and distinct content to model versions already in old stores.
	if _, err := r.ImportPacked(a, "one.example/team/test:1.0.0"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.ImportPacked(b, "two.example/team/test:2.0.0"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Resolve("test"); !errors.Is(err, ErrAmbiguous) {
		t.Fatalf("name-only err=%v", err)
	}
}

func TestShorthandResolutionAndIdentityIgnoreRegistryEnvironment(t *testing.T) {
	r := Repository{Root: t.TempDir()}
	a := artifact(t, "one")
	rec, err := r.ImportPacked(a, "test:1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	want := "registry.adversarylabs.ai/library/test:1.0.0"
	if got, err := r.CanonicalReference(rec.Digest); err != nil || got != want {
		t.Fatalf("canonical=%q err=%v", got, err)
	}
	t.Setenv("ADVERSARY_REGISTRY_HOST", "poison.invalid")
	got, err := (Repository{Root: r.Root}).Resolve("test:1.0.0")
	if err != nil || got.Digest != rec.Digest {
		t.Fatalf("resolve=%#v err=%v", got, err)
	}
	if exact, err := r.HasExact("test:1.0.0"); err != nil || !exact {
		t.Fatalf("exact=%v err=%v", exact, err)
	}
}

func TestInjectedRegistryDefaultsArePersistedThenEnvironmentIndependent(t *testing.T) {
	r := Repository{Root: t.TempDir(), DefaultRegistry: "configured.example", DefaultNamespace: "tenant"}
	a := artifact(t, "one")
	rec, err := r.ImportPacked(a, "test:1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := r.CanonicalReferenceFor(rec.Digest, "test:1.0.0"); err != nil || got != "configured.example/tenant/test:1.0.0" {
		t.Fatalf("canonical=%q err=%v", got, err)
	}
	t.Setenv("ADVERSARY_REGISTRY_HOST", "poison.invalid")
	restarted := Repository{Root: r.Root, DefaultRegistry: "other.example", DefaultNamespace: "other"}
	got, err := restarted.Resolve("test:1.0.0")
	if err != nil || got.Digest != rec.Digest {
		t.Fatalf("restart resolve=%#v err=%v", got, err)
	}
}

func TestPreMigrationRepositoryUsesDurableRefFallback(t *testing.T) {
	r := Repository{Root: t.TempDir()}
	a := artifact(t, "one")
	rec, err := r.ImportPacked(a, "old.example/team/test:1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	// Older repositories have name aliases but no tagged alias entry.
	if err := os.Remove(filepath.Join(r.Root, "aliases", key("test:1.0.0")+".json")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ADVERSARY_REGISTRY_HOST", "poison.invalid")
	got, err := (Repository{Root: r.Root}).Resolve("test:1.0.0")
	if err != nil || got.Digest != rec.Digest {
		t.Fatalf("legacy fallback got=%#v err=%v", got, err)
	}
}

func TestInventoryIsVerifiedSortedAndCorruptionFails(t *testing.T) {
	r := Repository{Root: t.TempDir()}
	a := artifact(t, "one")
	rec, err := r.ImportPacked(a, "test:1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	files, err := (Repository{Root: r.Root}).Inventory(rec)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("missing packed inventory")
	}
	for i := 1; i < len(files); i++ {
		if files[i-1].Path >= files[i].Path {
			t.Fatalf("inventory not sorted: %#v", files)
		}
	}
	for _, file := range files {
		if file.Mode != 0644 && file.Mode != 0755 {
			t.Fatalf("inventory mode for %s=%#o", file.Path, file.Mode)
		}
	}
	if err := os.WriteFile(r.content("blobs", rec.ConfigDigest), []byte(`{"files":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Inventory(rec); err == nil {
		t.Fatal("corrupt config inventory accepted")
	}
}

func TestInventoryPreservesValidEmptyConfigInventory(t *testing.T) {
	r := Repository{Root: t.TempDir()}
	a := artifact(t, "one")
	var config map[string]any
	if err := json.Unmarshal(a.Config, &config); err != nil {
		t.Fatal(err)
	}
	config["files"] = []any{}
	configData, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	manifestData, manifestDigest, manifest, err := oci.NewManifest(configData, a.OCIManifest.Layers[0], a.OCIManifest.Annotations)
	if err != nil {
		t.Fatal(err)
	}
	a.Config, a.ConfigDigest = configData, oci.Digest(configData)
	a.Manifest, a.ManifestDigest, a.OCIManifest = manifestData, manifestDigest, manifest
	rec, err := r.ImportPacked(a, "test:1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	files, err := r.Inventory(rec)
	if err != nil {
		t.Fatal(err)
	}
	if files == nil || len(files) != 0 {
		t.Fatalf("empty inventory=%#v", files)
	}
}

func TestInventoryRejectsNonCanonicalDigestAndMode(t *testing.T) {
	for name, mutate := range map[string]func(map[string]any){
		"uppercase digest": func(file map[string]any) { file["sha256"] = strings.ToUpper(file["sha256"].(string)) },
		"arbitrary mode":   func(file map[string]any) { file["mode"] = float64(0600) },
	} {
		t.Run(name, func(t *testing.T) {
			r := Repository{Root: t.TempDir()}
			a := artifact(t, "one")
			var config map[string]any
			if err := json.Unmarshal(a.Config, &config); err != nil {
				t.Fatal(err)
			}
			files := config["files"].([]any)
			mutate(files[0].(map[string]any))
			configData, _ := json.Marshal(config)
			manifestData, manifestDigest, manifest, err := oci.NewManifest(configData, a.OCIManifest.Layers[0], a.OCIManifest.Annotations)
			if err != nil {
				t.Fatal(err)
			}
			a.Config, a.ConfigDigest = configData, oci.Digest(configData)
			a.Manifest, a.ManifestDigest, a.OCIManifest = manifestData, manifestDigest, manifest
			rec, err := r.ImportPacked(a, "test:1.0.0")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := r.Inventory(rec); err == nil {
				t.Fatalf("%s accepted", name)
			}
		})
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
	latest := "registry.example/local/test:latest"
	if err := r.UpdateRef(latest, "", a.ManifestDigest); err != nil {
		t.Fatal(err)
	}
	if err := r.UpdateRef(latest, a.ManifestDigest, b.ManifestDigest); err != nil {
		t.Fatal(err)
	}
	got, err = (Repository{Root: r.Root}).Resolve("test:latest")
	if err != nil || got.Digest != b.ManifestDigest {
		t.Fatalf("latest alias retained stale target: got=%#v err=%v", got, err)
	}
}

func TestConcurrentReferenceRetargetHasSingleCASWinner(t *testing.T) {
	r := Repository{Root: t.TempDir()}
	a, b, c := artifact(t, "one"), artifact(t, "two"), artifact(t, "three")
	aRec, err := r.ImportPacked(a, "one.example/team/test:1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	bRec, err := r.ImportPacked(b, "two.example/team/test:2.0.0")
	if err != nil {
		t.Fatal(err)
	}
	cRec, err := r.ImportPacked(c, "three.example/team/test:3.0.0")
	if err != nil {
		t.Fatal(err)
	}
	ref := "registry.example/team/test:latest"
	if err := r.UpdateRef(ref, "", aRec.Digest); err != nil {
		t.Fatal(err)
	}
	start, errs := make(chan struct{}), make(chan error, 2)
	for _, digest := range []string{bRec.Digest, cRec.Digest} {
		go func(digest string) { <-start; errs <- r.UpdateRef(ref, aRec.Digest, digest) }(digest)
	}
	close(start)
	first, second := <-errs, <-errs
	if (first == nil) == (second == nil) || (!errors.Is(first, ErrCAS) && !errors.Is(second, ErrCAS)) {
		t.Fatalf("concurrent results=%v, %v", first, second)
	}
	got, err := (Repository{Root: r.Root}).Resolve(ref)
	if err != nil || (got.Digest != bRec.Digest && got.Digest != cRec.Digest) {
		t.Fatalf("winner=%#v err=%v", got, err)
	}
}

func TestReferenceMutationCompensatesWhenAliasRebuildFails(t *testing.T) {
	for _, operation := range []string{"update", "delete"} {
		t.Run(operation, func(t *testing.T) {
			r := Repository{Root: t.TempDir()}
			aRec, err := r.ImportPacked(artifact(t, "one"), "one.example/team/test:1.0.0")
			if err != nil {
				t.Fatal(err)
			}
			bRec, err := r.ImportPacked(artifact(t, "two"), "two.example/team/test:2.0.0")
			if err != nil {
				t.Fatal(err)
			}
			latest := "registry.example/team/test:latest"
			if err := r.UpdateRef(latest, "", aRec.Digest); err != nil {
				t.Fatal(err)
			}
			bad := filepath.Join(r.Root, "aliases", "unexpected")
			if err := os.Symlink(t.TempDir(), bad); err != nil {
				t.Skip(err)
			}
			if operation == "update" {
				err = r.UpdateRef(latest, aRec.Digest, bRec.Digest)
			} else {
				err = r.DeleteRef(latest, aRec.Digest)
			}
			if err == nil {
				t.Fatal("mutation ignored rebuild failure")
			}
			got, err := r.Resolve(latest)
			if err != nil || got.Digest != aRec.Digest {
				t.Fatalf("compensation got=%#v err=%v", got, err)
			}
			if err := os.Remove(bad); err != nil {
				t.Fatal(err)
			}
			if err := (Repository{Root: r.Root}).Recover(); err != nil {
				t.Fatal(err)
			}
			got, err = r.Resolve(latest)
			if err != nil || got.Digest != aRec.Digest {
				t.Fatalf("restart compensation got=%#v err=%v", got, err)
			}
		})
	}
}

func TestReferenceMutationJournalRetainsAndRetriesFailedCompensation(t *testing.T) {
	for _, tc := range []struct{ name, previous, failStage string }{{"restore write", "old", "restore"}, {"restore remove", "", "restore"}, {"reconcile", "old", "reconcile"}} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() { refMutationHook = nil }()
			r := Repository{Root: t.TempDir()}
			oldRec, err := r.ImportPacked(artifact(t, "one"), "one.example/team/test:1.0.0")
			if err != nil {
				t.Fatal(err)
			}
			newRec, err := r.ImportPacked(artifact(t, "two"), "two.example/team/test:2.0.0")
			if err != nil {
				t.Fatal(err)
			}
			ref := "registry.example/team/test:latest"
			previous := ""
			if tc.previous != "" {
				previous = oldRec.Digest
			}
			encoded, _ := json.Marshal(struct{ Reference, Digest string }{ref, newRec.Digest})
			if err := r.atomic("refs/"+key(ref)+".json", encoded); err != nil {
				t.Fatal(err)
			}
			j := refMutationJournal{Version: 1, Reference: ref, Previous: previous, Next: newRec.Digest}
			if err := r.saveRefMutationJournal(j); err != nil {
				t.Fatal(err)
			}
			refMutationHook = func(stage string) error {
				if stage == tc.failStage {
					return errors.New("injected " + stage)
				}
				return nil
			}
			if err := r.Recover(); err == nil {
				t.Fatal("compensation failure ignored")
			}
			if _, err := os.Stat(filepath.Join(r.Root, refMutationJournalPath(ref))); err != nil {
				t.Fatalf("journal removed early: %v", err)
			}
			refMutationHook = nil
			if err := (Repository{Root: r.Root}).Recover(); err != nil {
				t.Fatal(err)
			}
			if previous == "" {
				if _, err := r.Resolve(ref); !os.IsNotExist(err) {
					t.Fatalf("new ref survived rollback: %v", err)
				}
			} else {
				got, err := r.Resolve(ref)
				if err != nil || got.Digest != previous {
					t.Fatalf("restored=%#v err=%v", got, err)
				}
			}
			if _, err := os.Stat(filepath.Join(r.Root, refMutationJournalPath(ref))); !os.IsNotExist(err) {
				t.Fatalf("journal remains: %v", err)
			}
		})
	}
}

func TestPendingReferenceMutationNeverExposesNextToReaders(t *testing.T) {
	defer func() { refMutationHook = nil }()
	r := Repository{Root: t.TempDir()}
	oldRec, err := r.ImportPacked(artifact(t, "one"), "one.example/team/test:1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	newRec, err := r.ImportPacked(artifact(t, "two"), "two.example/team/test:2.0.0")
	if err != nil {
		t.Fatal(err)
	}
	ref := "registry.example/team/test:latest"
	if err := r.UpdateRef(ref, "", oldRec.Digest); err != nil {
		t.Fatal(err)
	}
	reached, release := make(chan struct{}), make(chan struct{})
	refMutationHook = func(stage string) error {
		if stage == "after-write" {
			close(reached)
			<-release
		}
		return nil
	}
	done := make(chan error, 1)
	go func() { done <- r.UpdateRef(ref, oldRec.Digest, newRec.Digest) }()
	<-reached
	released := false
	defer func() {
		if !released {
			close(release)
		}
	}()
	got, err := r.Resolve(ref)
	if err != nil || got.Digest != oldRec.Digest {
		t.Fatalf("pending ref exposed next: got=%#v err=%v", got, err)
	}
	snapshot, err := r.referenceSnapshot()
	if err != nil || snapshot[ref] != oldRec.Digest {
		t.Fatalf("pending snapshot=%v err=%v", snapshot, err)
	}
	close(release)
	released = true
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	refMutationHook = nil
	got, err = r.Resolve(ref)
	if err != nil || got.Digest != newRec.Digest {
		t.Fatalf("committed ref=%#v err=%v", got, err)
	}
}

func TestReferenceRecoveryRejectsJournalThatNoLongerOwnsCurrentState(t *testing.T) {
	r := Repository{Root: t.TempDir()}
	oldRec, err := r.ImportPacked(artifact(t, "one"), "one.example/team/test:1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	newRec, err := r.ImportPacked(artifact(t, "two"), "two.example/team/test:2.0.0")
	if err != nil {
		t.Fatal(err)
	}
	otherRec, err := r.ImportPacked(artifact(t, "three"), "three.example/team/test:3.0.0")
	if err != nil {
		t.Fatal(err)
	}
	ref := "registry.example/team/test:latest"
	encoded, _ := json.Marshal(struct{ Reference, Digest string }{ref, otherRec.Digest})
	if err := r.atomic("refs/"+key(ref)+".json", encoded); err != nil {
		t.Fatal(err)
	}
	j := refMutationJournal{Version: 1, Reference: ref, Previous: oldRec.Digest, Next: newRec.Digest}
	if err := r.saveRefMutationJournal(j); err != nil {
		t.Fatal(err)
	}
	if err := r.Recover(); !errors.Is(err, ErrCAS) {
		t.Fatalf("ownership err=%v", err)
	}
	for name, check := range map[string]func() error{
		"qualified resolve": func() error { _, err := r.Resolve(ref); return err },
		"shorthand resolve": func() error { _, err := r.Resolve("test:latest"); return err },
		"canonical":         func() error { _, err := r.CanonicalReference(otherRec.Digest); return err },
		"entries":           func() error { _, err := r.Entries(100); return err },
		"check":             func() error { _, err := r.CheckAll(); return err },
	} {
		if err := check(); !errors.Is(err, ErrCAS) {
			t.Fatalf("%s overlay err=%v", name, err)
		}
	}
	if got, err := r.referenceDigestRaw(ref); err != nil || got != otherRec.Digest {
		t.Fatalf("foreign current=%q err=%v", got, err)
	}
	if _, err := os.Stat(filepath.Join(r.Root, refMutationJournalPath(ref))); err != nil {
		t.Fatalf("ownership journal removed: %v", err)
	}
}

func TestReferenceJournalRejectsNoncanonicalReferenceWithoutCreatingIndex(t *testing.T) {
	r := Repository{Root: t.TempDir()}
	rec, err := r.ImportPacked(artifact(t, "one"), "one.example/team/test:1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	j := refMutationJournal{Version: 1, Reference: "test:latest", Previous: rec.Digest, Delete: true}
	if err := r.saveRefMutationJournal(j); err != nil {
		t.Fatal(err)
	}
	if err := r.Recover(); err == nil {
		t.Fatal("noncanonical journal accepted")
	}
	if _, err := os.Stat(filepath.Join(r.Root, "refs", key("test:latest")+".json")); !os.IsNotExist(err) {
		t.Fatalf("noncanonical ref created: %v", err)
	}
	if _, err := os.Stat(filepath.Join(r.Root, refMutationJournalPath(j.Reference))); err != nil {
		t.Fatalf("forged journal removed: %v", err)
	}
}

func TestConflictingImportLeavesNoVisibleRecordOrAliasMutation(t *testing.T) {
	r := Repository{Root: t.TempDir()}
	a, b := artifact(t, "one"), artifact(t, "two")
	ref := "registry.example/team/test:1.0.0"
	if _, err := r.ImportPacked(a, ref); err != nil {
		t.Fatal(err)
	}
	beforeEntries, err := r.Entries(100)
	if err != nil {
		t.Fatal(err)
	}
	beforeCheck, err := r.CheckAll()
	if err != nil {
		t.Fatal(err)
	}
	beforeEntriesJSON, _ := json.Marshal(beforeEntries)
	beforeCheckJSON, _ := json.Marshal(beforeCheck)
	if _, err := r.ImportPacked(b, ref); !errors.Is(err, ErrCAS) {
		t.Fatalf("conflict err=%v", err)
	}
	if _, err := r.Resolve(b.ManifestDigest); !os.IsNotExist(err) {
		t.Fatalf("conflicting record visible: %v", err)
	}
	afterEntries, err := r.Entries(100)
	if err != nil {
		t.Fatal(err)
	}
	afterCheck, err := r.CheckAll()
	if err != nil {
		t.Fatal(err)
	}
	afterEntriesJSON, _ := json.Marshal(afterEntries)
	afterCheckJSON, _ := json.Marshal(afterCheck)
	if !bytes.Equal(beforeEntriesJSON, afterEntriesJSON) || !bytes.Equal(beforeCheckJSON, afterCheckJSON) {
		t.Fatalf("conflict mutated views\nbefore entries=%s\nafter entries=%s\nbefore check=%s\nafter check=%s", beforeEntriesJSON, afterEntriesJSON, beforeCheckJSON, afterCheckJSON)
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
	for _, step := range []string{"record", "commit", "reference", "aliases"} {
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

func TestInFlightImportMetadataIsInvisibleToReadViews(t *testing.T) {
	r := Repository{Root: t.TempDir()}
	a := artifact(t, "one")
	reached, release := make(chan struct{}), make(chan struct{})
	importStepHook = func(step string) error {
		if step == "record" {
			close(reached)
			<-release
		}
		return nil
	}
	done := make(chan error, 1)
	go func() { _, err := r.ImportPacked(a, "registry.example/team/test:1.0.0"); done <- err }()
	<-reached
	released := false
	defer func() {
		if !released {
			close(release)
		}
		importStepHook = nil
	}()
	if _, err := r.Resolve(a.ManifestDigest); !os.IsNotExist(err) {
		t.Fatalf("in-flight digest visible: %v", err)
	}
	entries, err := r.Entries(100)
	if err != nil || len(entries) != 0 {
		t.Fatalf("in-flight entries=%#v err=%v", entries, err)
	}
	check, err := r.CheckAll()
	if err != nil || len(check.Records) != 0 || len(check.References) != 0 {
		t.Fatalf("in-flight check=%#v err=%v", check, err)
	}
	close(release)
	released = true
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	importStepHook = nil
}

func TestRestartRecoveryRollsBackUnacknowledgedImportJournal(t *testing.T) {
	r := Repository{Root: t.TempDir()}
	a := artifact(t, "one")
	rec, err := r.ImportPacked(a, "registry.example/team/test:1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	j := importJournal{Version: 1, Digest: rec.Digest, Reference: "registry.example/team/test:1.0.0", CreatedRecord: true, CreatedCommit: true, CreatedReference: true}
	if err := r.saveImportJournal(j); err != nil {
		t.Fatal(err)
	}
	if err := (Repository{Root: r.Root}).Recover(); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Resolve(rec.Digest); !os.IsNotExist(err) {
		t.Fatalf("recovered digest visible: %v", err)
	}
	if _, err := r.Resolve("registry.example/team/test:1.0.0"); !os.IsNotExist(err) {
		t.Fatalf("recovered ref visible: %v", err)
	}
	if _, err := r.CheckAll(); err != nil {
		t.Fatal(err)
	}
}

func TestRecoveryRetainsJournalUntilCleanupAndAliasReconcileSucceed(t *testing.T) {
	for _, failure := range []string{"remove", "rebuild"} {
		t.Run(failure, func(t *testing.T) {
			defer func() { transactionRemoveHook, transactionRebuildHook = nil, nil }()
			r := Repository{Root: t.TempDir()}
			a := artifact(t, "one")
			rec, err := r.ImportPacked(a, "registry.example/team/test:1.0.0")
			if err != nil {
				t.Fatal(err)
			}
			j := importJournal{Version: 1, Digest: rec.Digest, Reference: "registry.example/team/test:1.0.0", CreatedRecord: true, CreatedCommit: true, CreatedReference: true}
			if err := r.saveImportJournal(j); err != nil {
				t.Fatal(err)
			}
			if failure == "remove" {
				transactionRemoveHook = func(rel string) error {
					if strings.HasPrefix(rel, "commits/") {
						return errors.New("injected remove")
					}
					return nil
				}
			} else {
				transactionRebuildHook = func() error { return errors.New("injected rebuild") }
			}
			if err := r.Recover(); err == nil {
				t.Fatal("recovery failure was ignored")
			}
			if _, err := os.Stat(filepath.Join(r.Root, importJournalPath(j.Digest, j.Reference))); err != nil {
				t.Fatalf("journal removed early: %v", err)
			}
			transactionRemoveHook, transactionRebuildHook = nil, nil
			if err := r.Recover(); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(filepath.Join(r.Root, importJournalPath(j.Digest, j.Reference))); !os.IsNotExist(err) {
				t.Fatalf("journal remains: %v", err)
			}
		})
	}
	transactionRemoveHook, transactionRebuildHook = nil, nil
}

func TestImportRollbackRetainsJournalWhenOwnedRemovalFails(t *testing.T) {
	r := Repository{Root: t.TempDir()}
	a := artifact(t, "one")
	defer func() { importStepHook, transactionRemoveHook = nil, nil }()
	importStepHook = func(step string) error {
		if step == "commit" {
			return errors.New("injected import")
		}
		return nil
	}
	transactionRemoveHook = func(rel string) error {
		if strings.HasPrefix(rel, "records/") {
			return errors.New("injected remove")
		}
		return nil
	}
	if _, err := r.ImportPacked(a, "registry.example/team/test:1.0.0"); err == nil {
		t.Fatal("rollback failure ignored")
	}
	entries, err := os.ReadDir(filepath.Join(r.Root, "transactions"))
	if err != nil || len(entries) != 1 {
		t.Fatalf("retained journals=%v err=%v", entries, err)
	}
	importStepHook, transactionRemoveHook = nil, nil
	if err := r.Recover(); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Resolve(a.ManifestDigest); !os.IsNotExist(err) {
		t.Fatalf("recovered import visible: %v", err)
	}
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
