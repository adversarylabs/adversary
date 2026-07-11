package repository

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/adversarylabs/adversary/internal/publock"
	"github.com/adversarylabs/adversary/pkg/blobsource"
)

func TestRepairRejectsInvalidSourceBeforePublicationAndCleansTemporaryFiles(t *testing.T) {
	r := Repository{Root: t.TempDir()}
	a := artifact(t, "repair-source")
	rec, err := r.ImportPacked(a, "repair-source:1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	layer := artifactLayer(t, a)
	if err := os.WriteFile(r.content("blobs", rec.LayerDigest), []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	opened := false
	oversized, err := blobsource.New(int64(len(layer))+1, rec.LayerDigest, func() (io.ReadCloser, error) {
		opened = true
		return io.NopCloser(bytes.NewReader(append(layer, 0))), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Repair(rec, map[string]blobsource.Source{rec.LayerDigest: oversized}); err == nil {
		t.Fatal("oversized repair source accepted")
	}
	if opened {
		t.Fatal("oversized source opened before descriptor validation")
	}
	assertNoRepairTemps(t, r.Root)

	wrong := bytes.Repeat([]byte("x"), len(layer))
	mismatch, err := blobsource.New(int64(len(wrong)), rec.LayerDigest, func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(wrong)), nil })
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Repair(rec, map[string]blobsource.Source{rec.LayerDigest: mismatch}); err == nil {
		t.Fatal("digest-mismatched repair source accepted")
	}
	assertNoRepairTemps(t, r.Root)
	if got, err := os.ReadFile(r.content("blobs", rec.LayerDigest)); err != nil || string(got) != "corrupt" {
		t.Fatalf("corrupt target was published over: %q %v", got, err)
	}
}

func TestRepairRestoresMissingOrCorruptManifestFirst(t *testing.T) {
	for _, missing := range []bool{true, false} {
		t.Run(map[bool]string{true: "missing", false: "corrupt"}[missing], func(t *testing.T) {
			r := Repository{Root: t.TempDir()}
			a := artifact(t, "manifest-repair")
			rec, err := r.ImportPacked(a, "manifest-repair:1.0.0")
			if err != nil {
				t.Fatal(err)
			}
			path := r.content("manifests", rec.ManifestDigest)
			if missing {
				err = os.Remove(path)
			} else {
				err = os.WriteFile(path, []byte("corrupt"), 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := r.Repair(rec, map[string]blobsource.Source{rec.ManifestDigest: blobsource.Bytes(a.Manifest)}); err != nil {
				t.Fatal(err)
			}
			if result := r.Verify(rec); len(result.Missing)+len(result.Corrupt) != 0 {
				t.Fatalf("verify after repair: %#v", result)
			}
		})
	}
}

func TestRepairAllRestoresManifestBeforeDamagedBlob(t *testing.T) {
	r := Repository{Root: t.TempDir()}
	a := artifact(t, "manifest-and-layer-repair")
	rec, err := r.ImportPacked(a, "manifest-and-layer-repair:1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	layer := artifactLayer(t, a)
	if err := os.WriteFile(r.content("manifests", rec.ManifestDigest), []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(r.content("blobs", rec.LayerDigest), []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	report, err := r.RepairAll(map[string]blobsource.Source{
		rec.ManifestDigest: blobsource.Bytes(a.Manifest),
		rec.LayerDigest:    blobsource.Bytes(layer),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Repaired) != 1 || report.Repaired[0] != rec.Digest || len(report.Unresolved) != 0 {
		t.Fatalf("repair report: %#v", report)
	}
	if result := r.Verify(rec); len(result.Missing)+len(result.Corrupt) != 0 {
		t.Fatalf("verify after repair all: %#v", result)
	}
}

func TestRepairHoldsLifecycleLockAgainstGC(t *testing.T) {
	r := Repository{Root: t.TempDir()}
	ref := "repair-gc:1.0.0"
	a := artifact(t, "repair-gc")
	rec, err := r.ImportPacked(a, ref)
	if err != nil {
		t.Fatal(err)
	}
	layer := artifactLayer(t, a)
	if err := r.DeleteRef(ref, rec.Digest); err != nil {
		t.Fatal(err)
	}
	plan, err := r.PlanGC()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(r.content("blobs", rec.LayerDigest), []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	opened, release := make(chan struct{}), make(chan struct{})
	source, err := blobsource.New(int64(len(layer)), rec.LayerDigest, func() (io.ReadCloser, error) {
		close(opened)
		<-release
		return io.NopCloser(bytes.NewReader(layer)), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	repaired := make(chan error, 1)
	go func() { repaired <- r.Repair(rec, map[string]blobsource.Source{rec.LayerDigest: source}) }()
	select {
	case <-opened:
	case <-time.After(3 * time.Second):
		t.Fatal("repair did not open source")
	}
	gcDone := make(chan error, 1)
	go func() { _, err := r.ApplyGC(plan, false); gcDone <- err }()
	select {
	case err := <-gcDone:
		t.Fatalf("GC bypassed repair lifecycle lock: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	if err := <-repaired; err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-gcDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("GC remained blocked")
	}
	if _, err := os.Stat(r.content("blobs", rec.LayerDigest)); !os.IsNotExist(err) {
		t.Fatalf("GC left orphan repaired layer: %v", err)
	}
}

func assertNoRepairTemps(t *testing.T, root string) {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(root, "*", ".repair-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("repair temporary files remain: %v", matches)
	}
}

func TestPayloadSourcesAreFileBackedAndRepeatable(t *testing.T) {
	r := Repository{Root: t.TempDir()}
	a := artifact(t, "source content")
	rec, err := r.ImportPacked(a, "")
	if err != nil {
		t.Fatal(err)
	}
	sources, err := r.PayloadSources(rec)
	if err != nil {
		t.Fatal(err)
	}
	defer sources.Close()
	if len(sources.Blobs) != 2 {
		t.Fatalf("blob count %d", len(sources.Blobs))
	}
	for _, source := range []blobsource.Source{sources.Manifest, sources.Blobs[0].Source, sources.Blobs[1].Source, sources.AdversaryManifest} {
		if source == nil {
			t.Fatal("missing content source")
		}
		if err := blobsource.Verify(source); err != nil {
			t.Fatal(err)
		}
		first, err := source.Open()
		if err != nil {
			t.Fatal(err)
		}
		prefix := make([]byte, 1)
		_, _ = first.Read(prefix)
		second, err := source.Open()
		if err != nil {
			t.Fatal(err)
		}
		all, readErr := io.ReadAll(second)
		if closeErr := second.Close(); readErr != nil || closeErr != nil {
			t.Fatalf("read=%v close=%v", readErr, closeErr)
		}
		if err := first.Close(); err != nil {
			t.Fatal(err)
		}
		if int64(len(all)) != source.Size() {
			t.Fatalf("size %d != %d", len(all), source.Size())
		}
	}
}

func TestPayloadSourcesDetectContentReplacementOnVerification(t *testing.T) {
	r := Repository{Root: t.TempDir()}
	rec, err := r.ImportPacked(artifact(t, "one"), "")
	if err != nil {
		t.Fatal(err)
	}
	sources, err := r.PayloadSources(rec)
	if err != nil {
		t.Fatal(err)
	}
	defer sources.Close()
	if err := os.WriteFile(r.content("blobs", rec.LayerDigest), []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := blobsource.Verify(sources.Blobs[1].Source); err == nil {
		t.Fatal("expected verification failure")
	}
}

func TestPayloadLeaseBlocksGCAndRejectsOpenAfterClose(t *testing.T) {
	r := Repository{Root: t.TempDir()}
	rec, err := r.ImportPacked(artifact(t, "leased"), "")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := r.PlanGC()
	if err != nil {
		t.Fatal(err)
	}
	lease, err := r.PayloadSources(rec)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := lease.Blobs[1].Source.Open()
	if err != nil {
		t.Fatal(err)
	}
	if err := lease.Close(); !errors.Is(err, blobsource.ErrActiveReaders) {
		t.Fatalf("close with reader = %v", err)
	}
	if _, err := lease.Manifest.Open(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("open after close request = %v", err)
	}
	done := make(chan error, 1)
	go func() { _, err := r.ApplyGC(plan, false); done <- err }()
	select {
	case err := <-done:
		t.Fatalf("GC did not block: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("GC remained blocked after lease close")
	}
}

func TestPayloadSourcesConstructionErrorReleasesLifecycleLock(t *testing.T) {
	r := Repository{Root: t.TempDir()}
	rec, err := r.ImportPacked(artifact(t, "broken"), "")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(r.content("blobs", rec.LayerDigest)); err != nil {
		t.Fatal(err)
	}
	if _, err := r.PayloadSources(rec); err == nil {
		t.Fatal("expected missing layer error")
	}
	done := make(chan error, 1)
	go func() {
		lifecycle, err := publock.Acquire(r.Root, "repo-lifecycle")
		if err == nil {
			digest, digestErr := publock.Acquire(r.Root, "repo-digest\x00"+rec.Digest)
			if digestErr == nil {
				digestErr = digest.Close()
			}
			err = errors.Join(digestErr, lifecycle.Close())
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("construction error leaked lifecycle lock")
	}
}
