package repository

import (
	"errors"
	"io"
	"os"
	"testing"
	"time"

	"github.com/adversarylabs/adversary/internal/publock"
	"github.com/adversarylabs/adversary/pkg/blobsource"
)

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
