package repository

import (
	"bytes"
	"context"
	"crypto/rand"
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

func TestImportPackedStreamsOwnedLayerIntoRepository(t *testing.T) {
	dir := t.TempDir()
	manifest := "name: team/streaming\nversion: 1.0.0\nruntime:\n  name: node\n  version: '22'\n  command: [index.js]\n"
	if err := os.WriteFile(filepath.Join(dir, "adversary.yaml"), []byte(manifest), 0600); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 12<<20)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "payload.bin"), data, 0600); err != nil {
		t.Fatal(err)
	}
	a, err := pack.Create(context.Background(), pack.Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	root := filepath.Join(t.TempDir(), "repo")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	r := Repository{Root: root}
	rec, err := r.ImportPacked(a, "streaming:1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	lease, err := r.PayloadSources(rec)
	if err != nil {
		t.Fatal(err)
	}
	if err := blobsource.Verify(lease.Blobs[1].Source); err != nil {
		t.Fatal(err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestImportSourcesRejectsCoherentBlobThatConflictsWithManifest(t *testing.T) {
	a, in := sourceFixture(t)
	defer a.Close()
	r, err := in.Blobs[1].Source.Open()
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
	data = data[:len(data)-1]
	descriptor := in.Blobs[1].Descriptor
	descriptor.Size = int64(len(data))
	descriptor.Digest = oci.Digest(data)
	in.Blobs[1], err = oci.NewSourceBlob(descriptor, blobsource.Bytes(data))
	if err != nil {
		t.Fatal(err)
	}
	repo := newSourceRepository(t)
	if _, err := repo.ImportSources(in); err == nil || !strings.Contains(err.Error(), "descriptors conflict") {
		t.Fatalf("expected manifest descriptor conflict, got %v", err)
	}
}

func TestImportSourcesBoundsChangedLayerAtDeclaredSize(t *testing.T) {
	a, in := sourceFixture(t)
	defer a.Close()
	original := in.Blobs[1].Source
	var read int64
	changed, err := blobsource.New(original.Size(), original.Digest(), func() (io.ReadCloser, error) {
		r, err := original.Open()
		if err != nil {
			return nil, err
		}
		return &countedExtraReader{Reader: io.MultiReader(r, bytes.NewReader([]byte("extra"))), close: r, read: &read}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	in.Blobs[1].Source = changed
	repo := newSourceRepository(t)
	if _, err := repo.ImportSources(in); err == nil || !strings.Contains(err.Error(), "exceeds declared size") {
		t.Fatalf("expected overflow, got %v", err)
	}
	if read > original.Size()+1 {
		t.Fatalf("read %d bytes, want at most declared size+1", read)
	}
	if _, err := os.Stat(filepath.Join(repo.Root, "blobs", key(original.Digest()))); !os.IsNotExist(err) {
		t.Fatalf("overflowing source published: %v", err)
	}
}

func TestPutSourceUsesRootedDurableImmutablePublication(t *testing.T) {
	repo := newSourceRepository(t)
	src := blobsource.Bytes([]byte("content"))
	injected := errors.New("sync failed")
	rootreplace.SyncHook = func(step string) error {
		if step == "file" {
			return injected
		}
		return nil
	}
	defer func() { rootreplace.SyncHook = nil }()
	if err := repo.putSource("blobs", src); !errors.Is(err, injected) {
		t.Fatalf("expected sync failure, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(repo.Root, "blobs", key(src.Digest()))); !os.IsNotExist(err) {
		t.Fatalf("published after sync failure: %v", err)
	}
	rootreplace.SyncHook = nil
	external := t.TempDir()
	if err := os.Remove(filepath.Join(repo.Root, "blobs")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, filepath.Join(repo.Root, "blobs")); err != nil {
		t.Fatal(err)
	}
	if err := repo.putSource("blobs", src); err == nil {
		t.Fatal("expected rooted symlink rejection")
	}
	entries, err := os.ReadDir(external)
	if err != nil || len(entries) != 0 {
		t.Fatalf("wrote through symlink: entries=%v err=%v", entries, err)
	}
}

func TestPutSourcePreservesPostLinkDirectorySyncFailure(t *testing.T) {
	repo := newSourceRepository(t)
	if err := repo.init(); err != nil {
		t.Fatal(err)
	}
	src := blobsource.Bytes([]byte("durable content"))
	injected := errors.New("directory sync failed")
	fileSynced := false
	rootreplace.SyncHook = func(step string) error {
		if step == "file" {
			fileSynced = true
		}
		if step == "directory" && fileSynced {
			return injected
		}
		return nil
	}
	defer func() { rootreplace.SyncHook = nil }()
	if err := repo.putSource("blobs", src); !errors.Is(err, injected) {
		t.Fatalf("post-link sync failure masked: %v", err)
	}
	f, err := os.Open(filepath.Join(repo.Root, "blobs", key(src.Digest())))
	if err != nil {
		t.Fatalf("linked artifact missing after sync failure: %v", err)
	}
	verifyErr := verifyReader(f, src)
	closeErr := f.Close()
	if err := errors.Join(verifyErr, closeErr); err != nil {
		t.Fatal(err)
	}
	rootreplace.SyncHook = nil
	if err := repo.putSource("blobs", src); err != nil {
		t.Fatalf("clean retry did not accept verified artifact: %v", err)
	}
}

func TestPutSourceConcurrentWritersShareImmutableContent(t *testing.T) {
	repo := newSourceRepository(t)
	src := blobsource.Bytes(bytes.Repeat([]byte("x"), 2<<20))
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); errs <- repo.putSource("blobs", src) }()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	f, err := os.Open(filepath.Join(repo.Root, "blobs", key(src.Digest())))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := verifyReader(f, src); err != nil {
		t.Fatal(err)
	}
}

func TestCopyExactStopsReaderWithNoProgress(t *testing.T) {
	if _, _, err := copyExact(io.Discard, noProgressReader{}, 1); !errors.Is(err, io.ErrNoProgress) {
		t.Fatalf("expected no-progress error, got %v", err)
	}
}

func TestCopyExactRejectsInvalidReaderCounts(t *testing.T) {
	for _, count := range []int{-1, 2} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			if _, _, err := copyExact(io.Discard, invalidCountReader{count: count}, 1); err == nil || !strings.Contains(err.Error(), "invalid byte count") {
				t.Fatalf("count %d: %v", count, err)
			}
		})
	}
}

func TestReadSourceLimitedRejectsDeclaredSizeBeforeOpen(t *testing.T) {
	opened := false
	src, err := blobsource.New((4<<20)+1, oci.Digest(nil), func() (io.ReadCloser, error) { opened = true; return io.NopCloser(bytes.NewReader(nil)), nil })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := readSourceLimited(src, 4<<20); err == nil {
		t.Fatal("expected ceiling rejection")
	}
	if opened {
		t.Fatal("oversized source was opened")
	}
}

type noProgressReader struct{}

func (noProgressReader) Read([]byte) (int, error) { return 0, nil }

type invalidCountReader struct{ count int }

func (r invalidCountReader) Read([]byte) (int, error) { return r.count, nil }

type countedExtraReader struct {
	io.Reader
	close io.Closer
	read  *int64
}

func (r *countedExtraReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	*r.read += int64(n)
	return n, err
}
func (r *countedExtraReader) Close() error { return r.close.Close() }

func sourceFixture(t *testing.T) (pack.Artifact, SourceImport) {
	t.Helper()
	dir := t.TempDir()
	manifest := "name: team/source\nversion: 1.0.0\nruntime:\n  name: node\n  version: '22'\n  command: [index.js]\n"
	if err := os.WriteFile(filepath.Join(dir, "adversary.yaml"), []byte(manifest), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "index.js"), []byte("console.log('x')"), 0600); err != nil {
		t.Fatal(err)
	}
	a, err := pack.Create(context.Background(), pack.Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	blobs, err := a.Sources()
	if err != nil {
		a.Close()
		t.Fatal(err)
	}
	return a, SourceImport{Reference: "source:1.0.0", Name: a.ManifestName, Version: a.Version, Manifest: blobsource.Bytes(a.Manifest), AdversaryManifest: blobsource.Bytes(a.AdversaryManifest), Blobs: blobs}
}

func newSourceRepository(t *testing.T) Repository {
	t.Helper()
	root := filepath.Join(t.TempDir(), "repo")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	return Repository{Root: root}
}
