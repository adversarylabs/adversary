package repository

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/adversarylabs/adversary/internal/publock"
	"github.com/adversarylabs/adversary/pkg/blobsource"
	"github.com/adversarylabs/adversary/pkg/oci"
)

// ContentSources contains immutable repository content. The repository owns
// the files; callers own and must close each reader returned by Open. Sources
// remain valid until the corresponding record is removed by repository GC.
type ContentSources struct {
	Manifest          blobsource.Source
	Blobs             []oci.SourceBlob
	AdversaryManifest blobsource.Source
}

// PayloadLease holds a cross-process record lock against repository GC. Close
// every opened reader before closing the lease. Close with active readers
// returns blobsource.ErrActiveReaders and retains the lock for a later retry.
type PayloadLease struct {
	ContentSources
	mu       sync.Mutex
	lock     *publock.Lock
	closing  bool
	closed   bool
	active   int
	closeErr error
}

// PayloadSources is the bounded-memory counterpart to Payload. It validates
// the committed record but does not read blob bodies into memory.
func (r Repository) PayloadSources(rec Record) (*PayloadLease, error) {
	lifecycle, err := publock.Acquire(r.Root, "repo-lifecycle")
	if err != nil {
		return nil, err
	}
	lock, err := publock.Acquire(r.Root, "repo-digest\x00"+rec.Digest)
	if err != nil {
		return nil, errors.Join(err, lifecycle.Close())
	}
	if err := lifecycle.Close(); err != nil {
		return nil, errors.Join(err, lock.Close())
	}
	fail := func(err error) (*PayloadLease, error) {
		return nil, errors.Join(err, lock.Close())
	}
	canonical, err := r.record(rec.Digest)
	if err != nil {
		return fail(err)
	}
	canonicalManifest, err := r.validateStoredArtifactLayer(canonical)
	if err != nil {
		return fail(fmt.Errorf("artifact semantic validation failed: %w", err))
	}
	manifest, err := r.contentSource("manifests", canonical.ManifestDigest)
	if err != nil {
		return fail(err)
	}
	config, err := r.contentSource("blobs", canonical.ConfigDigest)
	if err != nil {
		return fail(err)
	}
	layer, err := r.contentSource("blobs", canonical.LayerDigest)
	if err != nil {
		return fail(err)
	}
	configBlob, err := oci.NewSourceBlob(oci.Descriptor{MediaType: oci.EmptyConfigMediaType, Digest: canonical.ConfigDigest, Size: config.Size()}, config)
	if err != nil {
		return fail(err)
	}
	layerBlob, err := oci.NewSourceBlob(oci.Descriptor{MediaType: oci.PackageLayerMediaType, Digest: canonical.LayerDigest, Size: layer.Size()}, layer)
	if err != nil {
		return fail(err)
	}
	lease := &PayloadLease{lock: lock}
	lease.Manifest = lease.wrap(manifest)
	configBlob.Source = lease.wrap(configBlob.Source)
	layerBlob.Source = lease.wrap(layerBlob.Source)
	lease.Blobs = []oci.SourceBlob{configBlob, layerBlob}
	if canonical.AdversaryManifestDigest != "" {
		adversaryManifest, sourceErr := r.contentSource("adversary-manifests", canonical.AdversaryManifestDigest)
		if sourceErr != nil {
			return fail(sourceErr)
		}
		lease.AdversaryManifest = lease.wrap(adversaryManifest)
	} else {
		lease.AdversaryManifest = lease.wrap(blobsource.Bytes(canonicalManifest))
	}
	return lease, nil
}

func (l *PayloadLease) wrap(source blobsource.Source) blobsource.Source {
	return leaseSource{Source: source, lease: l}
}

type leaseSource struct {
	blobsource.Source
	lease *PayloadLease
}

func (s leaseSource) Open() (io.ReadCloser, error) { return s.lease.open(s.Source) }

func (l *PayloadLease) open(source blobsource.Source) (io.ReadCloser, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closing || l.closed {
		return nil, os.ErrClosed
	}
	reader, err := source.Open()
	if err != nil {
		return nil, err
	}
	l.active++
	return &leaseReader{ReadCloser: reader, release: func() {
		l.mu.Lock()
		l.active--
		l.mu.Unlock()
	}}, nil
}

func (l *PayloadLease) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return l.closeErr
	}
	l.closing = true
	if l.active != 0 {
		return blobsource.ErrActiveReaders
	}
	l.closeErr = l.lock.Close()
	l.closed = true
	return l.closeErr
}

type leaseReader struct {
	io.ReadCloser
	once    sync.Once
	release func()
}

func (r *leaseReader) Close() error { err := r.ReadCloser.Close(); r.once.Do(r.release); return err }

func (r Repository) contentSource(kind, digest string) (blobsource.Source, error) {
	rel := filepath.ToSlash(filepath.Join(kind, key(digest)))
	root, err := os.OpenRoot(r.Root)
	if err != nil {
		return nil, err
	}
	info, statErr := root.Stat(rel)
	closeErr := root.Close()
	if statErr != nil {
		return nil, statErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("repository content is not a regular file")
	}
	return blobsource.New(info.Size(), digest, func() (io.ReadCloser, error) {
		root, err := os.OpenRoot(r.Root)
		if err != nil {
			return nil, err
		}
		file, err := root.Open(rel)
		if err != nil {
			_ = root.Close()
			return nil, err
		}
		return &rootedReader{ReadCloser: file, root: root}, nil
	})
}

type rootedReader struct {
	io.ReadCloser
	root *os.Root
}

func (r *rootedReader) Close() error {
	return errors.Join(r.ReadCloser.Close(), r.root.Close())
}
