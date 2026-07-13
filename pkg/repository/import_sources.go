package repository

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/adversarylabs/adversary/internal/publock"
	"github.com/adversarylabs/adversary/internal/rootreplace"
	"github.com/adversarylabs/adversary/pkg/blobsource"
	"github.com/adversarylabs/adversary/pkg/oci"
	digestapi "github.com/opencontainers/go-digest"
)

// SourceImport is the bounded-memory import contract. The manifest, config and
// adversary manifest are bounded metadata; layer content is always streamed.
type SourceImport struct {
	Reference, Name, Version    string
	Manifest, AdversaryManifest blobsource.Source
	Blobs                       []oci.SourceBlob
}

func (r Repository) ImportSources(in SourceImport) (_ Record, retErr error) {
	if err := r.init(); err != nil {
		return Record{}, err
	}
	lifecycle, err := publock.Acquire(r.Root, "repo-lifecycle")
	if err != nil {
		return Record{}, err
	}
	defer func() { retErr = errors.Join(retErr, lifecycle.Close()) }()
	if err := r.recoverImportsLocked(); err != nil {
		return Record{}, err
	}
	var configBlob, layerBlob oci.SourceBlob
	if len(in.Blobs) != 2 {
		return Record{}, fmt.Errorf("exactly one config and one layer source are required")
	}
	for _, b := range in.Blobs {
		if _, validateErr := oci.NewSourceBlob(b.Descriptor, b.Source); validateErr != nil {
			return Record{}, validateErr
		}
		switch b.Descriptor.MediaType {
		case oci.EmptyConfigMediaType:
			if configBlob.Source != nil {
				return Record{}, fmt.Errorf("duplicate config source")
			}
			configBlob = b
		case oci.PackageLayerMediaType:
			if layerBlob.Source != nil {
				return Record{}, fmt.Errorf("duplicate layer source")
			}
			layerBlob = b
		default:
			return Record{}, fmt.Errorf("unsupported source media type %q", b.Descriptor.MediaType)
		}
	}
	if in.Manifest == nil || configBlob.Source == nil || layerBlob.Source == nil {
		return Record{}, fmt.Errorf("manifest, config, and layer sources are required")
	}
	var stagedSources []blobsource.SourceCloser
	defer func() {
		for i := len(stagedSources) - 1; i >= 0; i-- {
			retErr = errors.Join(retErr, stagedSources[i].Close())
		}
	}()
	stage := func(source blobsource.Source, limit int64) (blobsource.Source, error) {
		staged, stageErr := stageImportSource(source, limit)
		if stageErr != nil {
			return nil, stageErr
		}
		stagedSources = append(stagedSources, staged)
		return staged, nil
	}
	in.Manifest, err = stage(in.Manifest, 4<<20)
	if err != nil {
		return Record{}, fmt.Errorf("stage manifest: %w", err)
	}
	configBlob.Source, err = stage(configBlob.Source, 1<<20)
	if err != nil {
		return Record{}, fmt.Errorf("stage config: %w", err)
	}
	layerBlob.Source, err = stage(layerBlob.Source, 256<<20)
	if err != nil {
		return Record{}, fmt.Errorf("stage layer: %w", err)
	}
	if in.AdversaryManifest != nil {
		in.AdversaryManifest, err = stage(in.AdversaryManifest, 1<<20)
		if err != nil {
			return Record{}, fmt.Errorf("stage adversary manifest: %w", err)
		}
	}
	manifest, err := readSourceLimited(in.Manifest, 4<<20)
	if err != nil {
		return Record{}, fmt.Errorf("read manifest: %w", err)
	}
	var parsed oci.Manifest
	if err := json.Unmarshal(manifest, &parsed); err != nil {
		return Record{}, fmt.Errorf("parse OCI manifest: %w", err)
	}
	if !descriptorMatches(parsed.Config, configBlob.Descriptor) || len(parsed.Layers) != 1 || !descriptorMatches(parsed.Layers[0], layerBlob.Descriptor) {
		return Record{}, fmt.Errorf("OCI manifest descriptors conflict with supplied sources")
	}
	config, layer := configBlob.Source, layerBlob.Source
	if config.Size() > 1<<20 {
		return Record{}, fmt.Errorf("config source exceeds %d byte limit", 1<<20)
	}
	if layer.Size() > 256<<20 {
		return Record{}, fmt.Errorf("layer source exceeds %d byte limit", 256<<20)
	}
	configData, err := readSourceLimited(config, 1<<20)
	if err != nil {
		return Record{}, fmt.Errorf("read config: %w", err)
	}
	var adversary []byte
	if in.AdversaryManifest != nil {
		adversary, err = readSourceLimited(in.AdversaryManifest, 1<<20)
		if err != nil {
			return Record{}, fmt.Errorf("read adversary manifest: %w", err)
		}
	}
	canonicalManifest, err := validateArtifactLayer(configData, adversary, parsed.Annotations, layer)
	if err != nil {
		return Record{}, err
	}
	if in.AdversaryManifest == nil {
		in.AdversaryManifest = blobsource.Bytes(canonicalManifest)
		adversary = canonicalManifest
	}
	for _, item := range []struct {
		kind string
		src  blobsource.Source
	}{{"manifests", in.Manifest}, {"blobs", config}, {"blobs", layer}, {"adversary-manifests", in.AdversaryManifest}} {
		if item.src != nil {
			if err := r.putSource(item.kind, item.src); err != nil {
				return Record{}, err
			}
		}
	}
	return r.importData(importMetadata{Reference: in.Reference, Name: in.Name, Version: in.Version,
		Manifest: manifest, Config: configData, AdversaryManifest: adversary,
		ManifestDigest: in.Manifest.Digest(), ConfigDigest: config.Digest(), LayerDigest: layer.Digest(),
		AdversaryManifestDigest: sourceDigest(in.AdversaryManifest)}, true)
}

func stageImportSource(source blobsource.Source, limit int64) (_ blobsource.SourceCloser, retErr error) {
	if source == nil || source.Size() < 0 || source.Size() > limit {
		return nil, fmt.Errorf("source exceeds %d byte limit", limit)
	}
	file, err := os.CreateTemp("", "adversary-import-source-")
	if err != nil {
		return nil, err
	}
	name := file.Name()
	keep := false
	defer func() {
		if !keep {
			retErr = errors.Join(retErr, os.Remove(name))
		}
	}()
	copyErr := copyVerifiedSource(file, source)
	syncErr := file.Sync()
	closeErr := file.Close()
	if err := errors.Join(copyErr, syncErr, closeErr); err != nil {
		return nil, err
	}
	staged, err := blobsource.File(name, source.Digest())
	if err != nil {
		return nil, err
	}
	keep = true
	return blobsource.Owned(staged, func() error { return os.Remove(name) }), nil
}

func descriptorMatches(a, b oci.Descriptor) bool {
	return a.MediaType == b.MediaType && a.Digest == b.Digest && a.Size == b.Size
}

func sourceDigest(s blobsource.Source) string {
	if s == nil {
		return ""
	}
	return s.Digest()
}

func readSourceLimited(src blobsource.Source, limit int64) ([]byte, error) {
	if src == nil || src.Size() < 0 || src.Size() > limit {
		return nil, fmt.Errorf("source exceeds %d byte limit", limit)
	}
	var data bytes.Buffer
	if err := copyVerifiedSource(&data, src); err != nil {
		return nil, err
	}
	return data.Bytes(), nil
}

func (r Repository) putSource(kind string, src blobsource.Source) (retErr error) {
	if err := r.init(); err != nil {
		return err
	}
	lock, err := publock.Acquire(r.Root, "repo-content\x00"+src.Digest())
	if err != nil {
		return err
	}
	defer func() { retErr = errors.Join(retErr, lock.Close()) }()
	root, err := os.OpenRoot(r.Root)
	if err != nil {
		return err
	}
	defer func() { retErr = errors.Join(retErr, root.Close()) }()
	dst := filepath.ToSlash(filepath.Join(kind, key(src.Digest())))
	if existing, err := root.Open(dst); err == nil {
		verifyErr := verifyReader(existing, src)
		return errors.Join(verifyErr, existing.Close())
	} else if !os.IsNotExist(err) {
		return err
	}
	tmp := filepath.ToSlash(filepath.Join(kind, ".stream-"+nonce()))
	f, err := root.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	cleanup := true
	defer func() {
		if cleanup {
			retErr = errors.Join(retErr, root.Remove(tmp))
		}
	}()
	copyErr := copyVerifiedSource(f, src)
	closeErr := f.Close()
	if err := errors.Join(copyErr, closeErr); err != nil {
		return err
	}
	if err := rootreplace.Immutable(root, tmp, dst); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func verifyReader(r io.Reader, src blobsource.Source) error {
	digest, err := digestapi.Parse(src.Digest())
	if err != nil {
		return err
	}
	dataDigest := digest.Verifier()
	n, overflow, err := copyExact(dataDigest, r, src.Size())
	if err != nil {
		return err
	}
	if n != src.Size() || overflow || !dataDigest.Verified() {
		return fmt.Errorf("stored source conflicts with %s", src.Digest())
	}
	return nil
}

func copyVerifiedSource(dst io.Writer, src blobsource.Source) error {
	digest, err := digestapi.Parse(src.Digest())
	if err != nil {
		return err
	}
	r, err := src.Open()
	if err != nil {
		return err
	}
	verifier := digest.Verifier()
	n, overflow, copyErr := copyExact(io.MultiWriter(dst, verifier), r, src.Size())
	closeErr := r.Close()
	if n != src.Size() {
		copyErr = errors.Join(copyErr, fmt.Errorf("source size mismatch: got %d, want %d", n, src.Size()))
	}
	if overflow {
		copyErr = errors.Join(copyErr, fmt.Errorf("source exceeds declared size %d", src.Size()))
	}
	if copyErr == nil && !verifier.Verified() {
		copyErr = fmt.Errorf("source digest mismatch")
	}
	return errors.Join(copyErr, closeErr)
}

func copyExact(dst io.Writer, src io.Reader, size int64) (int64, bool, error) {
	var n int64
	buf := make([]byte, 32<<10)
	empty := 0
	for n < size {
		want := int64(len(buf))
		if remain := size - n; remain < want {
			want = remain
		}
		readN, readErr := src.Read(buf[:want])
		if readN < 0 || readN > int(want) {
			return n, false, fmt.Errorf("source reader returned invalid byte count %d", readN)
		}
		if readN > 0 {
			empty = 0
			writeN, writeErr := dst.Write(buf[:readN])
			n += int64(writeN)
			if writeErr != nil {
				return n, false, errors.Join(writeErr, readErr)
			}
			if writeN != readN {
				return n, false, io.ErrShortWrite
			}
		} else if readErr == nil {
			empty++
			if empty >= 100 {
				return n, false, io.ErrNoProgress
			}
		}
		if readErr != nil {
			if readErr == io.EOF && n == size {
				return n, false, nil
			}
			return n, false, readErr
		}
	}
	var probe [1]byte
	for empty := 0; empty < 100; empty++ {
		readN, readErr := src.Read(probe[:])
		if readN < 0 || readN > len(probe) {
			return n, false, fmt.Errorf("source reader returned invalid byte count %d", readN)
		}
		if readN > 0 {
			return n, true, readErr
		}
		if readErr == io.EOF {
			return n, false, nil
		}
		if readErr != nil {
			return n, false, readErr
		}
	}
	return n, false, io.ErrNoProgress
}
