package oci

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/adversarylabs/adversary/pkg/blobsource"
)

// PulledSources owns downloaded temporary files. Close releases every source.
type PulledSources struct {
	Reference         Reference
	RawManifest       []byte
	Manifest          Manifest
	ManifestDigest    string
	AdversaryManifest []byte
	// AdversaryManifestDigest is the verified attached blob descriptor digest.
	AdversaryManifestDigest string
	Blobs                   []SourceBlob
	owned                   []blobsource.SourceCloser
}

var (
	blobTempCreated func(string)
	createBlobTemp  = func() (*os.File, error) { return os.CreateTemp("", "adversary-blob-*") }
	closeBlobTemp   = func(f *os.File) error { return f.Close() }
	removeBlobTemp  = os.Remove
)

func (p *PulledSources) Close() error {
	var err error
	for _, src := range p.owned {
		err = errors.Join(err, src.Close())
	}
	return err
}

func (r *HTTPRegistry) PushSources(ctx context.Context, ref Reference, manifest []byte, blobs []SourceBlob) (string, error) {
	ctx, cancel := withOperationDeadline(ctx)
	defer cancel()
	for _, blob := range blobs {
		if _, err := NewSourceBlob(blob.Descriptor, blob.Source); err != nil {
			return "", err
		}
		if err := blobsource.Verify(blob.Source); err != nil {
			return "", err
		}
		if err := r.pushSourceBlob(ctx, ref, blob); err != nil {
			return "", err
		}
	}
	return r.pushManifest(ctx, ref, ref.ManifestReference(), ImageManifestMediaType, manifest)
}

func (r *HTTPRegistry) pushSourceBlob(ctx context.Context, ref Reference, blob SourceBlob) error {
	head, err := r.newRequest(ctx, http.MethodHead, ref, "/blobs/"+blob.Descriptor.Digest, nil)
	if err != nil {
		return err
	}
	resp, err := r.do(head, ref, "repository:"+ref.Repository+":pull")
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusOK {
		return resp.Body.Close()
	}
	if resp.StatusCode != http.StatusNotFound && resp.StatusCode != http.StatusUnauthorized {
		defer resp.Body.Close()
		return registryError(resp)
	}
	if err := resp.Body.Close(); err != nil {
		return err
	}
	start, err := r.newRequest(ctx, http.MethodPost, ref, "/blobs/uploads/", nil)
	if err != nil {
		return err
	}
	resp, err = r.do(start, ref, "repository:"+ref.Repository+":push,pull")
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		defer resp.Body.Close()
		return registryError(resp)
	}
	location := resp.Header.Get("Location")
	closeErr := resp.Body.Close()
	if closeErr != nil {
		return closeErr
	}
	if location == "" {
		return fmt.Errorf("registry did not return upload location")
	}
	u, err := validatedLocation(r.scheme(), ref.Registry, location)
	if err != nil {
		return err
	}
	sep := "?"
	if strings.Contains(u, "?") {
		sep = "&"
	}
	u += sep + "digest=" + blob.Descriptor.Digest
	reader, err := blob.Source.Open()
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, u, reader)
	if err != nil {
		_ = reader.Close()
		return err
	}
	req.GetBody = blob.Source.Open
	req.ContentLength = blob.Source.Size()
	req.Header.Set("Content-Type", blob.Descriptor.MediaType)
	resp, err = r.do(req, ref, "repository:"+ref.Repository+":push,pull")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return registryError(resp)
	}
	return nil
}

func (r *HTTPRegistry) PullSources(ctx context.Context, ref Reference) (_ *PulledSources, retErr error) {
	ctx, cancel := withOperationDeadline(ctx)
	defer cancel()
	manifestData, manifestDigest, err := r.getManifest(ctx, ref)
	if err != nil {
		return nil, err
	}
	var manifest Manifest
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		return nil, err
	}
	if manifest.MediaType != "" && manifest.MediaType != ImageManifestMediaType && manifest.MediaType != DockerImageManifestMediaType {
		return nil, fmt.Errorf("unsupported manifest media type %s", manifest.MediaType)
	}
	if err := validatePulledManifest(manifest); err != nil {
		return nil, err
	}
	p := &PulledSources{Reference: ref, RawManifest: manifestData, Manifest: manifest, ManifestDigest: manifestDigest}
	defer func() {
		if retErr != nil {
			retErr = errors.Join(retErr, p.Close())
		}
	}()
	pinned := ref
	pinned.Tag = ""
	pinned.Digest = manifestDigest
	for _, descriptor := range append([]Descriptor{manifest.Config}, manifest.Layers...) {
		src, err := r.getBlobSource(ctx, pinned, descriptor)
		if err != nil {
			return nil, err
		}
		p.owned = append(p.owned, src)
		p.Blobs = append(p.Blobs, SourceBlob{Descriptor: descriptor, Source: src})
	}
	p.AdversaryManifest, p.AdversaryManifestDigest, err = r.getAdversaryManifestReferrer(ctx, pinned, manifestDigest)
	if err != nil {
		return nil, err
	}
	return p, nil
}

func (r *HTTPRegistry) getBlobSource(ctx context.Context, ref Reference, descriptor Descriptor) (_ blobsource.SourceCloser, retErr error) {
	limit := DefaultIngestionLimits.CompressedBlobBytes
	switch descriptor.MediaType {
	case EmptyConfigMediaType, AdversaryManifestMediaType:
		limit = DefaultIngestionLimits.ConfigBytes
	case PackageLayerMediaType:
	default:
		return nil, fmt.Errorf("unsupported blob media type %q", descriptor.MediaType)
	}
	if descriptor.Size < 0 || descriptor.Size > limit {
		return nil, fmt.Errorf("blob %s exceeds %d byte limit", descriptor.Digest, limit)
	}
	req, err := r.newRequest(ctx, http.MethodGet, ref, "/blobs/"+descriptor.Digest, nil)
	if err != nil {
		return nil, err
	}
	resp, err := r.do(req, ref, "repository:"+ref.Repository+":pull")
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, errors.Join(registryError(resp), resp.Body.Close())
	}
	tmp, err := createBlobTemp()
	if err != nil {
		return nil, errors.Join(err, resp.Body.Close())
	}
	name := tmp.Name()
	if blobTempCreated != nil {
		blobTempCreated(name)
	}
	cleanup := true
	defer func() {
		if tmp != nil {
			retErr = errors.Join(retErr, closeBlobTemp(tmp))
		}
		if cleanup {
			retErr = errors.Join(retErr, removeBlobTemp(name))
		}
	}()
	hash, err := ParseDigest(descriptor.Digest)
	if err != nil {
		return nil, errors.Join(err, resp.Body.Close())
	}
	digester := hash.Algorithm().Digester()
	n, overflow, copyErr := copyDescriptor(io.MultiWriter(tmp, digester.Hash()), resp.Body, descriptor.Size)
	closeErr := resp.Body.Close()
	if err := errors.Join(copyErr, closeErr); err != nil {
		return nil, err
	}
	if n != descriptor.Size {
		return nil, fmt.Errorf("blob %s size mismatch: got %d, want %d", descriptor.Digest, n, descriptor.Size)
	}
	if overflow {
		return nil, fmt.Errorf("blob %s exceeds declared size %d", descriptor.Digest, descriptor.Size)
	}
	if digester.Digest().String() != descriptor.Digest {
		return nil, fmt.Errorf("blob %s digest mismatch", descriptor.Digest)
	}
	if err := tmp.Sync(); err != nil {
		return nil, err
	}
	if err := closeBlobTemp(tmp); err != nil {
		return nil, err
	}
	tmp = nil
	src, err := blobsource.File(name, descriptor.Digest)
	if err != nil {
		return nil, err
	}
	cleanup = false
	return blobsource.Owned(src, func() error { return removeBlobTemp(name) }), nil
}

func copyDescriptor(dst io.Writer, src io.Reader, size int64) (int64, bool, error) {
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
			return n, false, fmt.Errorf("blob reader returned invalid byte count %d", readN)
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
			return n, false, fmt.Errorf("blob reader returned invalid byte count %d", readN)
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
