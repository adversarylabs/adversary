package repository

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/adversarylabs/adversary/internal/publock"
	"github.com/adversarylabs/adversary/pkg/blobsource"
	"github.com/adversarylabs/adversary/pkg/oci"
)

// CommitEquivalentManifest records the exact manifest bytes under another
// verified digest identity. It takes the lifecycle lock before reading the
// source record or creating the target record, so callers must not hold a
// PayloadLease. Existing config, layer, and adversary-manifest content is
// reused without opening caller-owned sources.
func (r Repository) CommitEquivalentManifest(sourceDigest, targetDigest string, manifest []byte) (_ Record, retErr error) {
	if len(manifest) == 0 || len(manifest) > 4<<20 {
		return Record{}, fmt.Errorf("manifest must be between 1 byte and 4 MiB")
	}
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

	source, err := r.record(sourceDigest)
	if err != nil {
		return Record{}, err
	}
	if source.Digest != sourceDigest || source.ManifestDigest != sourceDigest {
		return Record{}, fmt.Errorf("source manifest identity conflicts with committed record")
	}
	if err := r.validateStoredArtifactLayer(source); err != nil {
		return Record{}, fmt.Errorf("source artifact semantic validation failed: %w", err)
	}
	if err := oci.VerifyDigest(manifest, source.ManifestDigest); err != nil {
		return Record{}, fmt.Errorf("source manifest bytes mismatch: %w", err)
	}
	if err := oci.VerifyDigest(manifest, targetDigest); err != nil {
		return Record{}, fmt.Errorf("target manifest bytes mismatch: %w", err)
	}
	if targetDigest == sourceDigest {
		return source, nil
	}
	rootDigest := source.CanonicalAliasDigest
	if rootDigest == "" {
		rootDigest = source.Digest
	}
	if err := r.verifyContent("blobs", source.LayerDigest); err != nil {
		return Record{}, fmt.Errorf("verify committed layer: %w", err)
	}

	target, targetErr := r.record(targetDigest)
	if targetErr == nil {
		targetManifest, readErr := r.readLimit("manifests/"+key(target.ManifestDigest), 4<<20)
		if readErr != nil {
			return Record{}, fmt.Errorf("read existing target manifest: %w", readErr)
		}
		if target.Digest != targetDigest || target.ManifestDigest != targetDigest ||
			target.Name != source.Name || target.Version != source.Version ||
			target.ConfigDigest != source.ConfigDigest || target.LayerDigest != source.LayerDigest ||
			target.AdversaryManifestDigest != source.AdversaryManifestDigest ||
			!bytes.Equal(targetManifest, manifest) {
			return Record{}, fmt.Errorf("existing target record is not semantically equivalent")
		}
		return target, nil
	}
	if !errors.Is(targetErr, os.ErrNotExist) {
		return Record{}, targetErr
	}

	config, err := r.readLimit("blobs/"+key(source.ConfigDigest), 1<<20)
	if err != nil {
		return Record{}, fmt.Errorf("read committed config: %w", err)
	}
	var adversaryManifest []byte
	if source.AdversaryManifestDigest != "" {
		adversaryManifest, err = r.readLimit("adversary-manifests/"+key(source.AdversaryManifestDigest), 1<<20)
		if err != nil {
			return Record{}, fmt.Errorf("read committed adversary manifest: %w", err)
		}
	}
	targetSource, err := blobsource.New(int64(len(manifest)), targetDigest, func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(manifest)), nil
	})
	if err != nil {
		return Record{}, err
	}
	if err := r.putSource("manifests", targetSource); err != nil {
		return Record{}, fmt.Errorf("persist target manifest: %w", err)
	}
	aliasPreference := rootDigest
	if aliasPreference == targetDigest {
		aliasPreference = ""
	}
	return r.importData(importMetadata{
		Name: source.Name, Version: source.Version,
		Manifest: manifest, Config: config, AdversaryManifest: adversaryManifest,
		ManifestDigest: targetDigest, ConfigDigest: source.ConfigDigest,
		LayerDigest: source.LayerDigest, AdversaryManifestDigest: source.AdversaryManifestDigest,
		CanonicalAliasDigest: aliasPreference,
	}, true)
}
