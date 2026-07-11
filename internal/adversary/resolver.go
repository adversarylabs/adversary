package adversary

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	legacycache "github.com/adversarylabs/adversary/pkg/adversary"
	"github.com/adversarylabs/adversary/pkg/oci"
	"github.com/adversarylabs/adversary/pkg/pack"
	"github.com/adversarylabs/adversary/pkg/repository"
	legacy "github.com/adversarylabs/adversary/pkg/store"
)

type Resolver struct {
	Repository repository.Repository
	Legacy     legacy.Store
}

var ErrNotFound = errors.New("adversary reference not found")
var ErrMigrationRequired = errors.New("legacy cache artifact requires exact registry pull for migration")

type Resolution struct {
	Record             repository.Record
	CanonicalReference string
	Digest             string
	Path               string
	Local              bool
}

func DefaultResolver() (Resolver, error) {
	s, err := legacy.Default()
	if err != nil {
		return Resolver{}, err
	}
	root := filepath.Join(s.Root, "repository-v1")
	if err := os.MkdirAll(root, 0700); err != nil {
		return Resolver{}, err
	}
	return Resolver{Repository: repository.Repository{Root: root}, Legacy: s}, nil
}

func (r Resolver) Resolve(value string) (Resolution, error) {
	if info, err := os.Stat(filepath.Join(value, "adversary.yaml")); err == nil && !info.IsDir() {
		path, err := filepath.Abs(value)
		return Resolution{Path: path, Local: true, CanonicalReference: path}, err
	}
	if strings.HasPrefix(value, "sha256:") {
		return r.resolveOrMigrate(value)
	}
	if isFullyQualified(value) {
		return r.resolveOrMigrate(value)
	}
	if isLocalNameTag(value) {
		return r.resolveOrMigrate(value)
	}
	return r.resolveOrMigrate(value)
}
func (r Resolver) Lookup(value string) (Resolution, error) {
	if info, err := os.Stat(filepath.Join(value, "adversary.yaml")); err == nil && !info.IsDir() {
		path, err := filepath.Abs(value)
		return Resolution{Path: path, Local: true, CanonicalReference: path}, err
	}
	rec, err := r.Repository.Resolve(value)
	if err != nil {
		hasExact, exactErr := r.Repository.HasExact(value)
		if exactErr != nil {
			return Resolution{}, exactErr
		}
		if hasExact || !os.IsNotExist(err) {
			return Resolution{}, err
		}
		return r.resolveOrMigrate(value)
	}
	canonical, err := r.Repository.CanonicalReference(rec.Digest)
	if err != nil {
		return Resolution{}, err
	}
	return Resolution{Record: rec, CanonicalReference: canonical, Digest: rec.Digest}, nil
}
func (r Resolver) resolveRepository(value string) (Resolution, error) {
	rec, err := r.Repository.Resolve(value)
	if err != nil {
		return Resolution{}, err
	}
	path, err := r.Repository.Materialize(rec)
	if err != nil {
		return Resolution{}, err
	}
	canonical := value
	if ref, refErr := r.Repository.CanonicalReference(rec.Digest); refErr == nil {
		canonical = ref
	} else if !os.IsNotExist(refErr) {
		return Resolution{}, refErr
	}
	return Resolution{Record: rec, CanonicalReference: canonical, Digest: rec.Digest, Path: path}, nil
}
func (r Resolver) resolveOrMigrate(value string) (Resolution, error) {
	got, err := r.resolveRepository(value)
	if err == nil {
		return got, nil
	}
	if errors.Is(err, repository.ErrAmbiguous) {
		return Resolution{}, err
	}
	if !os.IsNotExist(err) {
		return Resolution{}, err
	}
	if hasExact, exactErr := r.Repository.HasExact(value); exactErr != nil {
		return Resolution{}, exactErr
	} else if hasExact {
		return Resolution{}, err
	}
	record, legacyErr := r.Legacy.Inspect(value)
	if legacyErr != nil {
		if cache, cacheErr := legacycache.DefaultCache(); cacheErr == nil {
			if strings.HasPrefix(value, "sha256:") {
				if _, ok := cache.ResolveDigest(value); ok {
					return Resolution{}, ErrMigrationRequired
				}
			} else if _, ok := cache.Resolve(value); ok {
				return Resolution{}, ErrMigrationRequired
			}
		}
		return Resolution{}, fmt.Errorf("%w: %s", ErrNotFound, value)
	}
	manifest, blobs, legacyErr := r.Legacy.OCIPayload(record)
	if legacyErr != nil {
		return Resolution{}, legacyErr
	}
	yaml, legacyErr := r.Legacy.AdversaryManifest(record)
	if legacyErr != nil {
		return Resolution{}, legacyErr
	}
	var config, layer []byte
	for _, b := range blobs {
		switch b.Descriptor.Digest {
		case record.ConfigDigest:
			config = b.Data
		case record.LayerDigest:
			layer = b.Data
		}
	}
	ref := record.Name + ":" + record.Version
	imported, legacyErr := r.Repository.Import(repository.Import{Reference: ref, Name: record.ManifestName, Version: record.Version, Manifest: manifest, Config: config, Layer: layer, AdversaryManifest: yaml, ManifestDigest: record.Digest, ConfigDigest: record.ConfigDigest, LayerDigest: record.LayerDigest, AdversaryManifestDigest: record.AdversaryManifestDigest})
	if legacyErr != nil {
		return Resolution{}, fmt.Errorf("migrate legacy artifact: %w", legacyErr)
	}
	path, legacyErr := r.Repository.Materialize(imported)
	if legacyErr != nil {
		return Resolution{}, legacyErr
	}
	return Resolution{Record: imported, CanonicalReference: ref, Digest: imported.Digest, Path: path}, nil
}
func isFullyQualified(v string) bool {
	if len(v) >= 3 && ((v[0] >= 'A' && v[0] <= 'Z') || (v[0] >= 'a' && v[0] <= 'z')) && v[1] == ':' && (v[2] == '\\' || v[2] == '/') {
		return false
	}
	first := v
	slash := strings.IndexByte(v, '/')
	if slash >= 0 {
		first = v[:slash]
	}
	return strings.Contains(first, ".") || (slash >= 0 && strings.Contains(first, ":")) || strings.Contains(v, "@")
}
func isLocalNameTag(v string) bool {
	slash := strings.LastIndexByte(v, '/')
	colon := strings.LastIndexByte(v, ':')
	return colon > slash && !strings.Contains(v, "@")
}
func (r Resolver) ImportPacked(a pack.Artifact, reference string) (repository.Record, error) {
	return r.Repository.ImportPacked(a, reference)
}
func (r Resolver) ImportPulled(a oci.PulledArtifact) (repository.Record, error) {
	return r.Repository.ImportPulled(a)
}
