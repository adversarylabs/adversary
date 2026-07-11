package adversary

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/adversarylabs/adversary/pkg/pack"
	"github.com/adversarylabs/adversary/pkg/repository"
)

type Resolver struct {
	Repository repository.Repository
	Files      RuntimeFiles
}

var ErrNotFound = errors.New("adversary reference not found")

type Resolution struct {
	Record             repository.Record
	CanonicalReference string
	Digest             string
	Path               string
	Local              bool
}

func (r Resolver) Resolve(value string) (Resolution, error) {
	files := r.runtimeFiles()
	if info, err := files.Stat(filepath.Join(value, "adversary.yaml")); err == nil && !info.IsDir() {
		path, err := files.Abs(value)
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
	files := r.runtimeFiles()
	if info, err := files.Stat(filepath.Join(value, "adversary.yaml")); err == nil && !info.IsDir() {
		path, err := files.Abs(value)
		return Resolution{Path: path, Local: true, CanonicalReference: path}, err
	}
	rec, err := r.Repository.Resolve(value)
	if err != nil {
		hasExact, exactErr := r.Repository.HasExact(value)
		if exactErr != nil {
			return Resolution{}, exactErr
		}
		if hasExact || !errors.Is(err, fs.ErrNotExist) {
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
	} else if !errors.Is(refErr, fs.ErrNotExist) {
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
	if !errors.Is(err, fs.ErrNotExist) {
		return Resolution{}, err
	}
	if hasExact, exactErr := r.Repository.HasExact(value); exactErr != nil {
		return Resolution{}, exactErr
	} else if hasExact {
		return Resolution{}, err
	}
	return Resolution{}, fmt.Errorf("%w: %s", ErrNotFound, value)
}

func (r Resolver) runtimeFiles() RuntimeFiles {
	if r.Files != nil {
		return r.Files
	}
	return OSRuntimeFiles{}
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
