// Package repository is the additive unified content-addressed artifact store.
package repository

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/adversarylabs/adversary/internal/archiveutil"
	"github.com/adversarylabs/adversary/internal/publock"
	"github.com/adversarylabs/adversary/internal/rootreplace"
	canonical "github.com/adversarylabs/adversary/pkg/manifest"
	"github.com/adversarylabs/adversary/pkg/oci"
	"github.com/adversarylabs/adversary/pkg/pack"
)

var ErrAmbiguous = errors.New("ambiguous artifact alias")
var ErrCAS = errors.New("reference changed")

type Repository struct{ Root string }
type Record struct {
	Digest                  string `json:"digest"`
	Name                    string `json:"name"`
	Version                 string `json:"version"`
	ManifestDigest          string `json:"manifestDigest"`
	ConfigDigest            string `json:"configDigest"`
	LayerDigest             string `json:"layerDigest"`
	AdversaryManifestDigest string `json:"adversaryManifestDigest"`
}
type Import struct {
	Reference                                                          string
	Name                                                               string
	Version                                                            string
	Manifest, Config, Layer, AdversaryManifest                         []byte
	ManifestDigest, ConfigDigest, LayerDigest, AdversaryManifestDigest string
}
type VerifyResult struct{ Missing, Corrupt []string }
type Checkpoint struct {
	LastDigest string `json:"lastDigest,omitempty"`
	Imported   int    `json:"imported"`
}

const maxIndexBytes int64 = 4 << 20

var importStepHook func(string) error

func (r Repository) ImportPacked(a pack.Artifact, reference string) (Record, error) {
	return r.Import(Import{Reference: reference, Name: a.ManifestName, Version: a.Version, Manifest: a.Manifest, Config: a.Config, Layer: a.Layer, AdversaryManifest: a.AdversaryManifest, ManifestDigest: a.ManifestDigest, ConfigDigest: a.ConfigDigest, LayerDigest: a.LayerDigest, AdversaryManifestDigest: a.AdversaryManifestDigest})
}
func (r Repository) ImportPulled(a oci.PulledArtifact) (Record, error) {
	if len(a.Manifest.Layers) != 1 {
		return Record{}, fmt.Errorf("pulled artifact must have one layer")
	}
	manifest := append([]byte(nil), a.RawManifest...)
	if len(manifest) == 0 || oci.Digest(manifest) != a.ManifestDigest {
		return Record{}, fmt.Errorf("exact pulled manifest bytes are required")
	}
	config := a.Blobs[a.Manifest.Config.Digest]
	layer := a.Blobs[a.Manifest.Layers[0].Digest]
	adversaryDigest := ""
	if len(a.AdversaryManifest) > 0 {
		adversaryDigest = oci.Digest(a.AdversaryManifest)
	}
	return r.Import(Import{Reference: a.Reference.Locator(), Name: a.Manifest.Annotations["ai.adversary.full_name"], Version: a.Manifest.Annotations["ai.adversary.version"], Manifest: manifest, Config: config, Layer: layer, AdversaryManifest: a.AdversaryManifest, ManifestDigest: a.ManifestDigest, ConfigDigest: a.Manifest.Config.Digest, LayerDigest: a.Manifest.Layers[0].Digest, AdversaryManifestDigest: adversaryDigest})
}

func (r Repository) Import(in Import) (Record, error) {
	if err := r.init(); err != nil {
		return Record{}, err
	}
	lifecycleLock, err := publock.Acquire(r.Root, "repo-lifecycle")
	if err != nil {
		return Record{}, err
	}
	defer lifecycleLock.Close()
	for label, v := range map[string]struct {
		data   []byte
		digest string
	}{"manifest": {in.Manifest, in.ManifestDigest}, "config": {in.Config, in.ConfigDigest}, "layer": {in.Layer, in.LayerDigest}, "adversary manifest": {in.AdversaryManifest, in.AdversaryManifestDigest}} {
		if (len(v.data) > 0 && (v.digest == "" || oci.Digest(v.data) != v.digest)) || (len(v.data) == 0 && v.digest != "") {
			return Record{}, fmt.Errorf("%s digest mismatch", label)
		}
	}
	ref, err := canonicalRef(in.Reference)
	if err != nil {
		return Record{}, err
	}
	rec, err := deriveRecord(in.Manifest, in.Config, in.Layer, in.AdversaryManifest, in.AdversaryManifestDigest)
	if err != nil {
		return Record{}, err
	}
	if rec.Name != in.Name || rec.Version != in.Version {
		return Record{}, fmt.Errorf("caller identity conflicts with artifact")
	}
	lock, err := publock.Acquire(r.Root, "repo-digest\x00"+rec.Digest)
	if err != nil {
		return Record{}, err
	}
	defer lock.Close()
	for _, v := range []struct {
		kind   string
		digest string
		data   []byte
	}{{"manifests", in.ManifestDigest, in.Manifest}, {"blobs", in.ConfigDigest, in.Config}, {"blobs", in.LayerDigest, in.Layer}, {"adversary-manifests", in.AdversaryManifestDigest, in.AdversaryManifest}} {
		if len(v.data) > 0 {
			if err := r.putContent(v.kind, v.digest, v.data); err != nil {
				return Record{}, err
			}
		}
	}
	data, _ := json.MarshalIndent(rec, "", "  ")
	recordPath := "records/" + key(rec.Digest) + ".json"
	if existing, e := r.read(recordPath); e == nil {
		if !bytes.Equal(existing, data) {
			return Record{}, fmt.Errorf("immutable record conflicts with digest")
		}
	} else if os.IsNotExist(e) {
		if err := r.atomicImmutable(recordPath, data); err != nil {
			return Record{}, err
		}
	} else {
		return Record{}, e
	}
	commitPath := "commits/" + key(rec.Digest) + ".json"
	if existing, e := r.read(commitPath); e == nil {
		if string(existing) != rec.Digest {
			return Record{}, fmt.Errorf("commit marker conflict")
		}
	} else if os.IsNotExist(e) {
		if err := r.atomicImmutable(commitPath, []byte(rec.Digest)); err != nil {
			return Record{}, err
		}
	} else {
		return Record{}, e
	}
	if importStepHook != nil {
		if err := importStepHook("record"); err != nil {
			return Record{}, err
		}
	}
	for _, alias := range aliases(rec, ref) {
		if err := r.addAlias(alias, rec.Digest); err != nil {
			return Record{}, err
		}
	}
	if importStepHook != nil {
		if err := importStepHook("aliases"); err != nil {
			return Record{}, err
		}
	}
	if importStepHook != nil {
		if err := importStepHook("reference"); err != nil {
			return Record{}, err
		}
	}
	if ref != "" {
		if err := r.updateRef(ref, "", rec.Digest); err != nil {
			return Record{}, err
		}
	}
	return rec, nil
}

func deriveRecord(manifestData, configData, layer, adversary []byte, adversaryDigest string) (Record, error) {
	if len(manifestData) == 0 || len(manifestData) > 4<<20 || len(configData) == 0 || len(configData) > 1<<20 || len(layer) > 256<<20 {
		return Record{}, fmt.Errorf("artifact component size invalid")
	}
	md := oci.Digest(manifestData)
	cd := oci.Digest(configData)
	var m oci.Manifest
	if err := json.Unmarshal(manifestData, &m); err != nil {
		return Record{}, err
	}
	if m.SchemaVersion != 2 || m.MediaType != oci.ImageManifestMediaType || m.ArtifactType != oci.ArtifactMediaType || m.Config.MediaType != oci.EmptyConfigMediaType || m.Config.Digest != cd || m.Config.Size != int64(len(configData)) || len(m.Layers) != 1 || m.Layers[0].MediaType != oci.PackageLayerMediaType {
		return Record{}, fmt.Errorf("unsupported or conflicting OCI manifest")
	}
	ld := m.Layers[0].Digest
	if len(layer) > 0 && (oci.Digest(layer) != ld || m.Layers[0].Size != int64(len(layer))) {
		return Record{}, fmt.Errorf("layer descriptor conflicts with content")
	}
	var c struct {
		FullName string `json:"full_name"`
		Version  string `json:"version"`
		Name     string `json:"name"`
	}
	if err := json.Unmarshal(configData, &c); err != nil {
		return Record{}, err
	}
	if c.FullName == "" || c.Version == "" || m.Annotations["ai.adversary.full_name"] != c.FullName || m.Annotations["ai.adversary.version"] != c.Version || m.Annotations["ai.adversary.name"] != c.Name {
		return Record{}, fmt.Errorf("annotations conflict with config")
	}
	if len(adversary) > 0 {
		if len(adversary) > 1<<20 || oci.Digest(adversary) != adversaryDigest {
			return Record{}, fmt.Errorf("adversary manifest linkage mismatch")
		}
		parsed, err := canonical.Parse(adversary)
		if err != nil || parsed.Name != c.FullName || (parsed.Version != "" && parsed.Version != c.Version) {
			return Record{}, fmt.Errorf("adversary identity conflicts with config")
		}
	} else if adversaryDigest != "" {
		return Record{}, fmt.Errorf("missing adversary manifest")
	}
	return Record{Digest: md, Name: c.FullName, Version: c.Version, ManifestDigest: md, ConfigDigest: cd, LayerDigest: ld, AdversaryManifestDigest: adversaryDigest}, nil
}

func (r Repository) UpdateRef(reference, oldDigest, newDigest string) error {
	if err := r.init(); err != nil {
		return err
	}
	lifecycleLock, err := publock.Acquire(r.Root, "repo-lifecycle")
	if err != nil {
		return err
	}
	defer lifecycleLock.Close()
	return r.updateRef(reference, oldDigest, newDigest)
}
func (r Repository) updateRef(reference, oldDigest, newDigest string) error {
	ref, err := canonicalRef(reference)
	if err != nil {
		return err
	}
	if ref == "" || newDigest == "" {
		return fmt.Errorf("nonempty canonical reference and target digest required")
	}
	if _, err := oci.ParseDigest(newDigest); err != nil {
		return err
	}
	if _, err := r.loadRecord(newDigest, true); err != nil {
		return fmt.Errorf("reference target does not exist: %w", err)
	}
	lock, err := publock.Acquire(r.Root, "repo-ref\x00"+ref)
	if err != nil {
		return err
	}
	defer lock.Close()
	path := "refs/" + key(ref) + ".json"
	var current struct{ Reference, Digest string }
	if data, e := r.read(path); e == nil {
		if json.Unmarshal(data, &current) != nil {
			return fmt.Errorf("corrupt reference")
		}
		if current.Reference != ref || current.Digest == "" {
			return fmt.Errorf("corrupt reference identity")
		}
	} else if !os.IsNotExist(e) {
		return e
	}
	if current.Digest == newDigest {
		return nil
	}
	if current.Digest != oldDigest {
		return ErrCAS
	}
	data, _ := json.Marshal(struct{ Reference, Digest string }{ref, newDigest})
	return r.atomic(path, data)
}
func (r Repository) DeleteRef(reference, oldDigest string) error {
	if err := r.init(); err != nil {
		return err
	}
	lifecycleLock, err := publock.Acquire(r.Root, "repo-lifecycle")
	if err != nil {
		return err
	}
	defer lifecycleLock.Close()
	ref, err := canonicalRef(reference)
	if err != nil || ref == "" {
		return fmt.Errorf("canonical reference required")
	}
	lock, err := publock.Acquire(r.Root, "repo-ref\x00"+ref)
	if err != nil {
		return err
	}
	defer lock.Close()
	data, err := r.read("refs/" + key(ref) + ".json")
	if err != nil {
		return err
	}
	var current struct{ Reference, Digest string }
	if json.Unmarshal(data, &current) != nil || current.Reference != ref {
		return fmt.Errorf("corrupt reference")
	}
	if current.Digest != oldDigest {
		return ErrCAS
	}
	root, e := os.OpenRoot(r.Root)
	if e != nil {
		return e
	}
	defer root.Close()
	return root.Remove("refs/" + key(ref) + ".json")
}
func (r Repository) Resolve(value string) (Record, error) {
	if strings.HasPrefix(value, "sha256:") {
		return r.record(value)
	}
	if ref, err := canonicalRef(value); err == nil {
		var idx struct{ Reference, Digest string }
		if data, e := r.read("refs/" + key(ref) + ".json"); e == nil {
			if json.Unmarshal(data, &idx) != nil {
				return Record{}, fmt.Errorf("corrupt exact reference index")
			}
			if idx.Reference != ref || idx.Digest == "" {
				return Record{}, fmt.Errorf("reference index identity mismatch")
			}
			return r.record(idx.Digest)
		} else if os.IsNotExist(e) && explicitReference(value) {
			return Record{}, e
		} else if !os.IsNotExist(e) {
			return Record{}, e
		}
	}
	var list []string
	data, err := r.read("aliases/" + key(value) + ".json")
	if err != nil {
		return Record{}, err
	}
	if json.Unmarshal(data, &list) != nil {
		return Record{}, fmt.Errorf("corrupt alias")
	}
	if len(list) == 0 || len(unique(list)) != len(list) {
		return Record{}, fmt.Errorf("malformed alias index")
	}
	for _, d := range list {
		if _, err := oci.ParseDigest(d); err != nil {
			return Record{}, fmt.Errorf("malformed alias target")
		}
	}
	visible := list[:0]
	for _, d := range list {
		if marker, e := r.read("commits/" + key(d) + ".json"); os.IsNotExist(e) {
			continue
		} else if e != nil || string(marker) != d {
			return Record{}, fmt.Errorf("corrupt commit marker")
		}
		visible = append(visible, d)
	}
	list = visible
	if len(list) != 1 {
		return Record{}, ErrAmbiguous
	}
	return r.record(list[0])
}
func explicitReference(v string) bool {
	first := v
	if i := strings.IndexByte(v, '/'); i >= 0 {
		first = v[:i]
	}
	return strings.Contains(first, ".") || strings.Contains(first, ":") || strings.Contains(v, "@")
}
func (r Repository) record(d string) (Record, error) {
	return r.loadRecord(d, true)
}
func (r Repository) loadRecord(d string, requireCommit bool) (Record, error) {
	if requireCommit {
		marker, err := r.read("commits/" + key(d) + ".json")
		if err != nil || string(marker) != d {
			return Record{}, os.ErrNotExist
		}
	}
	data, err := r.read("records/" + key(d) + ".json")
	if err != nil {
		return Record{}, err
	}
	var rec Record
	if err := json.Unmarshal(data, &rec); err != nil {
		return rec, err
	}
	if rec.Digest != d {
		return rec, fmt.Errorf("record digest conflict")
	}
	manifest, err := r.readLimit("manifests/"+key(rec.ManifestDigest), 4<<20)
	if err != nil {
		return rec, err
	}
	config, err := r.readLimit("blobs/"+key(rec.ConfigDigest), 1<<20)
	if err != nil {
		return rec, err
	}
	var adversary []byte
	if rec.AdversaryManifestDigest != "" {
		adversary, err = r.readLimit("adversary-manifests/"+key(rec.AdversaryManifestDigest), 1<<20)
		if err != nil {
			return rec, err
		}
	}
	derived, err := deriveRecord(manifest, config, nil, adversary, rec.AdversaryManifestDigest)
	if err != nil {
		return rec, err
	}
	if derived != rec {
		return rec, fmt.Errorf("persisted record conflicts with artifact content")
	}
	return rec, nil
}
func (r Repository) Verify(rec Record) VerifyResult {
	canonical, err := r.record(rec.Digest)
	if err != nil {
		return VerifyResult{Corrupt: []string{rec.Digest}}
	}
	rec = canonical
	var out VerifyResult
	for _, v := range []struct{ k, d string }{{"manifests", rec.ManifestDigest}, {"blobs", rec.ConfigDigest}, {"blobs", rec.LayerDigest}, {"adversary-manifests", rec.AdversaryManifestDigest}} {
		if v.d == "" {
			continue
		}
		err := r.verifyContent(v.k, v.d)
		if os.IsNotExist(err) {
			out.Missing = append(out.Missing, v.d)
		} else if err != nil {
			out.Corrupt = append(out.Corrupt, v.d)
		}
	}
	return out
}
func (r Repository) Repair(rec Record, sources map[string][]byte) error {
	canonical, err := r.record(rec.Digest)
	if err != nil {
		return err
	}
	rec = canonical
	for _, d := range append(append([]string{}, r.Verify(rec).Missing...), r.Verify(rec).Corrupt...) {
		contentLock, err := publock.Acquire(r.Root, "repo-content\x00"+d)
		if err != nil {
			return err
		}
		data, ok := sources[d]
		if !ok || oci.Digest(data) != d {
			_ = contentLock.Close()
			return fmt.Errorf("verified repair source missing for %s", d)
		}
		kind := "blobs"
		if d == rec.ManifestDigest {
			kind = "manifests"
		}
		if d == rec.AdversaryManifestDigest {
			kind = "adversary-manifests"
		}
		if err := r.atomic(filepath.ToSlash(filepath.Join(kind, key(d))), data); err != nil {
			_ = contentLock.Close()
			return err
		}
		if err := r.verifyContent(kind, d); err != nil {
			_ = contentLock.Close()
			return err
		}
		if err := contentLock.Close(); err != nil {
			return err
		}
	}
	return nil
}
func (r Repository) Materialize(rec Record) (string, error) {
	if err := r.init(); err != nil {
		return "", err
	}
	lifecycleLock, err := publock.Acquire(r.Root, "repo-lifecycle")
	if err != nil {
		return "", err
	}
	defer lifecycleLock.Close()
	digestLock, err := publock.Acquire(r.Root, "repo-digest\x00"+rec.Digest)
	if err != nil {
		return "", err
	}
	defer digestLock.Close()
	canonical, err := r.record(rec.Digest)
	if err != nil {
		return "", err
	}
	rec = canonical
	lock, err := publock.Acquire(r.Root, "repo-materialize\x00"+rec.Digest)
	if err != nil {
		return "", err
	}
	defer lock.Close()
	return r.materializeLocked(rec)
}

type MaterializationLease struct {
	Path string
	lock *publock.Lock
}

func (l *MaterializationLease) Close() error {
	if l == nil || l.lock == nil {
		return nil
	}
	err := l.lock.Close()
	l.lock = nil
	return err
}
func (r Repository) LeaseMaterialized(rec Record) (*MaterializationLease, error) {
	if err := r.init(); err != nil {
		return nil, err
	}
	lifecycle, err := publock.Acquire(r.Root, "repo-lifecycle")
	if err != nil {
		return nil, err
	}
	defer lifecycle.Close()
	digest, err := publock.Acquire(r.Root, "repo-digest\x00"+rec.Digest)
	if err != nil {
		return nil, err
	}
	defer digest.Close()
	canonical, err := r.record(rec.Digest)
	if err != nil {
		return nil, err
	}
	lock, err := publock.Acquire(r.Root, "repo-materialize\x00"+rec.Digest)
	if err != nil {
		return nil, err
	}
	path, err := r.materializeLocked(canonical)
	if err != nil {
		lock.Close()
		return nil, err
	}
	return &MaterializationLease{Path: path, lock: lock}, nil
}

// WithMaterialized callbacks are pure runtime consumers and must not re-enter
// Repository methods while the cross-process materialization lease is held.
func (r Repository) WithMaterialized(rec Record, fn func(string) error) error {
	lease, err := r.LeaseMaterialized(rec)
	if err != nil {
		return err
	}
	defer lease.Close()
	return fn(lease.Path)
}
func (r Repository) materializeLocked(rec Record) (string, error) {
	if v := r.Verify(rec); len(v.Missing)+len(v.Corrupt) > 0 {
		return "", fmt.Errorf("artifact content failed verification")
	}
	rel := "materialized/" + key(rec.Digest)
	dest := filepath.Join(r.Root, filepath.FromSlash(rel))
	if root, e := os.OpenRoot(dest); e == nil {
		defer root.Close()
		if archiveutil.ValidateSealed(root) == nil {
			return dest, nil
		}
	}
	root, err := os.OpenRoot(r.Root)
	if err != nil {
		return "", err
	}
	defer root.Close()
	_ = root.RemoveAll(rel)
	stage := "materialized/.stage-" + nonce()
	if err := root.Mkdir(stage, 0700); err != nil {
		return "", err
	}
	defer root.RemoveAll(stage)
	sr, err := root.OpenRoot(stage)
	if err != nil {
		return "", err
	}
	layer, err := root.Open(filepath.ToSlash(filepath.Join("blobs", key(rec.LayerDigest))))
	if err != nil {
		return "", err
	}
	err = archiveutil.ExtractGzipTar(layer, sr, archiveutil.DefaultLimits)
	_ = layer.Close()
	if err == nil && rec.AdversaryManifestDigest != "" {
		if _, e := sr.Stat("adversary.yaml"); os.IsNotExist(e) {
			data, e := root.ReadFile(filepath.ToSlash(filepath.Join("adversary-manifests", key(rec.AdversaryManifestDigest))))
			if e == nil {
				err = sr.WriteFile("adversary.yaml", data, 0444)
			} else {
				err = e
			}
		}
	}
	if err == nil {
		err = prepareDerivedSDK(sr)
	}
	if err == nil {
		err = archiveutil.PreparePublish(sr)
	}
	if err == nil {
		err = archiveutil.ValidatePrepared(sr)
	}
	_ = sr.Close()
	if err != nil {
		return "", err
	}
	published, err := archiveutil.PublishSealed(r.Root, root, stage, rel)
	if err != nil {
		if published {
			_ = root.RemoveAll(rel)
		}
		return "", err
	}
	return dest, nil
}

func prepareDerivedSDK(root *os.Root) error {
	src := "vendor/adversary-sdk"
	info, err := root.Stat(src)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("vendored SDK is not a directory")
	}
	packageData, err := root.ReadFile(src + "/package.json")
	if err != nil {
		return fmt.Errorf("vendored SDK package metadata: %w", err)
	}
	var metadata struct{ Name, Version, Type, Main string }
	if json.Unmarshal(packageData, &metadata) != nil || metadata.Name != "@adversary/sdk" || metadata.Version == "" || metadata.Type != "module" || metadata.Main != "./dist/index.js" {
		return fmt.Errorf("vendored SDK package identity is invalid")
	}
	if info, err := root.Stat(src + "/dist/index.js"); err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("vendored SDK entrypoint is missing or invalid")
	}
	dst := "node_modules/@adversary/sdk"
	if err := root.MkdirAll(dst, 0755); err != nil {
		return err
	}
	return fs.WalkDir(root.FS(), src, func(path string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.ToSlash(filepath.Join(dst, rel))
		if e.IsDir() {
			return root.MkdirAll(target, 0755)
		}
		data, err := root.ReadFile(path)
		if err != nil {
			return err
		}
		mode := os.FileMode(0444)
		if sourceInfo, infoErr := e.Info(); infoErr == nil && sourceInfo.Mode().Perm()&0111 != 0 {
			mode = 0555
		}
		return root.WriteFile(target, data, mode)
	})
}

func (r Repository) init() error {
	info, statErr := os.Lstat(r.Root)
	if os.IsNotExist(statErr) {
		return fmt.Errorf("repository root must be durably provisioned by caller")
	}
	if statErr != nil {
		return statErr
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("repository root must not be a symlink")
	}
	root, err := os.OpenRoot(r.Root)
	if err != nil {
		return err
	}
	defer root.Close()
	for _, d := range []string{"blobs", "manifests", "adversary-manifests", "records", "refs", "aliases", "commits", "checkpoints", "materialized"} {
		if err := root.MkdirAll(d, 0700); err != nil {
			return err
		}
	}
	return rootreplace.SyncDirectory(root, ".")
}
func (r Repository) putContent(kind, digest string, data []byte) error {
	lock, err := publock.Acquire(r.Root, "repo-content\x00"+digest)
	if err != nil {
		return err
	}
	defer lock.Close()
	if old, err := r.read(filepath.ToSlash(filepath.Join(kind, key(digest)))); err == nil {
		return oci.VerifyDigest(old, digest)
	} else if !os.IsNotExist(err) {
		return err
	}
	return r.atomicImmutable(filepath.ToSlash(filepath.Join(kind, key(digest))), data)
}
func (r Repository) addAlias(alias, digest string) error {
	lock, err := publock.Acquire(r.Root, "repo-alias\x00"+alias)
	if err != nil {
		return err
	}
	defer lock.Close()
	path := "aliases/" + key(alias) + ".json"
	var list []string
	if data, e := r.read(path); e == nil {
		if err := json.Unmarshal(data, &list); err != nil {
			return fmt.Errorf("malformed alias index: %w", err)
		}
	} else if !os.IsNotExist(e) {
		return e
	}
	list = append(list, digest)
	list = unique(list)
	data, _ := json.Marshal(list)
	return r.atomic(path, data)
}
func (r Repository) atomic(rel string, data []byte) error {
	return r.writeAtomic(rel, data, false)
}
func (r Repository) atomicImmutable(rel string, data []byte) error {
	return r.writeAtomic(rel, data, true)
}
func (r Repository) writeAtomic(rel string, data []byte, immutable bool) error {
	if err := r.init(); err != nil {
		return err
	}
	root, err := os.OpenRoot(r.Root)
	if err != nil {
		return err
	}
	defer root.Close()
	dir := filepath.ToSlash(filepath.Dir(rel))
	if err := root.MkdirAll(dir, 0700); err != nil {
		return err
	}
	tmp := dir + "/.tmp-" + nonce()
	if err := root.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	defer root.Remove(tmp)
	if immutable {
		return rootreplace.Immutable(root, tmp, filepath.ToSlash(rel))
	}
	return rootreplace.Mutable(root, tmp, filepath.ToSlash(rel))
}
func (r Repository) read(rel string) ([]byte, error) {
	return r.readLimit(rel, maxIndexBytes)
}
func (r Repository) readLimit(rel string, limit int64) ([]byte, error) {
	root, err := os.OpenRoot(r.Root)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	f, err := root.Open(filepath.ToSlash(rel))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("repository object exceeds limit")
	}
	return data, nil
}
func (r Repository) verifyContent(kind, digest string) error {
	root, err := os.OpenRoot(r.Root)
	if err != nil {
		return err
	}
	defer root.Close()
	f, err := root.Open(filepath.ToSlash(filepath.Join(kind, key(digest))))
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, (256<<20)+1))
	if err != nil {
		return err
	}
	if n > 256<<20 {
		return fmt.Errorf("content exceeds verification limit")
	}
	if "sha256:"+hex.EncodeToString(h.Sum(nil)) != digest {
		return fmt.Errorf("digest mismatch")
	}
	return nil
}
func (r Repository) content(kind, d string) string { return filepath.Join(r.Root, kind, key(d)) }
func canonicalRef(s string) (string, error) {
	if strings.TrimSpace(s) == "" {
		return "", nil
	}
	ref, err := oci.ParseReference(s)
	if err != nil {
		return "", err
	}
	return ref.Locator(), nil
}
func aliases(r Record, reference string) []string {
	out := []string{r.Name}
	if ref, err := oci.ParseReference(reference); err == nil {
		out = append(out, ref.ShortName(), ref.Repository)
	}
	return unique(out)
}
func unique(in []string) []string {
	m := map[string]bool{}
	out := []string{}
	for _, v := range in {
		if v != "" && !m[v] {
			m[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}
func key(s string) string { return fmt.Sprintf("v1-%x", sha256.Sum256([]byte(s))) }
func nonce() string       { var b [16]byte; _, _ = rand.Read(b[:]); return fmt.Sprintf("%x", b) }
func (r Repository) Enumerate(after string, limit int) ([]Record, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("positive enumeration limit required")
	}
	root, e := os.OpenRoot(r.Root)
	if e != nil {
		return nil, e
	}
	defer root.Close()
	dir, err := root.Open("records")
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	var out []Record
	for {
		entries, readErr := dir.ReadDir(128)
		if readErr != nil && readErr != io.EOF {
			return nil, readErr
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			data, err := r.read("records/" + e.Name())
			if err != nil {
				return nil, err
			}
			var rec Record
			if json.Unmarshal(data, &rec) != nil || rec.Digest == "" {
				return nil, fmt.Errorf("malformed repository record %q", e.Name())
			}
			if e.Name() != key(rec.Digest)+".json" {
				return nil, fmt.Errorf("record filename identity mismatch %q", e.Name())
			}
			marker, markerErr := r.read("commits/" + key(rec.Digest) + ".json")
			if os.IsNotExist(markerErr) {
				continue
			}
			if markerErr != nil || string(marker) != rec.Digest {
				return nil, fmt.Errorf("corrupt committed record %s", rec.Digest)
			}
			rec, err = r.record(rec.Digest)
			if err != nil {
				return nil, err
			}
			if rec.Digest > after {
				out = append(out, rec)
				if limit > 0 && len(out) > limit {
					max := 0
					for i := 1; i < len(out); i++ {
						if out[i].Digest > out[max].Digest {
							max = i
						}
					}
					out = append(out[:max], out[max+1:]...)
				}
			}
		}
		if readErr == io.EOF {
			break
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Digest < out[j].Digest })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}
func (r Repository) SaveCheckpoint(name string, c Checkpoint) error {
	if err := validateCheckpoint(name, c); err != nil {
		return err
	}
	lock, err := publock.Acquire(r.Root, "repo-checkpoint\x00"+name)
	if err != nil {
		return err
	}
	defer lock.Close()
	if current, loadErr := r.LoadCheckpoint(name); loadErr == nil {
		if c.Imported < current.Imported || c.LastDigest < current.LastDigest {
			return fmt.Errorf("checkpoint regression: %w", ErrCAS)
		}
	} else if !os.IsNotExist(loadErr) {
		return loadErr
	}
	data, _ := json.Marshal(c)
	return r.atomic("checkpoints/"+key(name)+".json", data)
}
func (r Repository) UpdateCheckpoint(name string, old, next Checkpoint) error {
	if err := validateCheckpoint(name, next); err != nil {
		return err
	}
	lock, err := publock.Acquire(r.Root, "repo-checkpoint\x00"+name)
	if err != nil {
		return err
	}
	defer lock.Close()
	current, err := r.LoadCheckpoint(name)
	if err != nil {
		return err
	}
	if current != old {
		return ErrCAS
	}
	if next.Imported < old.Imported || next.LastDigest < old.LastDigest {
		return fmt.Errorf("checkpoint regression: %w", ErrCAS)
	}
	data, _ := json.Marshal(next)
	return r.atomic("checkpoints/"+key(name)+".json", data)
}
func validateCheckpoint(name string, c Checkpoint) error {
	if strings.TrimSpace(name) == "" || len(name) > 256 {
		return fmt.Errorf("checkpoint name required")
	}
	if c.Imported < 0 {
		return fmt.Errorf("checkpoint imported count cannot be negative")
	}
	if c.LastDigest != "" {
		if _, err := oci.ParseDigest(c.LastDigest); err != nil {
			return fmt.Errorf("invalid checkpoint digest: %w", err)
		}
	}
	return nil
}
func (r Repository) LoadCheckpoint(name string) (Checkpoint, error) {
	if strings.TrimSpace(name) == "" || len(name) > 256 {
		return Checkpoint{}, fmt.Errorf("checkpoint name required")
	}
	data, err := r.read("checkpoints/" + key(name) + ".json")
	if err != nil {
		return Checkpoint{}, err
	}
	var c Checkpoint
	err = json.Unmarshal(data, &c)
	if err == nil {
		err = validateCheckpoint(name, c)
	}
	return c, err
}
func (r Repository) Reconcile(after string, limit int) (map[string]VerifyResult, error) {
	records, err := r.Enumerate(after, limit)
	if err != nil {
		return nil, err
	}
	out := map[string]VerifyResult{}
	for _, rec := range records {
		out[rec.Digest] = r.Verify(rec)
	}
	return out, nil
}
