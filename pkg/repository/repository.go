// Package repository is the additive unified content-addressed artifact store.
package repository

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
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
	"github.com/adversarylabs/adversary/pkg/blobsource"
	canonical "github.com/adversarylabs/adversary/pkg/manifest"
	"github.com/adversarylabs/adversary/pkg/oci"
	"github.com/adversarylabs/adversary/pkg/pack"
)

var ErrAmbiguous = errors.New("ambiguous artifact alias")
var ErrCAS = errors.New("reference changed")
var errLegacyAlias = errors.New("legacy alias index requires repair")

type aliasIndex struct {
	Version int      `json:"version"`
	Alias   string   `json:"alias"`
	Targets []string `json:"targets"`
}

type Repository struct {
	Root             string
	DefaultRegistry  string
	DefaultNamespace string
}

func (r Repository) registryDefaults() (string, string) {
	registry, namespace := strings.TrimSpace(r.DefaultRegistry), strings.TrimSpace(r.DefaultNamespace)
	if registry == "" {
		registry = oci.DefaultRegistry
	}
	if namespace == "" {
		namespace = oci.DefaultNamespace
	}
	return registry, namespace
}
func (r Repository) canonicalRef(s string) (string, error) {
	if strings.TrimSpace(s) == "" {
		return "", nil
	}
	registry, namespace := r.registryDefaults()
	ref, err := oci.ParseReferenceWithDefaults(s, registry, namespace)
	if err != nil {
		return "", err
	}
	return ref.Locator(), nil
}

type Record struct {
	Digest                  string `json:"digest"`
	Name                    string `json:"name"`
	Version                 string `json:"version"`
	ManifestDigest          string `json:"manifestDigest"`
	ConfigDigest            string `json:"configDigest"`
	LayerDigest             string `json:"layerDigest"`
	AdversaryManifestDigest string `json:"adversaryManifestDigest"`
	CanonicalAliasDigest    string `json:"canonicalAliasDigest,omitempty"`
}
type importMetadata struct {
	Reference                                                          string
	Name                                                               string
	Version                                                            string
	Manifest, Config, AdversaryManifest                                []byte
	ManifestDigest, ConfigDigest, LayerDigest, AdversaryManifestDigest string
	CanonicalAliasDigest                                               string
}
type VerifyResult struct{ Missing, Corrupt []string }
type Checkpoint struct {
	LastDigest string `json:"lastDigest,omitempty"`
	Imported   int    `json:"imported"`
}

const maxIndexBytes int64 = 4 << 20

var importStepHook func(string) error

func (r Repository) ImportPacked(a pack.Artifact, reference string) (Record, error) {
	blobs, err := a.Sources()
	if err != nil {
		return Record{}, err
	}
	return r.ImportSources(SourceImport{Reference: reference, Name: a.ManifestName, Version: a.Version, Manifest: blobsource.Bytes(a.Manifest), Blobs: blobs, AdversaryManifest: blobsource.Bytes(a.AdversaryManifest)})
}

func (r Repository) importData(in importMetadata, lifecycleHeld bool) (_ Record, retErr error) {
	if err := r.init(); err != nil {
		return Record{}, err
	}
	var err error
	var lifecycleLock *publock.Lock
	if !lifecycleHeld {
		lifecycleLock, err = publock.Acquire(r.Root, "repo-lifecycle")
		if err != nil {
			return Record{}, err
		}
		defer lifecycleLock.Close()
	}
	for label, v := range map[string]struct {
		data   []byte
		digest string
	}{"manifest": {in.Manifest, in.ManifestDigest}, "config": {in.Config, in.ConfigDigest}, "adversary manifest": {in.AdversaryManifest, in.AdversaryManifestDigest}} {
		if len(v.data) > 0 {
			if v.digest == "" {
				return Record{}, fmt.Errorf("%s digest missing", label)
			}
			if err := oci.VerifyDigest(v.data, v.digest); err != nil {
				return Record{}, fmt.Errorf("%s digest mismatch: %w", label, err)
			}
		}
	}
	ref, err := r.canonicalRef(in.Reference)
	if err != nil {
		return Record{}, err
	}
	rec, err := deriveRecord(in.Manifest, in.Config, in.AdversaryManifest, in.ManifestDigest, in.ConfigDigest, in.AdversaryManifestDigest)
	if err != nil {
		return Record{}, err
	}
	if rec.Name != in.Name || rec.Version != in.Version {
		return Record{}, fmt.Errorf("caller identity conflicts with artifact")
	}
	if in.CanonicalAliasDigest != "" {
		if in.CanonicalAliasDigest == rec.Digest {
			return Record{}, fmt.Errorf("canonical alias digest must differ from record digest")
		}
		if err := oci.VerifyDigest(in.Manifest, in.CanonicalAliasDigest); err != nil {
			return Record{}, fmt.Errorf("canonical alias digest mismatch: %w", err)
		}
		rec.CanonicalAliasDigest = in.CanonicalAliasDigest
	}
	previousRef := ""
	if ref != "" {
		previousRef, err = r.referenceDigest(ref)
		if err != nil && !os.IsNotExist(err) {
			return Record{}, err
		}
		if previousRef != "" && previousRef != rec.Digest {
			return Record{}, ErrCAS
		}
	}
	lock, err := publock.Acquire(r.Root, "repo-digest\x00"+rec.Digest)
	if err != nil {
		return Record{}, err
	}
	defer lock.Close()
	data, _ := json.MarshalIndent(rec, "", "  ")
	recordPath := "records/" + key(rec.Digest) + ".json"
	commitPath := "commits/" + key(rec.Digest) + ".json"
	_, recordProbeErr := r.read(recordPath)
	_, commitProbeErr := r.read(commitPath)
	if recordProbeErr != nil && !os.IsNotExist(recordProbeErr) {
		return Record{}, recordProbeErr
	}
	if commitProbeErr != nil && !os.IsNotExist(commitProbeErr) {
		return Record{}, commitProbeErr
	}
	journal := importJournal{Version: 1, Digest: rec.Digest, Reference: ref, CreatedRecord: os.IsNotExist(recordProbeErr), CreatedCommit: os.IsNotExist(commitProbeErr), CreatedReference: previousRef == "" && ref != ""}
	if err := r.saveImportJournal(journal); err != nil {
		return Record{}, err
	}
	defer func() {
		if retErr == nil {
			return
		}
		retErr = errors.Join(retErr, r.rollbackImportJournal(journal))
	}()
	if existing, e := r.read(recordPath); e == nil {
		if !bytes.Equal(existing, data) {
			return Record{}, fmt.Errorf("immutable record conflicts with digest")
		}
	} else if os.IsNotExist(e) {
		if err := r.atomicImmutable(recordPath, data); err != nil {
			return Record{}, err
		}
		journal.CreatedRecord = true
		if err := r.saveImportJournal(journal); err != nil {
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
	if existing, e := r.read(commitPath); e == nil {
		if string(existing) != rec.Digest {
			return Record{}, fmt.Errorf("commit marker conflict")
		}
	} else if os.IsNotExist(e) {
		if err := r.atomicImmutable(commitPath, []byte(rec.Digest)); err != nil {
			return Record{}, err
		}
		journal.CreatedCommit = true
		if err := r.saveImportJournal(journal); err != nil {
			return Record{}, err
		}
	} else {
		return Record{}, e
	}
	if importStepHook != nil {
		if err := importStepHook("commit"); err != nil {
			return Record{}, err
		}
	}
	if ref != "" {
		if err := r.updateRefWithHook(ref, previousRef, rec.Digest, func() error {
			if importStepHook != nil {
				return importStepHook("reference")
			}
			return nil
		}); err != nil {
			return Record{}, err
		}
	} else if err := r.rebuildAliases(); err != nil {
		return Record{}, err
	}
	if importStepHook != nil {
		if err := importStepHook("aliases"); err != nil {
			return Record{}, err
		}
	}
	root, err := os.OpenRoot(r.Root)
	if err != nil {
		return Record{}, err
	}
	removeErr := root.Remove(importJournalPath(rec.Digest, ref))
	closeErr := root.Close()
	if removeErr != nil || closeErr != nil {
		return Record{}, errors.Join(removeErr, closeErr)
	}
	return rec, nil
}

func (r Repository) referenceDigest(ref string) (string, error) {
	if j, err := r.readRefMutationJournal(ref); err == nil {
		if _, err := r.validateRefMutationCurrent(j); err != nil {
			return "", err
		}
		if j.Previous == "" {
			return "", os.ErrNotExist
		}
		return j.Previous, nil
	} else if !os.IsNotExist(err) {
		return "", err
	}
	return r.referenceDigestRaw(ref)
}

func (r Repository) referenceDigestRaw(ref string) (string, error) {
	info, err := os.Lstat(filepath.Join(r.Root, "refs", key(ref)+".json"))
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("reference index is not a regular file")
	}
	data, err := r.readLimit("refs/"+key(ref)+".json", maxIndexBytes)
	if err != nil {
		return "", err
	}
	var idx struct{ Reference, Digest string }
	if json.Unmarshal(data, &idx) != nil || idx.Reference != ref || idx.Digest == "" {
		return "", fmt.Errorf("corrupt reference index")
	}
	return idx.Digest, nil
}

func deriveRecord(manifestData, configData, adversary []byte, manifestDigest, configDigest, adversaryDigest string) (Record, error) {
	if len(manifestData) == 0 || len(manifestData) > 4<<20 || len(configData) == 0 || len(configData) > 1<<20 {
		return Record{}, fmt.Errorf("artifact component size invalid")
	}
	if err := oci.VerifyDigest(manifestData, manifestDigest); err != nil {
		return Record{}, fmt.Errorf("manifest digest mismatch: %w", err)
	}
	if err := oci.VerifyDigest(configData, configDigest); err != nil {
		return Record{}, fmt.Errorf("config digest mismatch: %w", err)
	}
	var m oci.Manifest
	if err := json.Unmarshal(manifestData, &m); err != nil {
		return Record{}, err
	}
	if m.SchemaVersion != 2 || m.MediaType != oci.ImageManifestMediaType || m.ArtifactType != oci.ArtifactMediaType || m.Config.MediaType != oci.EmptyConfigMediaType || m.Config.Digest != configDigest || m.Config.Size != int64(len(configData)) || len(m.Layers) != 1 || m.Layers[0].MediaType != oci.PackageLayerMediaType {
		return Record{}, fmt.Errorf("unsupported or conflicting OCI manifest")
	}
	ld := m.Layers[0].Digest
	if _, err := oci.ParseDigest(ld); err != nil {
		return Record{}, fmt.Errorf("invalid layer digest: %w", err)
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
		if len(adversary) > 1<<20 || oci.VerifyDigest(adversary, adversaryDigest) != nil {
			return Record{}, fmt.Errorf("adversary manifest linkage mismatch")
		}
		parsed, err := canonical.Parse(adversary)
		if err != nil || parsed.Name != c.FullName || (parsed.Version != "" && parsed.Version != c.Version) {
			return Record{}, fmt.Errorf("adversary identity conflicts with config")
		}
	} else if adversaryDigest != "" {
		return Record{}, fmt.Errorf("missing adversary manifest")
	}
	return Record{Digest: manifestDigest, Name: c.FullName, Version: c.Version, ManifestDigest: manifestDigest, ConfigDigest: configDigest, LayerDigest: ld, AdversaryManifestDigest: adversaryDigest}, nil
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
	if err := r.recoverImportsLocked(); err != nil {
		return err
	}
	ref, err := r.canonicalRef(reference)
	if err != nil || ref == "" {
		return fmt.Errorf("canonical reference required")
	}
	previous, readErr := r.referenceDigest(ref)
	if os.IsNotExist(readErr) {
		previous = ""
	} else if readErr != nil {
		return readErr
	}
	if previous != oldDigest {
		return ErrCAS
	}
	if previous == newDigest {
		return r.updateRef(ref, oldDigest, newDigest)
	}
	j := refMutationJournal{Version: 1, Reference: ref, Previous: previous, Next: newDigest}
	if err := r.saveRefMutationJournal(j); err != nil {
		return err
	}
	if err := r.updateRefWithHook(ref, oldDigest, newDigest, func() error {
		if refMutationHook != nil {
			return refMutationHook("after-write")
		}
		return nil
	}); err != nil {
		return errors.Join(err, r.rollbackRefMutation(j))
	}
	if err := r.commitRefMutation(j); err != nil {
		return errors.Join(err, r.rollbackRefMutation(j))
	}
	return nil
}
func (r Repository) updateRef(reference, oldDigest, newDigest string) error {
	return r.updateRefWithHook(reference, oldDigest, newDigest, nil)
}
func (r Repository) updateRefWithHook(reference, oldDigest, newDigest string, afterReference func() error) error {
	ref, err := r.canonicalRef(reference)
	if err != nil {
		return err
	}
	if ref == "" || newDigest == "" {
		return fmt.Errorf("nonempty canonical reference and target digest required")
	}
	if _, err := oci.ParseDigest(newDigest); err != nil {
		return err
	}
	_, err = r.loadRecordMode(newDigest, true, true)
	if err != nil {
		return fmt.Errorf("reference target does not exist: %w", err)
	}
	lock, err := publock.Acquire(r.Root, "repo-ref\x00"+ref)
	if err != nil {
		return err
	}
	defer lock.Close()
	path := "refs/" + key(ref) + ".json"
	var current struct{ Reference, Digest string }
	if digest, e := r.referenceDigestRaw(ref); e == nil {
		current.Reference, current.Digest = ref, digest
	} else if !os.IsNotExist(e) {
		return e
	}
	if current.Digest == newDigest {
		if afterReference != nil {
			if err := afterReference(); err != nil {
				return err
			}
		}
		return r.rebuildAliases()
	}
	if current.Digest != oldDigest {
		return ErrCAS
	}
	data, _ := json.Marshal(struct{ Reference, Digest string }{ref, newDigest})
	if err := r.atomic(path, data); err != nil {
		return err
	}
	var transitionErr error
	if afterReference != nil {
		transitionErr = afterReference()
	}
	if transitionErr == nil {
		transitionErr = r.rebuildAliases()
	}
	if transitionErr != nil {
		root, openErr := os.OpenRoot(r.Root)
		if openErr == nil {
			if current.Digest == "" {
				_ = root.Remove(path)
			} else {
				previous, _ := json.Marshal(struct{ Reference, Digest string }{ref, current.Digest})
				_ = r.atomic(path, previous)
			}
			_ = root.Close()
			_ = r.rebuildAliases()
		}
		return errors.Join(transitionErr, openErr)
	}
	return nil
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
	if err := r.recoverImportsLocked(); err != nil {
		return err
	}
	ref, err := r.canonicalRef(reference)
	if err != nil || ref == "" {
		return fmt.Errorf("canonical reference required")
	}
	digest, err := r.referenceDigest(ref)
	if err != nil {
		return err
	}
	if digest != oldDigest {
		return ErrCAS
	}
	j := refMutationJournal{Version: 1, Reference: ref, Previous: digest, Delete: true}
	if err := r.saveRefMutationJournal(j); err != nil {
		return err
	}
	if err := r.deleteRefLocked(ref, oldDigest); err != nil {
		return errors.Join(err, r.rollbackRefMutation(j))
	}
	if err := r.commitRefMutation(j); err != nil {
		return errors.Join(err, r.rollbackRefMutation(j))
	}
	return nil
}

func (r Repository) deleteRefLocked(ref, oldDigest string) error {
	lock, err := publock.Acquire(r.Root, "repo-ref\x00"+ref)
	if err != nil {
		return err
	}
	defer lock.Close()
	digest, err := r.referenceDigestRaw(ref)
	if err != nil {
		return err
	}
	current := struct{ Reference, Digest string }{ref, digest}
	if current.Digest != oldDigest {
		return ErrCAS
	}
	root, e := os.OpenRoot(r.Root)
	if e != nil {
		return e
	}
	defer root.Close()
	if err := root.Remove("refs/" + key(ref) + ".json"); err != nil {
		return err
	}
	if refMutationHook != nil {
		if err := refMutationHook("after-write"); err != nil {
			return err
		}
	}
	if err := r.rebuildAliases(); err != nil {
		encoded, _ := json.Marshal(current)
		restoreErr := r.atomic("refs/"+key(ref)+".json", encoded)
		_ = r.rebuildAliases()
		return errors.Join(err, restoreErr)
	}
	return nil
}
func (r Repository) Resolve(value string) (Record, error) {
	if isContentDigest(value) {
		return r.record(value)
	}
	if explicitReference(value) {
		ref, err := r.canonicalRef(value)
		if err != nil {
			return Record{}, err
		}
		if digest, e := r.referenceDigest(ref); e == nil {
			return r.record(digest)
		} else if os.IsNotExist(e) {
			return Record{}, e
		} else if !os.IsNotExist(e) {
			return Record{}, e
		}
	}
	list, err := r.readAlias(value)
	if (os.IsNotExist(err) || errors.Is(err, errLegacyAlias)) && !explicitReference(value) {
		return r.resolveStoredShorthand(value)
	}
	if err != nil {
		return Record{}, err
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
	if len(list) == 0 {
		return Record{}, ErrAmbiguous
	}
	if len(list) == 1 {
		return r.record(list[0])
	}
	records := make([]Record, 0, len(list))
	semanticKey := ""
	preferenceRoot := ""
	preferencesAgree := true
	for _, digest := range list {
		rec, loadErr := r.record(digest)
		if loadErr != nil {
			return Record{}, loadErr
		}
		candidateKey, keyErr := r.recordSemanticKey(rec)
		if keyErr != nil {
			return Record{}, keyErr
		}
		if semanticKey == "" {
			semanticKey = candidateKey
		} else if candidateKey != semanticKey {
			return Record{}, ErrAmbiguous
		}
		candidateRoot := rec.CanonicalAliasDigest
		if candidateRoot == "" {
			candidateRoot = rec.Digest
		}
		if preferenceRoot == "" {
			preferenceRoot = candidateRoot
		} else if candidateRoot != preferenceRoot {
			preferencesAgree = false
		}
		records = append(records, rec)
	}
	sort.Slice(records, func(i, j int) bool { return records[i].Digest < records[j].Digest })
	if preferencesAgree {
		for _, rec := range records {
			if rec.Digest == preferenceRoot {
				return rec, nil
			}
		}
	}
	return records[0], nil
}

func (r Repository) recordSemanticKey(rec Record) (string, error) {
	manifest, err := r.readLimit("manifests/"+key(rec.ManifestDigest), 4<<20)
	if err != nil {
		return "", err
	}
	if err := oci.VerifyDigest(manifest, rec.ManifestDigest); err != nil {
		return "", err
	}
	h := sha256.New()
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(manifest)))
	_, _ = h.Write(size[:])
	_, _ = h.Write(manifest)
	binary.BigEndian.PutUint64(size[:], uint64(len(rec.AdversaryManifestDigest)))
	_, _ = h.Write(size[:])
	_, _ = h.Write([]byte(rec.AdversaryManifestDigest))
	return fmt.Sprintf("sha256:%x", h.Sum(nil)), nil
}

func isContentDigest(value string) bool {
	_, err := oci.ParseDigest(value)
	return err == nil
}

// resolveStoredShorthand supports repositories created before tagged aliases
// were persisted. It derives candidates exclusively from durable ref records;
// process registry configuration is deliberately irrelevant. Multiple matches
// fail closed rather than selecting an arbitrary registry.
func (r Repository) resolveStoredShorthand(value string) (Record, error) {
	digests, err := r.storedShorthandDigests(value)
	if err != nil {
		return Record{}, err
	}
	if len(digests) == 0 {
		return Record{}, os.ErrNotExist
	}
	if len(digests) != 1 {
		return Record{}, ErrAmbiguous
	}
	return r.record(digests[0])
}

func (r Repository) storedShorthandDigests(value string) ([]string, error) {
	snapshot, err := r.referenceSnapshot()
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var digests []string
	for stored, digest := range snapshot {
		ref, err := oci.ParseReferenceWithDefaults(stored, oci.DefaultRegistry, oci.DefaultNamespace)
		if err != nil {
			return nil, fmt.Errorf("corrupt stored reference: %w", err)
		}
		short := ref.ShortName()
		if value == short || value == ref.Repository || value == short+":"+ref.Tag || value == ref.Repository+":"+ref.Tag {
			digests = append(digests, digest)
		}
	}
	digests = unique(digests)
	return digests, nil
}
func explicitReference(v string) bool {
	if strings.Contains(v, "@") {
		return true
	}
	first := v
	if i := strings.IndexByte(v, '/'); i >= 0 {
		first = v[:i]
		return strings.Contains(first, ".") || strings.Contains(first, ":") || first == "localhost" || strings.HasPrefix(first, "[")
	}
	return false
}
func (r Repository) record(d string) (Record, error) {
	return r.loadRecord(d, true)
}
func (r Repository) loadRecord(d string, requireCommit bool) (Record, error) {
	return r.loadRecordMode(d, requireCommit, false)
}
func (r Repository) loadRecordMode(d string, requireCommit, allowPending bool) (Record, error) {
	rec, err := r.loadRecordMetadataMode(d, requireCommit, allowPending)
	if err != nil {
		return rec, err
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
	derived, err := deriveRecord(manifest, config, adversary, rec.ManifestDigest, rec.ConfigDigest, rec.AdversaryManifestDigest)
	if err != nil {
		return rec, err
	}
	if rec.CanonicalAliasDigest != "" {
		if rec.CanonicalAliasDigest == rec.Digest {
			return rec, fmt.Errorf("canonical alias digest is self-referential")
		}
		if err := oci.VerifyDigest(manifest, rec.CanonicalAliasDigest); err != nil {
			return rec, fmt.Errorf("canonical alias digest mismatch: %w", err)
		}
		derived.CanonicalAliasDigest = rec.CanonicalAliasDigest
	}
	if derived != rec {
		return rec, fmt.Errorf("persisted record conflicts with artifact content")
	}
	return rec, nil
}

func (r Repository) loadRecordMetadata(d string, requireCommit bool) (Record, error) {
	return r.loadRecordMetadataMode(d, requireCommit, false)
}
func (r Repository) loadRecordMetadataMode(d string, requireCommit, allowPending bool) (Record, error) {
	if !allowPending {
		pending, err := r.pendingImport(d)
		if err != nil {
			return Record{}, err
		}
		if pending {
			return Record{}, os.ErrNotExist
		}
	}
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
func (r Repository) Repair(rec Record, sources map[string]blobsource.Source) error {
	lifecycle, err := publock.Acquire(r.Root, "repo-lifecycle")
	if err != nil {
		return err
	}
	defer lifecycle.Close()
	_, err = r.repairLocked(rec, sources)
	return err
}

func (r Repository) repairLocked(rec Record, sources map[string]blobsource.Source) (bool, error) {
	canonical, err := r.loadRecordMetadata(rec.Digest, true)
	if err != nil {
		return false, err
	}
	rec = canonical
	repaired := false
	manifestExpectation := repairExpectation{kind: "manifests", size: -1, limit: 4 << 20}
	if err := r.verifyContent("manifests", rec.ManifestDigest); err != nil {
		if err := r.repairComponent(rec.ManifestDigest, manifestExpectation, sources); err != nil {
			return false, err
		}
		repaired = true
	}
	expected, err := r.repairExpectations(rec)
	if err != nil {
		return false, err
	}
	delete(expected, rec.ManifestDigest)
	for d, expect := range expected {
		if err := r.verifyContent(expect.kind, d); err == nil {
			continue
		}
		if err := r.repairComponent(d, expect, sources); err != nil {
			return repaired, err
		}
		repaired = true
	}
	if _, err := r.record(rec.Digest); err != nil {
		return repaired, err
	}
	return repaired, nil
}

func (r Repository) repairComponent(d string, expect repairExpectation, sources map[string]blobsource.Source) error {
	source, ok := sources[d]
	if !ok || source == nil || source.Digest() != d {
		return fmt.Errorf("verified repair source missing for %s", d)
	}
	if source.Size() < 0 || source.Size() > expect.limit || (expect.size >= 0 && source.Size() != expect.size) {
		return fmt.Errorf("repair source %s has invalid size %d", d, source.Size())
	}
	contentLock, err := publock.Acquire(r.Root, "repo-content\x00"+d)
	if err != nil {
		return err
	}
	if err := r.replaceSource(expect.kind, source); err != nil {
		_ = contentLock.Close()
		return err
	}
	if err := r.verifyContent(expect.kind, d); err != nil {
		_ = contentLock.Close()
		return err
	}
	return contentLock.Close()
}

type repairExpectation struct {
	kind        string
	size, limit int64
}

func (r Repository) repairExpectations(rec Record) (map[string]repairExpectation, error) {
	manifestData, err := r.readLimit("manifests/"+key(rec.ManifestDigest), 4<<20)
	if err != nil {
		return nil, err
	}
	var manifest oci.Manifest
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		return nil, err
	}
	if len(manifest.Layers) != 1 || manifest.Config.Digest != rec.ConfigDigest || manifest.Layers[0].Digest != rec.LayerDigest {
		return nil, fmt.Errorf("canonical manifest descriptors conflict with record")
	}
	expected := map[string]repairExpectation{
		rec.ManifestDigest: {kind: "manifests", size: -1, limit: 4 << 20},
		rec.ConfigDigest:   {kind: "blobs", size: manifest.Config.Size, limit: 1 << 20},
		rec.LayerDigest:    {kind: "blobs", size: manifest.Layers[0].Size, limit: 256 << 20},
	}
	if rec.AdversaryManifestDigest != "" {
		expected[rec.AdversaryManifestDigest] = repairExpectation{kind: "adversary-manifests", size: -1, limit: 1 << 20}
	}
	for digest, item := range expected {
		if item.size < -1 || item.size > item.limit {
			return nil, fmt.Errorf("canonical descriptor %s has invalid size %d", digest, item.size)
		}
	}
	return expected, nil
}

func (r Repository) replaceSource(kind string, source blobsource.Source) (retErr error) {
	root, err := os.OpenRoot(r.Root)
	if err != nil {
		return err
	}
	defer func() { retErr = errors.Join(retErr, root.Close()) }()
	tmp := filepath.ToSlash(filepath.Join(kind, ".repair-"+nonce()))
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
	copyErr := copyVerifiedSource(f, source)
	closeErr := f.Close()
	if err := errors.Join(copyErr, closeErr); err != nil {
		return err
	}
	dst := filepath.ToSlash(filepath.Join(kind, key(source.Digest())))
	if err := rootreplace.Mutable(root, tmp, dst); err != nil {
		return err
	}
	cleanup = false
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
	for _, d := range []string{"blobs", "manifests", "adversary-manifests", "records", "refs", "aliases", "commits", "checkpoints", "materialized", "transactions"} {
		if err := root.MkdirAll(d, 0700); err != nil {
			return err
		}
	}
	return rootreplace.SyncDirectory(root, ".")
}
func (r Repository) addAlias(alias, digest string) error {
	lock, err := publock.Acquire(r.Root, "repo-alias\x00"+alias)
	if err != nil {
		return err
	}
	defer lock.Close()
	path := "aliases/" + key(alias) + ".json"
	var list []string
	if existing, e := r.readAlias(alias); e == nil {
		list = existing
	} else if errors.Is(e, errLegacyAlias) {
		// The authoritative records and refs are used below; legacy unauthenticated
		// targets are never trusted or copied into the new index.
	} else if !os.IsNotExist(e) {
		return e
	}
	list = append(list, digest)
	list = unique(list)
	data, _ := json.Marshal(aliasIndex{Version: 1, Alias: alias, Targets: list})
	return r.atomic(path, data)
}

func (r Repository) readAlias(alias string) ([]string, error) {
	info, err := os.Lstat(filepath.Join(r.Root, "aliases", key(alias)+".json"))
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("alias index is not a regular file")
	}
	data, err := r.readLimit("aliases/"+key(alias)+".json", maxIndexBytes)
	if err != nil {
		return nil, err
	}
	if len(data) > 0 && data[0] == '[' {
		return nil, errLegacyAlias
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var idx aliasIndex
	if err := dec.Decode(&idx); err != nil {
		return nil, fmt.Errorf("malformed alias index: %w", err)
	}
	if dec.Decode(&struct{}{}) != io.EOF || idx.Version != 1 || idx.Alias != alias || key(idx.Alias)+".json" != key(alias)+".json" || len(idx.Targets) == 0 || len(unique(idx.Targets)) != len(idx.Targets) {
		return nil, fmt.Errorf("alias index identity mismatch")
	}
	expected, err := r.authoritativeAliasTargets(alias)
	if err != nil {
		return nil, err
	}
	actual := unique(idx.Targets)
	if len(actual) != len(idx.Targets) || len(actual) != len(expected) {
		return nil, fmt.Errorf("alias target set does not match authoritative metadata")
	}
	for i := range actual {
		if actual[i] != expected[i] {
			return nil, fmt.Errorf("alias target set does not match authoritative metadata")
		}
	}
	return idx.Targets, nil
}

func (r Repository) authoritativeAliasTargets(alias string) ([]string, error) {
	all, err := r.authoritativeAliasMap(false)
	if err != nil {
		return nil, err
	}
	return all[alias], nil
}

func (r Repository) authoritativeAliasMap(allowPending bool) (map[string][]string, error) {
	records, err := r.scanRecordsMode(false, allowPending)
	if err != nil {
		return nil, err
	}
	refs, err := r.referenceSnapshotMode(allowPending)
	if err != nil {
		return nil, err
	}
	out := map[string][]string{}
	for _, rec := range records {
		for _, alias := range aliases(rec, "") {
			out[alias] = append(out[alias], rec.Digest)
		}
		for ref, digest := range refs {
			if digest == rec.Digest {
				for _, alias := range aliases(rec, ref) {
					out[alias] = append(out[alias], rec.Digest)
				}
			}
		}
	}
	for alias, targets := range out {
		out[alias] = unique(targets)
	}
	if len(out) > maxLifecycleEntries {
		return nil, fmt.Errorf("repository authoritative alias set exceeds lifecycle limit")
	}
	return out, nil
}

// pruneAliasTarget removes a GC'd digest from durable aliases. Callers hold
// the repository lifecycle lock, which excludes imports and other lifecycle
// mutations while the bounded index is scanned.
func (r Repository) pruneAliasTarget(digest string) error {
	root, err := os.OpenRoot(r.Root)
	if err != nil {
		return err
	}
	defer root.Close()
	entries, err := fs.ReadDir(root.FS(), "aliases")
	if err != nil {
		return err
	}
	if len(entries) > maxLifecycleEntries {
		return fmt.Errorf("repository alias index exceeds lifecycle limit")
	}
	for _, entry := range entries {
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() {
			return fmt.Errorf("invalid alias index entry %q", entry.Name())
		}
		name := entry.Name()
		data, err := r.read("aliases/" + name)
		if err != nil {
			return err
		}
		var idx aliasIndex
		if json.Unmarshal(data, &idx) != nil || idx.Version != 1 || key(idx.Alias)+".json" != name || len(idx.Targets) == 0 || len(unique(idx.Targets)) != len(idx.Targets) {
			return fmt.Errorf("malformed alias index %q", name)
		}
		current := idx.Targets
		next := make([]string, 0, len(current))
		for _, item := range current {
			if item != digest {
				next = append(next, item)
			}
		}
		if len(next) == len(current) {
			continue
		}
		if len(next) == 0 {
			if err := root.Remove("aliases/" + name); err != nil && !os.IsNotExist(err) {
				return err
			}
		} else {
			encoded, _ := json.Marshal(aliasIndex{Version: 1, Alias: idx.Alias, Targets: next})
			if err := r.atomic("aliases/"+name, encoded); err != nil {
				return err
			}
		}
	}
	return nil
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
	d, err := oci.ParseDigest(digest)
	if err != nil {
		return err
	}
	verifier := d.Verifier()
	n, err := io.Copy(verifier, io.LimitReader(f, (256<<20)+1))
	if err != nil {
		return err
	}
	if n > 256<<20 {
		return fmt.Errorf("content exceeds verification limit")
	}
	if !verifier.Verified() {
		return fmt.Errorf("digest mismatch")
	}
	return nil
}
func (r Repository) content(kind, d string) string { return filepath.Join(r.Root, kind, key(d)) }
func aliases(r Record, reference string) []string {
	out := []string{r.Name, r.Name + ":" + r.Version}
	if ref, err := oci.ParseReferenceWithDefaults(reference, oci.DefaultRegistry, oci.DefaultNamespace); err == nil {
		out = append(out, ref.ShortName(), ref.Repository)
		if ref.Tag != "" {
			out = append(out, ref.ShortName()+":"+ref.Tag, ref.Repository+":"+ref.Tag)
		}
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
			if os.IsNotExist(err) {
				continue
			}
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
