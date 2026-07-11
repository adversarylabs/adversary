package repository

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/adversarylabs/adversary/pkg/oci"
)

type Entry struct {
	Record             Record `json:"record"`
	CanonicalReference string `json:"canonicalReference"`
	Digest             string `json:"digest"`
}

func (r Repository) Payload(rec Record) ([]byte, []oci.Blob, []byte, error) {
	canonical, err := r.record(rec.Digest)
	if err != nil {
		return nil, nil, nil, err
	}
	manifest, err := r.readLimit("manifests/"+key(canonical.ManifestDigest), 4<<20)
	if err != nil {
		return nil, nil, nil, err
	}
	config, err := r.readLimit("blobs/"+key(canonical.ConfigDigest), 1<<20)
	if err != nil {
		return nil, nil, nil, err
	}
	layer, err := r.readLimit("blobs/"+key(canonical.LayerDigest), 256<<20)
	if err != nil {
		return nil, nil, nil, err
	}
	var adversary []byte
	if canonical.AdversaryManifestDigest != "" {
		adversary, err = r.readLimit("adversary-manifests/"+key(canonical.AdversaryManifestDigest), 1<<20)
		if err != nil {
			return nil, nil, nil, err
		}
	}
	var m oci.Manifest
	if err := json.Unmarshal(manifest, &m); err != nil {
		return nil, nil, nil, err
	}
	return manifest, []oci.Blob{{Descriptor: m.Config, Data: config}, {Descriptor: m.Layers[0], Data: layer}}, adversary, nil
}
func (r Repository) List(limit int) ([]Record, error) {
	if limit <= 0 {
		limit = 10000
	}
	records, err := r.Enumerate("", limit)
	if os.IsNotExist(err) {
		return nil, nil
	}
	sort.Slice(records, func(i, j int) bool {
		return records[i].Name < records[j].Name || records[i].Name == records[j].Name && records[i].Version < records[j].Version
	})
	return records, err
}
func (r Repository) RootPath() string { return filepath.Clean(r.Root) }
func (r Repository) CanonicalReference(digest string) (string, error) {
	root, err := os.OpenRoot(r.Root)
	if err != nil {
		return "", err
	}
	defer root.Close()
	entries, err := fs.ReadDir(root.FS(), "refs")
	if err != nil {
		return "", err
	}
	var refs []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		data, err := r.read("refs/" + entry.Name())
		if err != nil {
			return "", err
		}
		var idx struct{ Reference, Digest string }
		if json.Unmarshal(data, &idx) != nil || idx.Reference == "" || key(idx.Reference)+".json" != entry.Name() {
			return "", fmt.Errorf("corrupt reference index %q", entry.Name())
		}
		if idx.Digest == digest {
			refs = append(refs, idx.Reference)
		}
	}
	if len(refs) == 0 {
		return "", os.ErrNotExist
	}
	sort.Strings(refs)
	return refs[0], nil
}
func (r Repository) Entries(limit int) ([]Entry, error) {
	records, err := r.List(limit)
	if err != nil {
		return nil, err
	}
	out := make([]Entry, 0, len(records))
	for _, rec := range records {
		ref, err := r.CanonicalReference(rec.Digest)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		out = append(out, Entry{Record: rec, CanonicalReference: ref, Digest: rec.Digest})
	}
	return out, nil
}
func (r Repository) HasExact(value string) (bool, error) {
	if strings.HasPrefix(value, "sha256:") {
		_, err := r.read("commits/" + key(value) + ".json")
		if err == nil {
			return true, nil
		}
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	ref, err := canonicalRef(value)
	if err != nil {
		return false, nil
	}
	_, err = r.read("refs/" + key(ref) + ".json")
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}
