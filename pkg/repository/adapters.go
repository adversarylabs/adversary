package repository

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

type Entry struct {
	Record             Record `json:"record"`
	CanonicalReference string `json:"canonicalReference"`
	Digest             string `json:"digest"`
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
	snapshot, err := r.referenceSnapshot()
	if err != nil {
		return "", err
	}
	var refs []string
	for ref, target := range snapshot {
		if target == digest {
			refs = append(refs, ref)
		}
	}
	if len(refs) == 0 {
		return "", os.ErrNotExist
	}
	sort.Strings(refs)
	return refs[0], nil
}

// CanonicalReferenceFor returns the exact durable reference committed for a
// caller's preferred spelling and verifies that it targets digest.
func (r Repository) CanonicalReferenceFor(digest, preferred string) (string, error) {
	ref, err := r.canonicalRef(preferred)
	if err != nil {
		return "", err
	}
	target, err := r.referenceDigest(ref)
	if err != nil {
		return "", err
	}
	if target != digest {
		return "", fmt.Errorf("committed reference identity mismatch")
	}
	return ref, nil
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

// ReferenceEntries enumerates every runnable reference instead of collapsing
// aliases by digest. Publisher trust is reference-scoped, so automatic
// selection must not treat two publishers pointing at identical bytes as one
// identity.
func (r Repository) ReferenceEntries(limit int) ([]Entry, error) {
	if limit <= 0 {
		limit = 10000
	}
	snapshot, err := r.referenceSnapshot()
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	refs := make([]string, 0, len(snapshot))
	for ref := range snapshot {
		refs = append(refs, ref)
	}
	sort.Strings(refs)
	if len(refs) > limit {
		refs = refs[:limit]
	}
	entries := make([]Entry, 0, len(refs))
	for _, ref := range refs {
		digest := snapshot[ref]
		record, err := r.record(digest)
		if err != nil {
			return nil, fmt.Errorf("read record for reference %q: %w", ref, err)
		}
		entries = append(entries, Entry{Record: record, CanonicalReference: ref, Digest: digest})
	}
	return entries, nil
}
func (r Repository) HasExact(value string) (bool, error) {
	if isContentDigest(value) {
		_, err := r.record(value)
		if err == nil {
			return true, nil
		}
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	if explicitReference(value) {
		ref, err := r.canonicalRef(value)
		if err != nil {
			return false, nil
		}
		if _, err := r.referenceDigest(ref); err == nil {
			return true, nil
		} else if !os.IsNotExist(err) {
			return false, err
		}
	}
	if digests, err := r.readAlias(value); err == nil {
		if len(digests) > 1 {
			return false, ErrAmbiguous
		}
		return true, nil
	} else if !os.IsNotExist(err) && !errors.Is(err, errLegacyAlias) {
		return false, err
	}
	if !explicitReference(value) {
		digests, err := r.storedShorthandDigests(value)
		if err != nil {
			return false, err
		}
		if len(digests) > 1 {
			return false, ErrAmbiguous
		}
		return len(digests) == 1, nil
	}
	return false, nil
}
