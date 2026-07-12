package repository

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/adversarylabs/adversary/pkg/oci"
	"github.com/adversarylabs/adversary/pkg/pack"
)

// Inventory returns the immutable file inventory embedded in the verified OCI
// config. Config reads are bounded to 1 MiB and checked against both the record
// and descriptor before any metadata is returned.
func (r Repository) Inventory(rec Record) ([]pack.File, error) {
	canonical, err := r.record(rec.Digest)
	if err != nil {
		return nil, err
	}
	if canonical != rec {
		return nil, fmt.Errorf("record does not match committed artifact")
	}
	data, err := r.readLimit("blobs/"+key(rec.ConfigDigest), 1<<20)
	if err != nil {
		return nil, err
	}
	if oci.Digest(data) != rec.ConfigDigest {
		return nil, fmt.Errorf("config digest mismatch")
	}
	var config struct {
		Files *[]pack.File `json:"files"`
	}
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("decode artifact inventory: %w", err)
	}
	if config.Files == nil {
		return nil, fmt.Errorf("artifact config does not contain a file inventory")
	}
	files := make([]pack.File, len(*config.Files))
	copy(files, *config.Files)
	for i, f := range files {
		clean := path.Clean(f.Path)
		if f.Path == "" || clean != f.Path || clean == "." || strings.HasPrefix(f.Path, "/") || strings.Contains(f.Path, "\\") || strings.HasPrefix(f.Path, "../") {
			return nil, fmt.Errorf("invalid inventory path %q", f.Path)
		}
		if f.Size < 0 || (f.Mode != 0o644 && f.Mode != 0o755) {
			return nil, fmt.Errorf("invalid inventory metadata for %q", f.Path)
		}
		decoded, err := hex.DecodeString(f.SHA256)
		if err != nil || len(decoded) != 32 || f.SHA256 != strings.ToLower(f.SHA256) {
			return nil, fmt.Errorf("invalid inventory digest for %q", f.Path)
		}
		if i > 0 && files[i-1].Path >= f.Path {
			return nil, fmt.Errorf("inventory is not uniquely sorted")
		}
	}
	// Keep the contract defensive if an older producer emitted valid unsorted
	// inventory: do not silently reinterpret immutable metadata.
	if !sort.SliceIsSorted(files, func(i, j int) bool { return files[i].Path < files[j].Path }) {
		return nil, fmt.Errorf("inventory is not sorted")
	}
	return files, nil
}
