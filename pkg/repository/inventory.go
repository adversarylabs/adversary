package repository

import (
	"fmt"

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
	if _, err := r.validateStoredArtifactLayer(canonical); err != nil {
		return nil, fmt.Errorf("artifact semantic validation failed: %w", err)
	}
	data, err := r.readLimit("blobs/"+key(rec.ConfigDigest), 1<<20)
	if err != nil {
		return nil, err
	}
	if err := oci.VerifyDigest(data, rec.ConfigDigest); err != nil {
		return nil, fmt.Errorf("config digest mismatch: %w", err)
	}
	config, err := pack.DecodeArtifactConfig(data)
	if err != nil {
		return nil, fmt.Errorf("decode artifact inventory: %w", err)
	}
	files := append([]pack.File(nil), config.Files...)
	if files == nil {
		files = []pack.File{}
	}
	return files, nil
}
