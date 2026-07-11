package oci

import (
	"fmt"

	"github.com/adversarylabs/adversary/pkg/blobsource"
)

// SourceBlob is the streaming counterpart to Blob. Source must report the
// descriptor size and digest; consumers may reopen it for authenticated HTTP
// retries. This additive type does not change Registry yet.
type SourceBlob struct {
	Descriptor Descriptor
	Source     blobsource.Source
}

// NewSourceBlob validates metadata without reading content. Consumers must use
// blobsource.Verify while ingesting or before publishing untrusted sources.
func NewSourceBlob(descriptor Descriptor, source blobsource.Source) (SourceBlob, error) {
	if source == nil {
		return SourceBlob{}, fmt.Errorf("blob source is required")
	}
	if source.Size() != descriptor.Size || source.Digest() != descriptor.Digest {
		return SourceBlob{}, fmt.Errorf("blob source conflicts with descriptor")
	}
	if _, err := ParseDigest(descriptor.Digest); err != nil {
		return SourceBlob{}, err
	}
	return SourceBlob{Descriptor: descriptor, Source: source}, nil
}

// Source adapts the legacy in-memory blob without copying it.
func (b Blob) Source() (SourceBlob, error) {
	return NewSourceBlob(b.Descriptor, blobsource.Bytes(b.Data))
}
