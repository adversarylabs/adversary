package pack

import (
	"fmt"

	"github.com/adversarylabs/adversary/pkg/blobsource"
	"github.com/adversarylabs/adversary/pkg/oci"
)

// Sources exposes the current packed bytes through the repeatable source
// contract. The subsequent migration will make Create produce file-backed
// sources directly; this compatibility adapter lets downstream code migrate
// first without changing Artifact.
func (a Artifact) Sources() ([]oci.SourceBlob, error) {
	if len(a.OCIManifest.Layers) != 1 {
		return nil, fmt.Errorf("packed artifact must have one layer")
	}
	config, err := oci.NewSourceBlob(a.OCIManifest.Config, blobsource.Bytes(a.Config))
	if err != nil {
		return nil, err
	}
	layerSource := blobsource.Source(blobsource.Bytes(a.Layer))
	if a.LayerSource != nil {
		layerSource = a.LayerSource
	}
	layer, err := oci.NewSourceBlob(a.OCIManifest.Layers[0], layerSource)
	if err != nil {
		return nil, err
	}
	return []oci.SourceBlob{config, layer}, nil
}
