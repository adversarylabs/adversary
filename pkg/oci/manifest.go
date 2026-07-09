package oci

import "encoding/json"

const (
	ImageManifestMediaType = "application/vnd.oci.image.manifest.v1+json"
	EmptyConfigMediaType   = "application/vnd.adversarylabs.adversary.config.v1+json"
	ArtifactMediaType      = "application/vnd.adversarylabs.adversary.manifest.v1+json"
	PackageLayerMediaType  = "application/vnd.adversarylabs.adversary.layer.v1.tar+gzip"
)

type Manifest struct {
	SchemaVersion int               `json:"schemaVersion"`
	MediaType     string            `json:"mediaType"`
	ArtifactType  string            `json:"artifactType,omitempty"`
	Config        Descriptor        `json:"config"`
	Layers        []Descriptor      `json:"layers"`
	Annotations   map[string]string `json:"annotations,omitempty"`
}

type PulledArtifact struct {
	Reference      Reference
	Manifest       Manifest
	ManifestDigest string
	Blobs          map[string][]byte
}

func NewManifest(config []byte, layer Descriptor, annotations map[string]string) ([]byte, string, Manifest, error) {
	configDescriptor := Descriptor{
		MediaType: EmptyConfigMediaType,
		Digest:    Digest(config),
		Size:      int64(len(config)),
	}
	manifest := Manifest{
		SchemaVersion: 2,
		MediaType:     ImageManifestMediaType,
		ArtifactType:  ArtifactMediaType,
		Config:        configDescriptor,
		Layers:        []Descriptor{layer},
		Annotations:   annotations,
	}
	data, err := json.Marshal(manifest)
	if err != nil {
		return nil, "", Manifest{}, err
	}
	return data, Digest(data), manifest, nil
}
