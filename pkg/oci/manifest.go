package oci

import (
	"encoding/json"
	"fmt"
	"strings"
)

const (
	ImageManifestMediaType       = "application/vnd.oci.image.manifest.v1+json"
	OCIArtifactManifestMediaType = "application/vnd.oci.artifact.manifest.v1+json"
	AdversaryManifestMediaType   = "application/vnd.adversarylabs.manifest.v1+yaml"
	EmptyConfigMediaType         = "application/vnd.adversarylabs.adversary.config.v1+json"
	ArtifactMediaType            = "application/vnd.adversarylabs.adversary.manifest.v1+json"
	PackageLayerMediaType        = "application/vnd.adversarylabs.adversary.layer.v1.tar+gzip"
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
	Reference         Reference
	RawManifest       []byte
	Manifest          Manifest
	ManifestDigest    string
	AdversaryManifest []byte
	Blobs             map[string][]byte
}

type ArtifactManifest struct {
	MediaType    string            `json:"mediaType"`
	ArtifactType string            `json:"artifactType"`
	Subject      Descriptor        `json:"subject"`
	Blobs        []Descriptor      `json:"blobs"`
	Annotations  map[string]string `json:"annotations,omitempty"`
}

type ReferrersResponse struct {
	Manifests []Descriptor `json:"manifests"`
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

func NewAdversaryManifestArtifact(imageDigest string, yaml []byte) ([]byte, string, ArtifactManifest, error) {
	artifact := ArtifactManifest{
		MediaType:    OCIArtifactManifestMediaType,
		ArtifactType: AdversaryManifestMediaType,
		Subject: Descriptor{
			MediaType: ImageManifestMediaType,
			Digest:    imageDigest,
		},
		Blobs: []Descriptor{
			{
				MediaType: AdversaryManifestMediaType,
				Digest:    Digest(yaml),
				Size:      int64(len(yaml)),
			},
		},
		Annotations: map[string]string{
			"org.opencontainers.image.title": "adversary.yaml",
		},
	}
	data, err := json.Marshal(artifact)
	if err != nil {
		return nil, "", ArtifactManifest{}, err
	}
	return data, Digest(data), artifact, nil
}

func AdversaryManifestArtifactTag(imageDigest string) (string, error) {
	const prefix = "sha256:"
	hexValue := strings.TrimPrefix(imageDigest, prefix)
	if hexValue == imageDigest || hexValue == "" {
		return "", fmt.Errorf("invalid image digest %q", imageDigest)
	}
	return "sha256-" + hexValue + ".adversary-manifest", nil
}
