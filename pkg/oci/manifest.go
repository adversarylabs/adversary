package oci

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
)

const (
	ImageManifestMediaType       = "application/vnd.oci.image.manifest.v1+json"
	DockerImageManifestMediaType = "application/vnd.docker.distribution.manifest.v2+json"
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
	digest, err := ParseDigest(imageDigest)
	if err != nil {
		return "", fmt.Errorf("invalid image digest %q: %w", imageDigest, err)
	}
	tag := digest.Algorithm().String() + "-" + digest.Encoded() + ".adversary-manifest"
	if len(tag) <= 128 {
		return tag, nil
	}
	// OCI tags are limited to 128 characters, so a literal SHA-512 digest does
	// not fit. Hash the canonical subject identity with a domain separator while
	// retaining the source algorithm in the tag. SHA-256 and SHA-384 keep the
	// established literal digest-derived convention above.
	projected := sha256.Sum256([]byte("adversary-referrer-fallback-v1\x00" + digest.String()))
	return fmt.Sprintf("%s-sha256-%x.adversary-manifest", digest.Algorithm(), projected), nil
}
