package oci

import (
	"encoding/json"
	"testing"
)

func TestNewAdversaryManifestArtifact(t *testing.T) {
	yaml := []byte("name: local/test\r\nversion: 0.1.0\n")
	imageDigest := "sha256:0123456789abcdef"

	data, digest, manifest, err := NewAdversaryManifestArtifact(imageDigest, yaml)
	if err != nil {
		t.Fatal(err)
	}
	if digest != Digest(data) {
		t.Fatalf("digest = %q, want %q", digest, Digest(data))
	}
	if manifest.MediaType != OCIArtifactManifestMediaType {
		t.Fatalf("mediaType = %q", manifest.MediaType)
	}
	if manifest.ArtifactType != AdversaryManifestMediaType {
		t.Fatalf("artifactType = %q", manifest.ArtifactType)
	}
	if manifest.Subject.MediaType != ImageManifestMediaType || manifest.Subject.Digest != imageDigest {
		t.Fatalf("subject = %#v", manifest.Subject)
	}
	if len(manifest.Blobs) != 1 {
		t.Fatalf("blobs = %d, want 1", len(manifest.Blobs))
	}
	blob := manifest.Blobs[0]
	if blob.MediaType != AdversaryManifestMediaType || blob.Digest != Digest(yaml) || blob.Size != int64(len(yaml)) {
		t.Fatalf("blob = %#v", blob)
	}

	var roundTrip ArtifactManifest
	if err := json.Unmarshal(data, &roundTrip); err != nil {
		t.Fatal(err)
	}
	if roundTrip.Blobs[0].Digest != Digest(yaml) {
		t.Fatalf("json blob digest = %q", roundTrip.Blobs[0].Digest)
	}
}

func TestAdversaryManifestArtifactTag(t *testing.T) {
	got, err := AdversaryManifestArtifactTag("sha256:abcdef")
	if err != nil {
		t.Fatal(err)
	}
	if got != "sha256-abcdef.adversary-manifest" {
		t.Fatalf("tag = %q", got)
	}
	if got == "0.1.0" {
		t.Fatal("artifact tag must not equal image tag")
	}
}
