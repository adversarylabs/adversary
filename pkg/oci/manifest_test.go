package oci

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
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
	sha256Digest := "sha256:" + strings.Repeat("a", 64)
	got, err := AdversaryManifestArtifactTag(sha256Digest)
	if err != nil {
		t.Fatal(err)
	}
	if got != "sha256-"+strings.Repeat("a", 64)+".adversary-manifest" {
		t.Fatalf("tag = %q", got)
	}
	for _, digest := range []string{
		"sha384:" + strings.Repeat("b", 96),
		"sha512:" + strings.Repeat("c", 128),
	} {
		tag, err := AdversaryManifestArtifactTag(digest)
		if err != nil {
			t.Fatal(err)
		}
		if len(tag) > 128 {
			t.Fatalf("tag length=%d: %q", len(tag), tag)
		}
		if _, err := ParseReferenceWithDefaults("example.invalid/team/tool:"+tag, DefaultRegistry, DefaultNamespace); err != nil {
			t.Fatalf("tag does not pass reference grammar: %q: %v", tag, err)
		}
	}
	sha512Digest := "sha512:" + strings.Repeat("c", 128)
	got, err = AdversaryManifestArtifactTag(sha512Digest)
	if err != nil {
		t.Fatal(err)
	}
	projected := sha256.Sum256([]byte("adversary-referrer-fallback-v1\x00" + sha512Digest))
	want := fmt.Sprintf("sha512-sha256-%x.adversary-manifest", projected)
	if got != want {
		t.Fatalf("sha512 tag = %q", got)
	}
	if got == "0.1.0" {
		t.Fatal("artifact tag must not equal image tag")
	}
}
