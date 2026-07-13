package cmd

import (
	"crypto/sha512"
	"fmt"
	"testing"

	"github.com/adversarylabs/adversary/pkg/blobsource"
	"github.com/adversarylabs/adversary/pkg/oci"
)

func TestPulledMetadataSourcesPreserveVerifiedRegisteredDigests(t *testing.T) {
	manifest := []byte("raw OCI manifest")
	adversaryManifest := []byte("name: team/agile\nversion: 1.0.0\n")
	manifestDigest := fmt.Sprintf("sha512:%x", sha512.Sum512(manifest))
	for _, tc := range []struct {
		name, digest string
	}{
		{"sha384 attached", fmt.Sprintf("sha384:%x", sha512.Sum384(adversaryManifest))},
		{"sha512 attached", fmt.Sprintf("sha512:%x", sha512.Sum512(adversaryManifest))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			manifestSource, adversarySource, err := pulledMetadataSources(&oci.PulledSources{
				RawManifest:             manifest,
				ManifestDigest:          manifestDigest,
				AdversaryManifest:       adversaryManifest,
				AdversaryManifestDigest: tc.digest,
			})
			if err != nil {
				t.Fatal(err)
			}
			if manifestSource.Digest() != manifestDigest || adversarySource.Digest() != tc.digest {
				t.Fatalf("digests normalized: manifest=%s adversary=%s", manifestSource.Digest(), adversarySource.Digest())
			}
			if err := blobsource.Verify(manifestSource); err != nil {
				t.Fatal(err)
			}
			if err := blobsource.Verify(adversarySource); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPulledMetadataSourcesRejectMissingAttachedDigest(t *testing.T) {
	manifest := []byte("raw OCI manifest")
	manifestDigest := fmt.Sprintf("sha512:%x", sha512.Sum512(manifest))
	if _, _, err := pulledMetadataSources(&oci.PulledSources{
		RawManifest:       manifest,
		ManifestDigest:    manifestDigest,
		AdversaryManifest: []byte("attached"),
	}); err == nil {
		t.Fatal("accepted attached manifest without verified descriptor digest")
	}
}

func TestPulledMetadataSourcesRejectDigestMismatch(t *testing.T) {
	manifest := []byte("raw OCI manifest")
	manifestDigest := fmt.Sprintf("sha512:%x", sha512.Sum512(manifest))
	wrongDigest := fmt.Sprintf("sha512:%x", sha512.Sum512([]byte("different")))
	for _, tc := range []struct {
		name     string
		artifact oci.PulledSources
	}{
		{"manifest", oci.PulledSources{RawManifest: manifest, ManifestDigest: wrongDigest}},
		{"attached manifest", oci.PulledSources{RawManifest: manifest, ManifestDigest: manifestDigest, AdversaryManifest: []byte("attached"), AdversaryManifestDigest: wrongDigest}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := pulledMetadataSources(&tc.artifact); err == nil {
				t.Fatal("accepted bytes that do not match the verified digest")
			}
		})
	}
}
