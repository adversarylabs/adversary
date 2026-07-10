package oci

import "testing"

func TestValidatePulledManifestRejectsNonPackageLayouts(t *testing.T) {
	valid := Manifest{SchemaVersion: 2, MediaType: ImageManifestMediaType, ArtifactType: ArtifactMediaType, Config: Descriptor{MediaType: EmptyConfigMediaType}, Layers: []Descriptor{{MediaType: PackageLayerMediaType}}}
	if err := validatePulledManifest(valid); err != nil {
		t.Fatal(err)
	}
	tests := []Manifest{
		{SchemaVersion: 2, MediaType: ImageManifestMediaType, Config: valid.Config, Layers: valid.Layers},
		{SchemaVersion: 2, ArtifactType: ArtifactMediaType, Config: Descriptor{MediaType: "application/vnd.oci.image.config.v1+json"}, Layers: valid.Layers},
		{SchemaVersion: 2, ArtifactType: ArtifactMediaType, Config: valid.Config, Layers: []Descriptor{{MediaType: "application/vnd.oci.image.layer.v1.tar+gzip"}}},
		{SchemaVersion: 2, ArtifactType: ArtifactMediaType, Config: valid.Config, Layers: append(valid.Layers, valid.Layers[0])},
	}
	for i, manifest := range tests {
		if err := validatePulledManifest(manifest); err == nil {
			t.Fatalf("case %d accepted", i)
		}
	}
}

func TestReadLimited(t *testing.T) {
	if _, err := readLimited(&endlessByteReader{}, 32, "test"); err == nil {
		t.Fatal("oversized response accepted")
	}
}

type endlessByteReader struct{}

func (*endlessByteReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'x'
	}
	return len(p), nil
}
