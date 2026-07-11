package oci

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPullUsesVerifiedAdversaryManifestFallback(t *testing.T) {
	for _, tc := range []struct {
		name       string
		status     int
		referrers  ReferrersResponse
		linkHeader string
	}{
		{name: "unsupported-not-found", status: http.StatusNotFound},
		{name: "unsupported-method", status: http.StatusMethodNotAllowed},
		{name: "empty", status: http.StatusOK, referrers: ReferrersResponse{}},
		{name: "pagination", status: http.StatusOK, linkHeader: `</v2/acme/tool/referrers/next>; rel="next"`, referrers: ReferrersResponse{Manifests: []Descriptor{{ArtifactType: AdversaryManifestMediaType, Digest: Digest([]byte("ignored page artifact"))}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			registry, ref, wantYAML, requests := fallbackRegistry(t, tc.status, tc.referrers, tc.linkHeader, false)
			pulled, err := registry.PullSources(t.Context(), ref)
			if err != nil {
				t.Fatal(err)
			}
			defer pulled.Close()
			if string(pulled.AdversaryManifest) != string(wantYAML) {
				t.Fatalf("adversary manifest = %q, want %q", pulled.AdversaryManifest, wantYAML)
			}
			if pulled.ManifestDigest != Digest(pulled.RawManifest) {
				t.Fatalf("manifest digest = %s, content = %s", pulled.ManifestDigest, Digest(pulled.RawManifest))
			}
			if !strings.Contains(strings.Join(*requests, "\n"), ".adversary-manifest") {
				t.Fatalf("fallback tag not requested: %v", *requests)
			}
		})
	}
}

func TestPullRejectsMalformedFallbackArtifact(t *testing.T) {
	registry, ref, _, _ := fallbackRegistry(t, http.StatusNotFound, ReferrersResponse{}, "", true)
	if _, err := registry.PullSources(t.Context(), ref); err == nil || !strings.Contains(err.Error(), "invalid adversary manifest fallback artifact") {
		t.Fatalf("Pull error = %v, want malformed fallback rejection", err)
	}
}

func fallbackRegistry(t *testing.T, referrersStatus int, referrers ReferrersResponse, linkHeader string, malformed bool) (*HTTPRegistry, Reference, []byte, *[]string) {
	t.Helper()
	config := []byte(`{}`)
	layer := []byte("package layer")
	layerDescriptor := Descriptor{MediaType: PackageLayerMediaType, Digest: Digest(layer), Size: int64(len(layer))}
	manifestData, manifestDigest, _, err := NewManifest(config, layerDescriptor, nil)
	if err != nil {
		t.Fatal(err)
	}
	yaml := []byte("name: verified-fallback\nversion: 1.0.0\n")
	artifactData, _, artifact, err := NewAdversaryManifestArtifact(manifestDigest, yaml)
	if err != nil {
		t.Fatal(err)
	}
	if malformed {
		artifact.Subject.Digest = Digest([]byte("different subject"))
		artifactData, err = json.Marshal(artifact)
		if err != nil {
			t.Fatal(err)
		}
	}
	fallbackTag, err := AdversaryManifestArtifactTag(manifestDigest)
	if err != nil {
		t.Fatal(err)
	}
	requests := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.URL.RequestURI())
		path := r.URL.Path
		switch {
		case strings.HasSuffix(path, "/manifests/latest"):
			w.Header().Set("Docker-Content-Digest", manifestDigest)
			_, _ = w.Write(manifestData)
		case strings.HasSuffix(path, "/blobs/"+Digest(config)):
			_, _ = w.Write(config)
		case strings.HasSuffix(path, "/blobs/"+layerDescriptor.Digest):
			_, _ = w.Write(layer)
		case strings.Contains(path, "/referrers/"):
			if linkHeader != "" {
				w.Header().Set("Link", linkHeader)
			}
			w.WriteHeader(referrersStatus)
			if referrersStatus == http.StatusOK {
				_ = json.NewEncoder(w).Encode(referrers)
			}
		case strings.HasSuffix(path, "/manifests/"+fallbackTag):
			w.Header().Set("Docker-Content-Digest", Digest(artifactData))
			_, _ = w.Write(artifactData)
		case strings.HasSuffix(path, "/blobs/"+Digest(yaml)):
			_, _ = w.Write(yaml)
		default:
			http.Error(w, fmt.Sprintf("unexpected %s", r.URL.RequestURI()), http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	ref := Reference{Registry: strings.TrimPrefix(server.URL, "http://"), Repository: "acme/tool", Tag: "latest"}
	return &HTTPRegistry{Client: server.Client(), PlainHTTP: true}, ref, yaml, &requests
}
