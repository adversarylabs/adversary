package oci

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func integrityRegistry(t *testing.T, body, header string) (*HTTPRegistry, Reference) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if header != "" {
			w.Header().Set("Docker-Content-Digest", header)
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return &HTTPRegistry{Client: srv.Client(), PlainHTTP: true}, Reference{Registry: strings.TrimPrefix(srv.URL, "http://"), Repository: "test"}
}

func TestGetManifestRejectsRequestedDigestSubstitution(t *testing.T) {
	r, ref := integrityRegistry(t, "substitute", "")
	ref.Digest = Digest([]byte("requested"))
	if _, _, err := r.getManifest(t.Context(), ref); err == nil {
		t.Fatal("accepted substituted digest content")
	}
}

func TestGetManifestRejectsDigestHeaderMismatch(t *testing.T) {
	body := "content"
	r, ref := integrityRegistry(t, body, Digest([]byte("other")))
	if _, _, err := r.getManifest(t.Context(), ref); err == nil {
		t.Fatal("accepted mismatched digest header")
	}
}

func TestGetArtifactManifestRejectsRequestedDigestSubstitution(t *testing.T) {
	r, ref := integrityRegistry(t, "substitute", Digest([]byte("substitute")))
	requested := Digest([]byte("requested"))
	if _, _, err := r.getArtifactManifest(t.Context(), ref, requested); err == nil {
		t.Fatal("accepted substituted artifact manifest")
	}
}
