package oci

import (
	"crypto/sha512"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func testDigest(algorithm, body string) string {
	switch algorithm {
	case "sha384":
		return fmt.Sprintf("sha384:%x", sha512.Sum384([]byte(body)))
	case "sha512":
		return fmt.Sprintf("sha512:%x", sha512.Sum512([]byte(body)))
	default:
		panic("unsupported test algorithm")
	}
}

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

func TestGetManifestAcceptsRegisteredDigestHeadersAndRequests(t *testing.T) {
	const body = "algorithm-agile manifest"
	for _, algorithm := range []string{"sha384", "sha512"} {
		t.Run(algorithm+" header", func(t *testing.T) {
			digest := testDigest(algorithm, body)
			r, ref := integrityRegistry(t, body, digest)
			_, got, err := r.getManifest(t.Context(), ref)
			if err != nil || got != digest {
				t.Fatalf("digest=%q err=%v", got, err)
			}
		})
		t.Run(algorithm+" request", func(t *testing.T) {
			digest := testDigest(algorithm, body)
			r, ref := integrityRegistry(t, body, "")
			ref.Digest = digest
			_, got, err := r.getManifest(t.Context(), ref)
			if err != nil || got != digest {
				t.Fatalf("digest=%q err=%v", got, err)
			}
		})
	}
}

func TestGetManifestAcceptsEquivalentRegisteredHeaderAndRequestDigests(t *testing.T) {
	const body = "dual-digest manifest"
	header := testDigest("sha384", body)
	requested := testDigest("sha512", body)
	r, ref := integrityRegistry(t, body, header)
	ref.Digest = requested
	_, got, err := r.getManifest(t.Context(), ref)
	if err != nil || got != requested {
		t.Fatalf("digest=%q err=%v", got, err)
	}
}

func TestGetArtifactManifestAcceptsRegisteredDigest(t *testing.T) {
	const body = "algorithm-agile artifact manifest"
	requested := testDigest("sha512", body)
	header := testDigest("sha384", body)
	r, ref := integrityRegistry(t, body, header)
	_, got, err := r.getArtifactManifest(t.Context(), ref, requested)
	if err != nil || got != requested {
		t.Fatalf("digest=%q err=%v", got, err)
	}
}

func TestPushManifestAcceptsRegisteredCanonicalDigestHeader(t *testing.T) {
	const body = "uploaded manifest"
	want := testDigest("sha512", body)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Fatalf("method=%s", r.Method)
		}
		w.Header().Set("Docker-Content-Digest", want)
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()
	r := &HTTPRegistry{Client: server.Client(), PlainHTTP: true}
	ref := Reference{Registry: strings.TrimPrefix(server.URL, "http://"), Repository: "test", Tag: "latest"}
	got, err := r.pushManifest(t.Context(), ref, ref.Tag, ImageManifestMediaType, []byte(body))
	if err != nil || got != want {
		t.Fatalf("digest=%q err=%v", got, err)
	}
}

func TestPushManifestRejectsRegisteredDigestHeaderMismatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Docker-Content-Digest", testDigest("sha384", "different"))
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()
	r := &HTTPRegistry{Client: server.Client(), PlainHTTP: true}
	ref := Reference{Registry: strings.TrimPrefix(server.URL, "http://"), Repository: "test", Tag: "latest"}
	if _, err := r.pushManifest(t.Context(), ref, ref.Tag, ImageManifestMediaType, []byte("uploaded manifest")); err == nil {
		t.Fatal("accepted mismatched registered digest header")
	}
}
