package oci

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/adversarylabs/adversary/pkg/blobsource"
)

func TestPushSourcesReopensBodyForBearerRetry(t *testing.T) {
	data := []byte("repeatable upload")
	var puts, opens atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodHead:
			w.WriteHeader(http.StatusNotFound)
		case r.Method == http.MethodPost:
			w.Header().Set("Location", serverURL(r)+"/upload")
			w.WriteHeader(http.StatusAccepted)
		case r.Method == http.MethodPut:
			if puts.Add(1) == 1 {
				w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm=%q,service=%q`, serverURL(r)+"/token", r.Host))
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusCreated)
		case r.URL.Path == "/token":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"token":"ok"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	u, _ := url.Parse(server.URL)
	digest := Digest(data)
	src, _ := blobsource.New(int64(len(data)), digest, func() (io.ReadCloser, error) { opens.Add(1); return io.NopCloser(bytes.NewReader(data)), nil })
	r := NewHTTPRegistry()
	r.Client = server.Client()
	r.PlainHTTP = true
	ref := Reference{Registry: u.Host, Repository: "team/tool", Tag: "latest"}
	err := r.pushSourceBlob(context.Background(), ref, SourceBlob{Descriptor: Descriptor{Digest: digest, Size: int64(len(data))}, Source: src})
	if err != nil {
		t.Fatal(err)
	}
	if opens.Load() != 2 {
		t.Fatalf("opens=%d, want retry reopen", opens.Load())
	}
}

func TestGetBlobSourceCleansPartialFileOnDigestError(t *testing.T) {
	data := []byte("bad content")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(data) }))
	defer server.Close()
	u, _ := url.Parse(server.URL)
	var path string
	blobTempCreated = func(p string) { path = p }
	defer func() { blobTempCreated = nil }()
	r := NewHTTPRegistry()
	r.Client = server.Client()
	r.PlainHTTP = true
	_, err := r.getBlobSource(context.Background(), Reference{Registry: u.Host, Repository: "team/tool"}, Descriptor{MediaType: PackageLayerMediaType, Digest: Digest([]byte("different")), Size: int64(len(data))})
	if err == nil {
		t.Fatal("expected digest error")
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatalf("partial temp remains: %v", statErr)
	}
}

func TestGetBlobSourceJoinsTemporaryRemovalFailure(t *testing.T) {
	data := []byte("bad content")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(data) }))
	defer server.Close()
	u, _ := url.Parse(server.URL)
	injected := errors.New("remove failed")
	var path string
	blobTempCreated = func(p string) { path = p }
	removeBlobTemp = func(string) error { return injected }
	defer func() { blobTempCreated = nil; removeBlobTemp = os.Remove; _ = os.Remove(path) }()
	r := NewHTTPRegistry()
	r.Client = server.Client()
	r.PlainHTTP = true
	_, err := r.getBlobSource(context.Background(), Reference{Registry: u.Host, Repository: "team/tool"}, Descriptor{MediaType: PackageLayerMediaType, Digest: Digest([]byte("different")), Size: int64(len(data))})
	if !errors.Is(err, injected) {
		t.Fatalf("cleanup error not joined: %v", err)
	}
}

func TestGetBlobSourceJoinsTemporaryCloseFailureAndRemovesFile(t *testing.T) {
	data := []byte("valid content")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(data) }))
	defer server.Close()
	u, _ := url.Parse(server.URL)
	injected := errors.New("close failed")
	var path string
	blobTempCreated = func(p string) { path = p }
	closeBlobTemp = func(f *os.File) error { return errors.Join(f.Close(), injected) }
	defer func() {
		blobTempCreated = nil
		closeBlobTemp = func(f *os.File) error { return f.Close() }
		_ = os.Remove(path)
	}()
	r := NewHTTPRegistry()
	r.Client = server.Client()
	r.PlainHTTP = true
	_, err := r.getBlobSource(context.Background(), Reference{Registry: u.Host, Repository: "team/tool"}, Descriptor{MediaType: PackageLayerMediaType, Digest: Digest(data), Size: int64(len(data))})
	if !errors.Is(err, injected) {
		t.Fatalf("close error not joined: %v", err)
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatalf("temp remains after close failure: %v", statErr)
	}
}

func TestPullSourcesCleansAccumulatedDownloadsWhenLaterBlobFails(t *testing.T) {
	config, layer := []byte(`{"name":"x"}`), []byte("corrupt layer")
	layerDescriptor := Descriptor{MediaType: PackageLayerMediaType, Digest: Digest([]byte("expected layer")), Size: int64(len(layer))}
	manifestData, _, _, err := NewManifest(config, layerDescriptor, map[string]string{"ai.adversary.full_name": "team/x", "ai.adversary.version": "1.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/manifests/"):
			w.Header().Set("Docker-Content-Digest", Digest(manifestData))
			_, _ = w.Write(manifestData)
		case strings.HasSuffix(r.URL.Path, "/"+Digest(config)):
			_, _ = w.Write(config)
		case strings.HasSuffix(r.URL.Path, "/"+layerDescriptor.Digest):
			_, _ = w.Write(layer)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	u, _ := url.Parse(server.URL)
	var paths []string
	blobTempCreated = func(p string) { paths = append(paths, p) }
	defer func() { blobTempCreated = nil }()
	r := NewHTTPRegistry()
	r.Client = server.Client()
	r.PlainHTTP = true
	_, err = r.PullSources(context.Background(), Reference{Registry: u.Host, Repository: "team/x", Tag: "latest"})
	if err == nil {
		t.Fatal("expected later layer digest failure")
	}
	if len(paths) != 2 {
		t.Fatalf("created %d temporary files, want 2", len(paths))
	}
	for _, path := range paths {
		if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
			t.Fatalf("temporary file %s remains: %v", path, statErr)
		}
	}
}

func TestPullSourcesPreservesRegisteredManifestAndBlobDigests(t *testing.T) {
	config := []byte(`{"full_name":"team/agile","version":"1.0.0","name":"agile","files":[]}`)
	layer := []byte("algorithm-agile package layer")
	configDigest := testDigest("sha512", string(config))
	layerDigest := testDigest("sha384", string(layer))
	manifest := Manifest{
		SchemaVersion: 2,
		MediaType:     ImageManifestMediaType,
		ArtifactType:  ArtifactMediaType,
		Config:        Descriptor{MediaType: EmptyConfigMediaType, Digest: configDigest, Size: int64(len(config))},
		Layers:        []Descriptor{{MediaType: PackageLayerMediaType, Digest: layerDigest, Size: int64(len(layer))}},
	}
	manifestData, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifestDigest := testDigest("sha512", string(manifestData))

	var requested []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requested = append(requested, r.URL.Path)
		switch {
		case strings.HasSuffix(r.URL.Path, "/manifests/"+manifestDigest):
			w.Header().Set("Docker-Content-Digest", manifestDigest)
			_, _ = w.Write(manifestData)
		case strings.HasSuffix(r.URL.Path, "/blobs/"+configDigest):
			_, _ = w.Write(config)
		case strings.HasSuffix(r.URL.Path, "/blobs/"+layerDigest):
			_, _ = w.Write(layer)
		case strings.Contains(r.URL.Path, "/referrers/"):
			_, _ = w.Write([]byte(`{"manifests":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	u, _ := url.Parse(server.URL)
	r := NewHTTPRegistry()
	r.Client = server.Client()
	r.PlainHTTP = true
	pulled, err := r.PullSources(t.Context(), Reference{Registry: u.Host, Repository: "team/agile", Digest: manifestDigest})
	if err != nil {
		t.Fatal(err)
	}
	defer pulled.Close()
	if pulled.ManifestDigest != manifestDigest || len(pulled.Blobs) != 2 {
		t.Fatalf("pulled manifest=%s blobs=%d", pulled.ManifestDigest, len(pulled.Blobs))
	}
	if pulled.Blobs[0].Descriptor.Digest != configDigest || pulled.Blobs[1].Descriptor.Digest != layerDigest {
		t.Fatalf("blob digests=%#v", pulled.Blobs)
	}
	for _, blob := range pulled.Blobs {
		if err := blobsource.Verify(blob.Source); err != nil {
			t.Fatalf("verify %s: %v", blob.Descriptor.Digest, err)
		}
	}
	if !slices.Contains(requested, "/v2/team/agile/manifests/"+manifestDigest) || !slices.Contains(requested, "/v2/team/agile/blobs/"+configDigest) || !slices.Contains(requested, "/v2/team/agile/blobs/"+layerDigest) {
		t.Fatalf("generic digest paths not requested: %#v", requested)
	}
}

func TestCopyDescriptorStopsReaderWithNoProgress(t *testing.T) {
	if _, _, err := copyDescriptor(io.Discard, ociNoProgressReader{}, 1); !errors.Is(err, io.ErrNoProgress) {
		t.Fatalf("expected no-progress error, got %v", err)
	}
}

func TestCopyDescriptorRejectsInvalidReaderCounts(t *testing.T) {
	for _, count := range []int{-1, 2} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			if _, _, err := copyDescriptor(io.Discard, ociInvalidCountReader{count: count}, 1); err == nil || !strings.Contains(err.Error(), "invalid byte count") {
				t.Fatalf("count %d: %v", count, err)
			}
		})
	}
}

type ociNoProgressReader struct{}

func (ociNoProgressReader) Read([]byte) (int, error) { return 0, nil }

type ociInvalidCountReader struct{ count int }

func (r ociInvalidCountReader) Read([]byte) (int, error) { return r.count, nil }

func serverURL(r *http.Request) string { return "http://" + r.Host }
