package oci

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMetadataBatchAvoidsPayloadsAndChunks(t *testing.T) {
	calls := 0
	digest := "sha256:" + strings.Repeat("a", 64)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/v2/metadata" {
			t.Errorf("unexpected package request %s", r.URL)
			w.WriteHeader(500)
			return
		}
		refs := r.URL.Query()["ref"]
		if len(refs) > 16 {
			t.Error("unbounded batch")
		}
		items := []Metadata{}
		for _, ref := range refs {
			items = append(items, Metadata{Ref: ref, Digest: digest, Manifest: "detection:\n  files: ['**/*.go']"})
		}
		json.NewEncoder(w).Encode(map[string]any{"items": items})
	}))
	defer server.Close()
	registry := NewHTTPRegistry()
	registry.PlainHTTP = true
	refs := []Reference{}
	for i := 0; i < 33; i++ {
		refs = append(refs, Reference{Registry: strings.TrimPrefix(server.URL, "http://"), Repository: fmt.Sprintf("library/reviewer%d", i), Tag: "1.0.0"})
	}
	results := registry.MetadataBatch(context.Background(), refs)
	if len(results) != 33 || calls != 3 {
		t.Fatalf("results=%d requests=%d", len(results), calls)
	}
	for _, item := range results {
		if item.Digest != digest || item.Manifest == "" || item.Error != "" {
			t.Fatalf("bad metadata: %+v", item)
		}
	}
}
func TestMetadataBatchFallsBackForOlderRegistry(t *testing.T) {
	registry, ref, want, _ := fallbackRegistry(t, http.StatusNotFound, ReferrersResponse{}, "", false)
	got := registry.MetadataBatch(context.Background(), []Reference{ref})[ref.Locator()]
	if got.Error != "" || got.Manifest != string(want) {
		t.Fatalf("got %+v want %q", got, want)
	}
}
