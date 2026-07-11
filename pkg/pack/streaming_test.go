package pack

import (
	"context"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/adversarylabs/adversary/pkg/blobsource"
)

func BenchmarkCreateStreamingLargeLayer(b *testing.B) {
	dir := b.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "adversary.yaml"), []byte("name: team/benchmark\nversion: 1.0.0\nruntime:\n  name: node\n  version: '22'\n  command: [index.js]\n"), 0600); err != nil {
		b.Fatal(err)
	}
	f, err := os.Create(filepath.Join(dir, "payload.bin"))
	if err != nil {
		b.Fatal(err)
	}
	chunk := make([]byte, 1<<20)
	random := rand.New(rand.NewSource(19019))
	for i := 0; i < 64; i++ {
		_, _ = random.Read(chunk)
		if _, err := f.Write(chunk); err != nil {
			b.Fatal(err)
		}
	}
	if err := f.Close(); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.SetBytes(64 << 20)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		a, err := Create(context.Background(), Options{Dir: dir, Streaming: true})
		if err != nil {
			b.Fatal(err)
		}
		if len(a.Layer) != 0 {
			b.Fatal("streaming benchmark materialized the layer")
		}
		if err := a.Close(); err != nil {
			b.Fatal(err)
		}
	}
}

func TestCreateStreamingAllocationStaysBoundedForIncompressibleLayer(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "adversary.yaml"), []byte("name: team/allocation\nversion: 1.0.0\nruntime:\n  name: node\n  version: '22'\n  command: [index.js]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(filepath.Join(dir, "payload.bin"))
	if err != nil {
		t.Fatal(err)
	}
	chunk := make([]byte, 1<<20)
	random := rand.New(rand.NewSource(19019))
	for i := 0; i < 64; i++ {
		_, _ = random.Read(chunk)
		if _, err := f.Write(chunk); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	a, err := Create(context.Background(), Options{Dir: dir, Streaming: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Layer) != 0 {
		t.Fatal("streaming create retained whole layer")
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	runtime.ReadMemStats(&after)
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 8<<20 {
		t.Fatalf("streaming 64 MiB layer allocated %d bytes, want <= 8 MiB", allocated)
	}
}

func TestCreateStreamingUsesOwnedRepeatableLayer(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "adversary.yaml"), []byte("name: team/streaming\nversion: 1.0.0\nruntime:\n  name: node\n  version: '22'\n  command: [index.js]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "index.js"), make([]byte, 8<<20), 0600); err != nil {
		t.Fatal(err)
	}
	a, err := Create(context.Background(), Options{Dir: dir, Streaming: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Layer) != 0 || a.LayerSource == nil {
		t.Fatalf("streaming layer materialized: bytes=%d source=%v", len(a.Layer), a.LayerSource)
	}
	if err := blobsource.Verify(a.LayerSource); err != nil {
		t.Fatal(err)
	}
	r1, err := a.LayerSource.Open()
	if err != nil {
		t.Fatal(err)
	}
	_ = r1.Close()
	r2, err := a.LayerSource.Open()
	if err != nil {
		t.Fatal(err)
	}
	_ = r2.Close()
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := a.LayerSource.Open(); err == nil {
		t.Fatal("owned source opened after cleanup")
	}
}
