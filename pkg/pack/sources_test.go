package pack

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/adversarylabs/adversary/pkg/blobsource"
)

func TestArtifactSourcesAdaptPackedContent(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "adversary.yaml"), []byte("name: local/source\nversion: 1.0.0\nruntime:\n  name: node\n  version: \"22\"\n  command: [index.js]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "index.js"), []byte("export default {}"), 0600); err != nil {
		t.Fatal(err)
	}
	artifact, err := Create(context.Background(), Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	sources, err := artifact.Sources()
	if err != nil {
		t.Fatal(err)
	}
	if len(sources) != 2 {
		t.Fatalf("source count %d", len(sources))
	}
	for _, source := range sources {
		if err := blobsource.Verify(source.Source); err != nil {
			t.Fatal(err)
		}
	}
}
