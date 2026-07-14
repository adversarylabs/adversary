package pack

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func BenchmarkCreateManyFilesRepository(b *testing.B) {
	dir := b.TempDir()
	manifest := "name: team/many-files\nversion: 1.0.0\nruntime:\n  name: node\n  version: '22'\n  command: [dist/index.js]\n"
	if err := os.WriteFile(filepath.Join(dir, "adversary.yaml"), []byte(manifest), 0o600); err != nil {
		b.Fatal(err)
	}
	for i := 0; i < 2_000; i++ {
		path := filepath.Join(dir, "src", fmt.Sprintf("group-%02d", i%32), fmt.Sprintf("file-%04d.ts", i))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			b.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(fmt.Sprintf("export const value%d = %d;\n", i, i)), 0o600); err != nil {
			b.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(dir, "dist"), 0o700); err != nil {
		b.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "dist", "index.js"), []byte("export {};\n"), 0o700); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		artifact, err := Create(context.Background(), Options{Dir: dir})
		if err != nil {
			b.Fatal(err)
		}
		if err := artifact.Close(); err != nil {
			b.Fatal(err)
		}
	}
}
