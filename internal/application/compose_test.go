package application

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/adversarylabs/adversary/pkg/manifest"
)

func writeComposePkg(t *testing.T, dir, name, usesYAML string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := "name: " + name + "\nversion: 0.0.1\n" + usesYAML +
		"runtime:\n  name: node\n  version: \"22\"\n  command: [dist/index.js]\n"
	if err := os.WriteFile(filepath.Join(dir, manifest.FileName), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestExpandComposeLocalMetaPackage(t *testing.T) {
	root := t.TempDir()
	meta := filepath.Join(root, "go-meta")
	leafA := filepath.Join(root, "go-concurrency")
	leafB := filepath.Join(root, "go-security")
	writeComposePkg(t, leafA, "go/concurrency", "")
	writeComposePkg(t, leafB, "go/security", "")
	writeComposePkg(t, meta, "go", "uses:\n  - path: ../go-concurrency\n  - path: ../go-security\n")

	// Resolver unused for pure local path expansion.
	expanded, voice, err := ExpandCompose(context.Background(), nil, nil, []string{meta}, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(expanded) != 3 {
		t.Fatalf("refs %#v", expanded)
	}
	joined := strings.Join(expanded, "\n")
	if !strings.Contains(joined, "go-concurrency") || !strings.Contains(joined, "go-security") {
		t.Fatalf("%s", joined)
	}
	if len(voice) != 1 {
		t.Fatalf("voice roots %#v", voice)
	}
}

func TestExpandComposeNoCompose(t *testing.T) {
	refs := []string{"a", "b"}
	got, roots, err := ExpandCompose(context.Background(), nil, nil, refs, true, nil)
	if err != nil || len(got) != 2 || roots != nil {
		t.Fatalf("%v %#v %#v", err, got, roots)
	}
}
