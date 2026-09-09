package application

import (
	"bytes"
	"context"
	"fmt"
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

// Exercise actual pull callbacks and expansion so concise output cannot skip work.
func TestExpandComposeCIProgress(t *testing.T) {
	for _, ci := range []string{"", "true"} {
		t.Run("CI="+ci, func(t *testing.T) {
			t.Setenv("CI", ci)
			root := t.TempDir()
			meta, leaf := filepath.Join(root, "meta"), filepath.Join(root, "leaf")
			writeComposePkg(t, meta, "meta", "uses:\n  - path: ../leaf\n")
			writeComposePkg(t, leaf, "leaf", "")
			resolver := &progressComposeResolver{path: meta}
			pulls := 0
			var output bytes.Buffer
			refs, _, err := ExpandCompose(t.Context(), resolver, func(context.Context, string) error {
				pulls++
				resolver.ready = true
				return nil
			}, []string{"registry.test/meta"}, false, &output)
			if err != nil || len(refs) != 2 || pulls != 1 {
				t.Fatalf("refs=%v pulls=%d err=%v", refs, pulls, err)
			}
			out := output.String()
			if !strings.Contains(out, "Compose: expanded 1 → 2 adversaries") {
				t.Fatalf("missing summary: %s", out)
			}
			for _, detail := range []string{"Compose: pulling", "  · "} {
				if strings.Contains(out, detail) != (ci == "") {
					t.Fatalf("unexpected detail %q: %s", detail, out)
				}
			}
			if ci != "" && !strings.HasPrefix(out, "Compose: preparing adversaries") {
				t.Fatalf("missing step: %s", out)
			}
		})
	}
}

type progressComposeResolver struct {
	Resolver
	path  string
	ready bool
}

func (r *progressComposeResolver) Resolve(context.Context, string) (Resolution, error) {
	if !r.ready {
		return Resolution{}, fmt.Errorf("not installed")
	}
	return Resolution{Path: r.path}, nil
}
