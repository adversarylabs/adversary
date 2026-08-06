package application

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/adversarylabs/adversary/pkg/compose"
	"github.com/adversarylabs/adversary/pkg/manifest"
)

// ComposePullFunc pulls an adversary ref into the local store (same as run auto-pull).
type ComposePullFunc func(ctx context.Context, ref string) error

// ExpandCompose expands adversary.yaml uses for explicit run refs.
// When noCompose is true, returns refs unchanged.
// VoiceRoots are absolute dirs for successfully loaded entry packages.
//
// Nodes that cannot be loaded are left as leaves (run will pull/fail later).
// Members that cannot be loaded still appear in the run list once enqueued.
func ExpandCompose(
	ctx context.Context,
	resolver Resolver,
	pull ComposePullFunc,
	refs []string,
	noCompose bool,
	progress io.Writer,
) (expanded []string, voiceRoots []string, err error) {
	if noCompose || len(refs) == 0 {
		return refs, nil, nil
	}
	loader := &composeLoader{
		ctx:      ctx,
		resolver: resolver,
		pull:     pull,
		stderr:   progress,
		pulled:   map[string]bool{},
	}
	result, err := compose.Expand(refs, loader, compose.Options{})
	if err != nil {
		return nil, nil, err
	}
	if result.Expanded && progress != nil {
		fmt.Fprintf(progress, "Compose: expanded %d → %d adversaries\n", len(refs), len(result.Refs))
		for _, r := range result.Refs {
			fmt.Fprintf(progress, "  · %s\n", r)
		}
	}
	return result.Refs, result.VoiceRoots, nil
}

type composeLoader struct {
	ctx      context.Context
	resolver Resolver
	pull     ComposePullFunc
	stderr   io.Writer
	pulled   map[string]bool
}

func (l *composeLoader) Load(ref string) (manifest.Manifest, string, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return manifest.Manifest{}, "", fmt.Errorf("empty reference")
	}
	if dir, ok := localPackageDir(ref); ok {
		m, err := manifest.Load(filepath.Join(dir, manifest.FileName))
		return m, dir, err
	}
	if l.resolver == nil {
		return manifest.Manifest{}, "", fmt.Errorf("resolve %q: no resolver", ref)
	}

	res, err := l.resolver.Resolve(l.ctx, ref)
	if err != nil || strings.TrimSpace(res.Path) == "" {
		if l.pull != nil && !l.pulled[ref] {
			l.pulled[ref] = true
			if l.stderr != nil {
				fmt.Fprintf(l.stderr, "Compose: pulling %s…\n", ref)
			}
			if pullErr := l.pull(l.ctx, ref); pullErr != nil {
				if err != nil {
					return manifest.Manifest{}, "", fmt.Errorf("resolve %q: %w (pull: %v)", ref, err, pullErr)
				}
				return manifest.Manifest{}, "", fmt.Errorf("resolve %q after pull failed: %w", ref, pullErr)
			}
			res, err = l.resolver.Resolve(l.ctx, ref)
		}
		if err != nil {
			return manifest.Manifest{}, "", fmt.Errorf("resolve %q: %w", ref, err)
		}
	}
	path := strings.TrimSpace(res.Path)
	if path == "" {
		return manifest.Manifest{}, "", fmt.Errorf("resolve %q: empty package path", ref)
	}
	dir := path
	if st, err := os.Stat(path); err == nil && !st.IsDir() {
		dir = filepath.Dir(path)
	}
	yamlPath := filepath.Join(dir, manifest.FileName)
	if _, err := os.Stat(yamlPath); err != nil {
		if strings.HasSuffix(path, manifest.FileName) {
			yamlPath = path
			dir = filepath.Dir(path)
		} else {
			return manifest.Manifest{}, "", fmt.Errorf("package %q missing %s", ref, manifest.FileName)
		}
	}
	m, err := manifest.Load(yamlPath)
	if err != nil {
		return manifest.Manifest{}, "", err
	}
	return m, dir, nil
}

func localPackageDir(ref string) (string, bool) {
	candidates := []string{ref}
	if !filepath.IsAbs(ref) {
		if abs, err := filepath.Abs(ref); err == nil {
			candidates = append(candidates, abs)
		}
	}
	for _, c := range candidates {
		st, err := os.Stat(c)
		if err != nil {
			continue
		}
		dir := c
		if !st.IsDir() {
			if filepath.Base(c) != manifest.FileName {
				continue
			}
			dir = filepath.Dir(c)
		}
		if _, err := os.Stat(filepath.Join(dir, manifest.FileName)); err == nil {
			abs, err := filepath.Abs(dir)
			if err != nil {
				return dir, true
			}
			return abs, true
		}
	}
	return "", false
}
