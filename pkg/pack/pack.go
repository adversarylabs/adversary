package pack

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/adversarylabs/adversary/pkg/manifest"
	"github.com/adversarylabs/adversary/pkg/oci"
)

type Options struct {
	Dir          string
	NameOverride string
	Build        bool
	Builder      string
	Stdout       io.Writer
	Stderr       io.Writer
}

type BuildOptions struct {
	Dir     string
	Builder string
	Stdout  io.Writer
	Stderr  io.Writer
	Strict  bool
}

type Artifact struct {
	Name                    string
	ManifestName            string
	Version                 string
	Runtime                 string
	RuntimeName             string
	RuntimeVersion          string
	Entrypoint              []string
	Permissions             any
	Config                  []byte
	Layer                   []byte
	AdversaryManifest       []byte
	Manifest                []byte
	ManifestDigest          string
	AdversaryManifestDigest string
	ConfigDigest            string
	LayerDigest             string
	Size                    int64
	Files                   []File
	OCIManifest             oci.Manifest
}

type File struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
	Mode   int64  `json:"mode,omitempty"`
}

func Create(ctx context.Context, opts Options) (Artifact, error) {
	dir := opts.Dir
	if dir == "" {
		dir = "."
	}
	dir, err := filepath.Abs(dir)
	if err != nil {
		return Artifact{}, err
	}
	m, err := manifest.Load(filepath.Join(dir, manifest.FileName))
	if err != nil {
		return Artifact{}, err
	}
	adversaryManifest, err := os.ReadFile(filepath.Join(dir, manifest.FileName))
	if err != nil {
		return Artifact{}, err
	}
	if opts.Build {
		if err := BuildProject(ctx, BuildOptions{Dir: dir, Builder: opts.Builder, Stdout: opts.Stdout, Stderr: opts.Stderr}); err != nil {
			return Artifact{}, err
		}
	}
	files, err := collectFiles(dir)
	if err != nil {
		return Artifact{}, err
	}
	layer, err := buildLayer(dir, files)
	if err != nil {
		return Artifact{}, err
	}
	name := manifest.ShortName(m.Name)
	if strings.TrimSpace(opts.NameOverride) != "" {
		name, err = normalizeNameOverride(opts.NameOverride)
		if err != nil {
			return Artifact{}, err
		}
	}
	version := m.Version
	if version == "" {
		version = oci.DefaultTag
	}
	runtime := detectRuntime(dir, m)
	config, err := json.Marshal(struct {
		Created        string   `json:"created"`
		Name           string   `json:"name"`
		FullName       string   `json:"full_name"`
		Version        string   `json:"version"`
		Runtime        string   `json:"runtime"`
		RuntimeName    string   `json:"runtime_name,omitempty"`
		RuntimeVersion string   `json:"runtime_version,omitempty"`
		Entrypoint     []string `json:"entrypoint,omitempty"`
		Files          []File   `json:"files"`
	}{
		Created:        "1970-01-01T00:00:00Z",
		Name:           name,
		FullName:       m.Name,
		Version:        version,
		Runtime:        runtime,
		RuntimeName:    runtimeName(m),
		RuntimeVersion: m.Runtime.Version,
		Entrypoint:     m.Runtime.Command,
		Files:          files,
	})
	if err != nil {
		return Artifact{}, err
	}
	layerDescriptor := oci.Descriptor{
		MediaType: oci.PackageLayerMediaType,
		Digest:    oci.Digest(layer),
		Size:      int64(len(layer)),
		Annotations: map[string]string{
			"org.opencontainers.image.title": "adversary-layer",
		},
	}
	annotations := map[string]string{
		"org.opencontainers.image.title":   name,
		"org.opencontainers.image.version": version,
		"ai.adversary.name":                name,
		"ai.adversary.full_name":           m.Name,
		"ai.adversary.version":             version,
		"ai.adversary.runtime":             runtime,
		"ai.adversary.runtime.name":        runtimeName(m),
		"ai.adversary.runtime.version":     m.Runtime.Version,
	}
	manifestData, manifestDigest, ociManifest, err := oci.NewManifest(config, layerDescriptor, annotations)
	if err != nil {
		return Artifact{}, err
	}
	return Artifact{
		Name:                    name,
		ManifestName:            m.Name,
		Version:                 version,
		Runtime:                 runtime,
		RuntimeName:             runtimeName(m),
		RuntimeVersion:          m.Runtime.Version,
		Entrypoint:              m.Runtime.Command,
		Permissions:             m.Permissions,
		Config:                  config,
		Layer:                   layer,
		AdversaryManifest:       adversaryManifest,
		Manifest:                manifestData,
		ManifestDigest:          manifestDigest,
		AdversaryManifestDigest: oci.Digest(adversaryManifest),
		ConfigDigest:            oci.Digest(config),
		LayerDigest:             oci.Digest(layer),
		Size:                    int64(len(config) + len(layer) + len(manifestData)),
		Files:                   files,
		OCIManifest:             ociManifest,
	}, nil
}

func normalizeNameOverride(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", nil
	}
	if strings.Contains(name, "@") {
		return "", fmt.Errorf("--name must not include a digest")
	}
	lastSlash := strings.LastIndex(name, "/")
	lastColon := strings.LastIndex(name, ":")
	if lastColon > lastSlash {
		return "", fmt.Errorf("--name must not include a tag; version comes from adversary.yaml")
	}
	if _, err := oci.ParseReference(name); err != nil {
		return "", fmt.Errorf("invalid --name: %w", err)
	}
	return name, nil
}

func BuildProject(ctx context.Context, opts BuildOptions) error {
	dir := opts.Dir
	if dir == "" {
		dir = "."
	}
	dir, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(filepath.Join(dir, "package.json"))
	if err != nil {
		return nil
	}
	if !bytes.Contains(data, []byte(`"build"`)) {
		return nil
	}
	if _, err := os.Stat(filepath.Join(dir, "node_modules")); err != nil {
		if opts.Strict {
			return fmt.Errorf("build failed: node_modules was not found; run npm install or use --builder docker")
		}
		if opts.Builder == "" || opts.Builder == "local" {
			return nil
		}
	}
	builder := opts.Builder
	if builder == "" {
		builder = "local"
	}
	switch builder {
	case "local":
		return buildWithLocalNPM(ctx, dir, opts.Stdout, opts.Stderr)
	case "docker":
		return buildWithDocker(ctx, dir, opts.Stdout, opts.Stderr)
	default:
		return fmt.Errorf("unsupported builder %q; supported builders: local, docker", builder)
	}
}

func buildWithLocalNPM(ctx context.Context, dir string, stdout, stderr io.Writer) error {
	npm, err := findNPM()
	if err != nil {
		if _, statErr := os.Stat(filepath.Join(dir, "dist")); statErr == nil {
			if stderr != nil {
				fmt.Fprintf(stderr, "Skipping build: npm was not found, using existing dist/ output\n")
			}
			return nil
		}
		return fmt.Errorf("build failed: npm was not found; ensure npm is on PATH or build the project before packing")
	}
	cmd := exec.CommandContext(ctx, npm, "run", "build")
	cmd.Dir = dir
	if stdout == nil {
		stdout = os.Stdout
	}
	if stderr == nil {
		stderr = os.Stderr
	}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("build failed: %w", err)
	}
	return nil
}

func buildWithDocker(ctx context.Context, dir string, stdout, stderr io.Writer) error {
	docker, err := exec.LookPath("docker")
	if err != nil {
		return fmt.Errorf("build failed: docker was not found; install Docker or use --builder local")
	}
	tmp, err := os.MkdirTemp("", "adversary-pack-docker-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	dockerfile := filepath.Join(tmp, "Dockerfile")
	if err := os.WriteFile(dockerfile, []byte(dockerBuildfile()), 0644); err != nil {
		return err
	}
	outDir := filepath.Join(tmp, "out")
	cmd := exec.CommandContext(ctx, docker, "build", "--output", "type=local,dest="+outDir, "-f", dockerfile, dir)
	if stdout == nil {
		stdout = os.Stdout
	}
	if stderr == nil {
		stderr = os.Stderr
	}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("docker build failed: %w", err)
	}
	builtDist := filepath.Join(outDir, "dist")
	if info, err := os.Stat(builtDist); err != nil || !info.IsDir() {
		return fmt.Errorf("docker build did not produce dist/")
	}
	if err := os.RemoveAll(filepath.Join(dir, "dist")); err != nil {
		return err
	}
	return copyDir(builtDist, filepath.Join(dir, "dist"))
}

func dockerBuildfile() string {
	return `FROM node:22-alpine AS build
WORKDIR /workspace
COPY package*.json ./
RUN if [ -f package-lock.json ]; then npm ci; else npm install; fi
COPY . .
RUN npm run build

FROM scratch
COPY --from=build /workspace/dist /dist
`
}

func copyDir(src, dst string) error {
	return filepath.WalkDir(src, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if entry.IsDir() {
			return os.MkdirAll(target, 0755)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0644)
	})
}

func findNPM() (string, error) {
	if path, err := exec.LookPath("npm"); err == nil {
		return path, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	candidates := []string{
		filepath.Join(home, ".volta", "bin", "npm"),
		filepath.Join(home, ".asdf", "shims", "npm"),
	}
	nvmMatches, _ := filepath.Glob(filepath.Join(home, ".nvm", "versions", "node", "*", "bin", "npm"))
	sort.Sort(sort.Reverse(sort.StringSlice(nvmMatches)))
	candidates = append(nvmMatches, candidates...)
	for _, candidate := range candidates {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate, nil
		}
	}
	return "", exec.ErrNotFound
}

func collectFiles(dir string) ([]File, error) {
	ignore := loadIgnore(dir)
	var files []File
	err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == dir {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == manifest.FileName {
			return nil
		}
		if ignore.ignored(rel, entry.IsDir()) {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("unsupported package file type: %s", rel)
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		h := sha256.New()
		_, copyErr := io.CopyBuffer(h, f, make([]byte, 32<<10))
		closeErr := f.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		files = append(files, File{Path: rel, Size: info.Size(), SHA256: hex.EncodeToString(h.Sum(nil)), Mode: int64(info.Mode().Perm() & 0111)})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files, nil
}

func buildLayer(dir string, files []File) ([]byte, error) {
	var buf bytes.Buffer
	gz, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	gz.Name = ""
	gz.ModTime = time.Unix(0, 0).UTC()
	tw := tar.NewWriter(gz)
	defer tw.Close()
	defer gz.Close()
	for _, file := range files {
		f, err := os.Open(filepath.Join(dir, filepath.FromSlash(file.Path)))
		if err != nil {
			return nil, err
		}
		header := &tar.Header{
			Name:    file.Path,
			Mode:    0644 | file.Mode,
			Size:    file.Size,
			ModTime: time.Unix(0, 0).UTC(),
			Format:  tar.FormatPAX,
		}
		if err := tw.WriteHeader(header); err != nil {
			f.Close()
			return nil, err
		}
		if _, err := io.CopyBuffer(tw, f, make([]byte, 32<<10)); err != nil {
			f.Close()
			return nil, err
		}
		if err := f.Close(); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func detectRuntime(dir string, m manifest.Manifest) string {
	if _, err := os.Stat(filepath.Join(dir, "package.json")); err == nil {
		return "typescript"
	}
	if runtimeName(m) == "node" {
		return "typescript"
	}
	return "custom"
}

func runtimeName(m manifest.Manifest) string {
	name := strings.TrimSpace(m.Runtime.Name)
	if name == "typescript" {
		return "node"
	}
	if name != "" {
		return name
	}
	if len(m.Runtime.Command) > 0 && m.Runtime.Command[0] == "node" {
		return "node"
	}
	return ""
}

type ignoreRules []string

func loadIgnore(dir string) ignoreRules {
	rules := ignoreRules{
		"node_modules/", ".git/", ".env", ".env.*", ".DS_Store", "coverage/", "tmp/", ".cache/", "Dockerfile",
	}
	data, err := os.ReadFile(filepath.Join(dir, ".adversaryignore"))
	if err != nil {
		return rules
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		rules = append(rules, line)
	}
	return rules
}

func (rules ignoreRules) ignored(rel string, isDir bool) bool {
	base := filepath.Base(rel)
	for _, rule := range rules {
		rule = filepath.ToSlash(strings.TrimSpace(rule))
		if rule == "" {
			continue
		}
		dirRule := strings.HasSuffix(rule, "/")
		rule = strings.TrimSuffix(rule, "/")
		if dirRule && !isDir && !strings.HasPrefix(rel, rule+"/") {
			continue
		}
		if rel == rule || base == rule || strings.HasPrefix(rel, rule+"/") {
			return true
		}
		if ok, _ := filepath.Match(rule, rel); ok {
			return true
		}
		if ok, _ := filepath.Match(rule, base); ok {
			return true
		}
	}
	return false
}
