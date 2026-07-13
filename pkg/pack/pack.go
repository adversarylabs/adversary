package pack

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	internalpaths "github.com/adversarylabs/adversary/internal/paths"
	"github.com/adversarylabs/adversary/internal/publock"
	"github.com/adversarylabs/adversary/pkg/blobsource"
	"github.com/adversarylabs/adversary/pkg/manifest"
	"github.com/adversarylabs/adversary/pkg/oci"
)

type Options struct {
	Dir            string
	NameOverride   string
	Build          bool
	Builder        string
	Stdout         io.Writer
	Stderr         io.Writer
	ParseReference func(string) (oci.Reference, error)
	BuildProject   func(context.Context, BuildOptions) error
}

type BuildOptions struct {
	Dir     string
	Builder string
	Stdout  io.Writer
	Stderr  io.Writer
	// Strict is retained for source compatibility. Builds with scripts.build
	// are now always strict; stale output requires AllowStaleDist explicitly.
	Strict         bool
	AllowStaleDist bool
	BuildStateDir  string
}

type BuildEnvironment struct {
	NPM, Node, Docker                string
	NPMError, NodeError, DockerError error
	Environment                      []string
	Run                              func(context.Context, string, []string, string, []string, io.Writer, io.Writer, bool) ([]byte, error)
}

const nodeBuilderImage = "node:22.14.0-alpine3.21@sha256:9bef0ef1e268f60627da9ba7d7605e8831d5b56ad07487d24d1aa386336d1944"
const nodeBuilderAMD64Manifest = "sha256:01393fe5a51489b63da0ab51aa8e0a7ff9990132917cf20cfc3d46f5e36c0e48"
const nodeBuilderARM64Manifest = "sha256:4a78eedb5c49d58c0c0b610ebc48f4ac397358604daac64e8dec1baecde2a31b"
const maxBuildSnapshotFiles = 250000
const maxBuildSnapshotBytes int64 = 4 << 30

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
	AdversaryManifest       []byte
	Manifest                []byte
	ManifestDigest          string
	AdversaryManifestDigest string
	ConfigDigest            string
	LayerDigest             string
	Size                    int64
	Files                   []File
	OCIManifest             oci.Manifest
	LayerSource             blobsource.SourceCloser
}

func (a *Artifact) Close() error {
	if a == nil || a.LayerSource == nil {
		return nil
	}
	return a.LayerSource.Close()
}

type File struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
	Mode   int64  `json:"mode,omitempty"`
}

// Preflight is the deterministic, non-mutating result of checking a package.
// Warnings are based on paths only; file contents are never inspected for secrets.
type Preflight struct {
	Name     string    `json:"name"`
	Version  string    `json:"version"`
	Runtime  string    `json:"runtime"`
	Files    []File    `json:"files"`
	Warnings []Warning `json:"warnings"`
}

type Warning struct {
	Path    string `json:"path"`
	Kind    string `json:"kind"`
	Message string `json:"message"`
}

// Check validates and inventories a package without running its build, creating
// an artifact, or writing to the repository.
func Check(opts Options) (result Preflight, err error) {
	if err := validateBuilder(opts.Builder); err != nil {
		return result, err
	}
	dir, root, err := openValidatedProject(opts.Dir)
	if err != nil {
		return result, err
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	before, err := root.Lstat(manifest.FileName)
	if err != nil {
		return result, err
	}
	data, err := root.ReadFile(manifest.FileName)
	if err != nil {
		return result, err
	}
	after, err := root.Lstat(manifest.FileName)
	if err != nil || !os.SameFile(before, after) {
		return result, errors.Join(err, fmt.Errorf("manifest changed while reading"))
	}
	m, err := manifest.Parse(data)
	if err != nil {
		return result, err
	}
	name := manifest.ShortName(m.Name)
	if strings.TrimSpace(opts.NameOverride) != "" {
		name, err = normalizeNameOverride(opts.NameOverride, opts.ParseReference)
		if err != nil {
			return result, err
		}
	}
	files, err := collectAndBuildLayerTo(root, dir, io.Discard)
	if err != nil {
		return result, err
	}
	if err := validatePackageEntrypoint(m, files); err != nil {
		return result, err
	}
	version := m.Version
	if version == "" {
		version = oci.DefaultTag
	}
	result = Preflight{Name: name, Version: version, Runtime: detectRuntime(files, m), Files: files}
	result.Warnings = WarningsForFiles(files)
	return result, nil
}

func checkedPackageEntrypoint(m manifest.Manifest) (string, bool, error) {
	command := m.Runtime.Command[0]
	// Image commands are resolved inside the declared image, not against host
	// package files. Named node commands always identify package build output.
	if m.Runtime.Image != "" {
		return "", false, nil
	}
	required := runtimeName(m) == "node" || strings.ContainsAny(command, `/\\`)
	if !required { // A bare process command is intentionally resolved via PATH at run time.
		return "", false, nil
	}
	if filepath.IsAbs(command) || filepath.VolumeName(command) != "" || strings.HasPrefix(command, "/") || strings.HasPrefix(command, `\`) || strings.Contains(command, ":") {
		return "", false, fmt.Errorf("runtime entrypoint %q must be package-relative", command)
	}
	if strings.Contains(command, `\`) {
		return "", false, fmt.Errorf("runtime entrypoint %q must use portable forward-slash separators", command)
	}
	entrypoint := filepath.ToSlash(filepath.Clean(command))
	if entrypoint == "." || entrypoint == ".." || strings.HasPrefix(entrypoint, "../") {
		return "", false, fmt.Errorf("runtime entrypoint %q escapes the package", command)
	}
	return entrypoint, true, nil
}

func validatePackageEntrypoint(m manifest.Manifest, files []File) error {
	entrypoint, required, err := checkedPackageEntrypoint(m)
	if err != nil {
		return err
	}
	if required && !inventoryContains(files, entrypoint) {
		return fmt.Errorf("runtime entrypoint %q is missing from packed files; build output is not ready", entrypoint)
	}
	return nil
}

func WarningsForFiles(files []File) []Warning {
	var warnings []Warning
	for _, file := range files {
		if secretRisk(file.Path) {
			warnings = append(warnings, Warning{Path: file.Path, Kind: "secret-risk", Message: "path resembles a credential or private-key file; review before packing"})
		}
	}
	return warnings
}

func secretRisk(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	switch base {
	case ".env", ".npmrc", ".pypirc", ".netrc", "id_rsa", "id_ed25519", "credentials.json", "service-account.json", "application_default_credentials.json", "kubeconfig", "azureprofile.json", "accesstokens.json":
		return true
	}
	clean := strings.ToLower(filepath.ToSlash(filepath.Clean(path)))
	return strings.HasSuffix(base, ".pem") || strings.HasSuffix(base, ".key") || strings.HasSuffix(base, ".p12") || strings.HasSuffix(base, ".pfx") || strings.HasSuffix(clean, "/.aws/credentials") || clean == ".aws/credentials" || strings.HasSuffix(clean, "/.kube/config") || clean == ".kube/config"
}

func Create(ctx context.Context, opts Options) (Artifact, error) {
	if err := validateBuilder(opts.Builder); err != nil {
		return Artifact{}, err
	}
	dir := opts.Dir
	if dir == "" {
		dir = "."
	}
	dir, err := filepath.Abs(dir)
	if err != nil {
		return Artifact{}, err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return Artifact{}, err
	}
	defer root.Close()
	before, err := root.Lstat(manifest.FileName)
	if err != nil {
		return Artifact{}, err
	}
	if beforeManifestRead != nil {
		beforeManifestRead()
	}
	adversaryManifest, err := root.ReadFile(manifest.FileName)
	if err != nil {
		return Artifact{}, err
	}
	after, err := root.Lstat(manifest.FileName)
	if err != nil || !os.SameFile(before, after) {
		return Artifact{}, fmt.Errorf("manifest changed while reading")
	}
	m, err := manifest.Parse(adversaryManifest)
	if err != nil {
		return Artifact{}, err
	}
	if opts.Build {
		if opts.BuildProject == nil {
			return Artifact{}, fmt.Errorf("build dependency is required")
		}
		if err := opts.BuildProject(ctx, BuildOptions{Dir: dir, Builder: opts.Builder, Stdout: opts.Stdout, Stderr: opts.Stderr}); err != nil {
			return Artifact{}, err
		}
	}
	var files []File
	var layerSource blobsource.SourceCloser
	var layerSize int64
	var layerDigest string
	ownershipTransferred := false
	defer func() {
		if layerSource != nil && !ownershipTransferred {
			_ = layerSource.Close()
		}
	}()
	{
		tmp, createErr := os.CreateTemp("", "adversary-pack-*.tar.gz")
		if createErr != nil {
			return Artifact{}, createErr
		}
		name := tmp.Name()
		keep := false
		defer func() {
			if !keep {
				_ = tmp.Close()
				_ = os.Remove(name)
			}
		}()
		hash := sha256.New()
		files, err = collectAndBuildLayerTo(root, dir, io.MultiWriter(tmp, hash))
		if err == nil {
			err = tmp.Sync()
		}
		if closeErr := tmp.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			return Artifact{}, err
		}
		info, statErr := os.Stat(name)
		if statErr != nil {
			return Artifact{}, statErr
		}
		layerSize = info.Size()
		layerDigest = "sha256:" + hex.EncodeToString(hash.Sum(nil))
		src, sourceErr := blobsource.File(name, layerDigest)
		if sourceErr != nil {
			return Artifact{}, sourceErr
		}
		layerSource = blobsource.Owned(src, func() error { return os.Remove(name) })
		keep = true
	}
	if err != nil {
		return Artifact{}, err
	}
	if err := validatePackageEntrypoint(m, files); err != nil {
		return Artifact{}, err
	}
	name := manifest.ShortName(m.Name)
	if strings.TrimSpace(opts.NameOverride) != "" {
		name, err = normalizeNameOverride(opts.NameOverride, opts.ParseReference)
		if err != nil {
			return Artifact{}, err
		}
	}
	version := m.Version
	if version == "" {
		version = oci.DefaultTag
	}
	runtime := detectRuntime(files, m)
	config, err := json.Marshal(ArtifactConfig{
		Created:        "1970-01-01T00:00:00Z",
		Name:           name,
		FullName:       m.Name,
		Version:        version,
		Runtime:        runtime,
		RuntimeName:    runtimeName(m),
		RuntimeVersion: m.Runtime.Version,
		RuntimeImage:   m.Runtime.Image,
		Entrypoint:     m.Runtime.Command,
		Files:          files,
	})
	if err != nil {
		return Artifact{}, err
	}
	layerDescriptor := oci.Descriptor{
		MediaType: oci.PackageLayerMediaType,
		Digest:    layerDigest,
		Size:      layerSize,
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
		"ai.adversary.runtime.image":       m.Runtime.Image,
	}
	manifestData, manifestDigest, ociManifest, err := oci.NewManifest(config, layerDescriptor, annotations)
	if err != nil {
		return Artifact{}, err
	}
	artifact := Artifact{
		Name:                    name,
		ManifestName:            m.Name,
		Version:                 version,
		Runtime:                 runtime,
		RuntimeName:             runtimeName(m),
		RuntimeVersion:          m.Runtime.Version,
		Entrypoint:              m.Runtime.Command,
		Permissions:             m.Permissions,
		Config:                  config,
		AdversaryManifest:       adversaryManifest,
		Manifest:                manifestData,
		ManifestDigest:          manifestDigest,
		AdversaryManifestDigest: oci.Digest(adversaryManifest),
		ConfigDigest:            oci.Digest(config),
		LayerDigest:             layerDigest,
		Size:                    int64(len(config)+len(manifestData)) + layerSize,
		Files:                   files,
		OCIManifest:             ociManifest,
		LayerSource:             layerSource,
	}
	ownershipTransferred = true
	return artifact, nil
}

var beforePackOpen func(string)
var beforeManifestRead func()

type packFile interface {
	io.Reader
	io.Closer
	Stat() (os.FileInfo, error)
}

var openPackFile = func(root *os.Root, name string) (packFile, error) { return root.Open(name) }

func collectAndBuildLayerTo(root *os.Root, dir string, dst io.Writer) ([]File, error) {
	ignore := loadIgnore(dir)
	files := make([]File, 0)
	gz, err := gzip.NewWriterLevel(dst, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	gz.Name = ""
	gz.ModTime = time.Unix(0, 0).UTC()
	tw := tar.NewWriter(gz)
	err = fs.WalkDir(root.FS(), ".", func(rel string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if rel == "." {
			return nil
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
		before, err := root.Lstat(rel)
		if err != nil {
			return err
		}
		if !before.Mode().IsRegular() {
			return fmt.Errorf("unsupported package file type: %s", rel)
		}
		if beforePackOpen != nil {
			beforePackOpen(rel)
		}
		f, err := openPackFile(root, rel)
		if err != nil {
			return err
		}
		after, err := f.Stat()
		if err != nil {
			return errors.Join(err, f.Close())
		}
		if !after.Mode().IsRegular() || !os.SameFile(before, after) {
			return errors.Join(fmt.Errorf("package file changed while opening: %s", rel), f.Close())
		}
		h := sha256.New()
		mode := normalizedFileMode(after.Mode())
		header := &tar.Header{Name: rel, Mode: mode, Size: after.Size(), ModTime: time.Unix(0, 0).UTC(), Format: tar.FormatPAX}
		if err := tw.WriteHeader(header); err != nil {
			return errors.Join(err, f.Close())
		}
		n, copyErr := io.CopyBuffer(io.MultiWriter(tw, h), f, make([]byte, 32<<10))
		closeErr := f.Close()
		if err := errors.Join(copyErr, closeErr); err != nil {
			return err
		}
		if n != after.Size() {
			return fmt.Errorf("package file changed while reading: %s", rel)
		}
		files = append(files, File{Path: rel, Size: n, SHA256: hex.EncodeToString(h.Sum(nil)), Mode: mode})
		return nil
	})
	if err != nil {
		return nil, errors.Join(err, tw.Close(), gz.Close())
	}
	if err := errors.Join(tw.Close(), gz.Close()); err != nil {
		return nil, err
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files, nil
}

func normalizeNameOverride(name string, parse func(string) (oci.Reference, error)) (string, error) {
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
	if parse == nil {
		return "", fmt.Errorf("reference parser dependency is required for --name")
	}
	if _, err := parse(name); err != nil {
		return "", fmt.Errorf("invalid --name: %w", err)
	}
	return name, nil
}

func BuildProjectWithEnvironment(ctx context.Context, opts BuildOptions, environment BuildEnvironment) error {
	if err := validateBuilder(opts.Builder); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("build canceled before filesystem access: %w", err)
	}
	dir, root, err := openValidatedProject(opts.Dir)
	if err != nil {
		return err
	}
	defer root.Close()
	stateCandidate, err := buildStatePath(opts.BuildStateDir)
	if err != nil {
		return err
	}
	if pathWithin(dir, stateCandidate) {
		return fmt.Errorf("build state root must be outside the project directory")
	}
	var stateBase string
	var state *os.Root
	var lock *publock.Lock
	defer func() {
		if state != nil {
			_ = state.Close()
		}
		if lock != nil {
			_ = lock.Close()
		}
	}()
	if existingBase, exists, err := findExistingJournalBase(stateCandidate, dir); err != nil {
		return err
	} else if exists {
		stateBase = existingBase
		lock, err = publock.Acquire(stateBase, "project-build\x00"+dir)
		if err != nil {
			return fmt.Errorf("acquire project build lock: %w", err)
		}
		state, err = openExistingProjectBuildState(stateBase, dir)
		if err != nil {
			return err
		}
		if err := recoverDistPublication(state, root); err != nil {
			return fmt.Errorf("recover interrupted dist publication: %w", err)
		}
	}
	data, err := root.ReadFile("package.json")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("read package.json: %w", err)
	}
	var packageInfo struct {
		Scripts map[string]json.RawMessage `json:"scripts"`
	}
	if err := json.Unmarshal(data, &packageInfo); err != nil {
		return fmt.Errorf("parse package.json: %w", err)
	}
	buildScript, exists := packageInfo.Scripts["build"]
	if !exists {
		return nil
	}
	var script string
	if err := json.Unmarshal(buildScript, &script); err != nil || strings.TrimSpace(script) == "" {
		return fmt.Errorf("package.json scripts.build must be a non-empty string")
	}
	if lock == nil {
		stateBase, err = ensureBuildStateRoot(stateCandidate)
		if err != nil {
			return err
		}
		if pathWithin(dir, stateBase) {
			return fmt.Errorf("build state root must be outside the project directory")
		}
		lock, err = publock.Acquire(stateBase, "project-build\x00"+dir)
		if err != nil {
			return fmt.Errorf("acquire project build lock: %w", err)
		}
		state, err = openProjectBuildState(stateBase, dir)
		if err != nil {
			return err
		}
		if err := recoverDistPublication(state, root); err != nil {
			return fmt.Errorf("recover interrupted dist publication: %w", err)
		}
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("build canceled while acquiring project lock: %w", err)
	}
	builder := opts.Builder
	if builder == "" {
		builder = "local"
	}
	switch builder {
	case "local":
		if _, err := root.Stat("node_modules"); err != nil {
			if opts.AllowStaleDist {
				if info, distErr := os.Stat(filepath.Join(dir, "dist")); distErr == nil && info.IsDir() {
					if opts.Stderr != nil {
						fmt.Fprintln(opts.Stderr, "Skipping build by explicit stale-dist policy: node_modules was not found, using existing dist/ output")
					}
					return nil
				}
			}
			return fmt.Errorf("build failed: node_modules was not found; run npm install or use --builder docker")
		}
		return buildWithLocalNPM(ctx, state, root, dir, opts.Stdout, opts.Stderr, opts.AllowStaleDist, environment)
	case "docker":
		return buildWithDocker(ctx, state, root, dir, opts.Stdout, opts.Stderr, environment)
	}
	panic("validated builder became invalid")
}

// ResolveBuildStateDir resolves the canonical private build-state root without
// creating it. Production composition calls this once and passes the result in
// BuildOptions; library callers may continue to provide their own override.
func ResolveBuildStateDir(override string) (string, error) {
	return buildStatePath(override)
}

func openValidatedProject(dir string) (string, *os.Root, error) {
	if dir == "" {
		dir = "."
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", nil, err
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return "", nil, fmt.Errorf("project directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", nil, fmt.Errorf("project path must be an existing non-symlink directory")
	}
	canonical, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", nil, fmt.Errorf("canonicalize project directory: %w", err)
	}
	canonical, err = filepath.Abs(canonical)
	if err != nil {
		return "", nil, err
	}
	root, err := os.OpenRoot(canonical)
	if err != nil {
		return "", nil, err
	}
	return canonical, root, nil
}

func ensureBuildStateRoot(override string) (string, error) {
	if override != "" {
		original, err := filepath.Abs(override)
		if err != nil {
			return "", err
		}
		if info, err := os.Lstat(original); err == nil && info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("build state root must be a non-symlink directory")
		}
	}
	root, err := buildStatePath(override)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return "", err
	}
	info, err := os.Lstat(root)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", fmt.Errorf("build state root must be a non-symlink directory")
	}
	if err := validateBuildStateOwner(info); err != nil {
		return "", err
	}
	if err := os.Chmod(root, 0700); err != nil {
		return "", err
	}
	canonical, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", err
	}
	return filepath.Abs(canonical)
}

func buildStatePath(override string) (string, error) {
	root := override
	if root == "" {
		cache, err := internalpaths.CacheDir()
		if err != nil {
			return "", err
		}
		root = filepath.Join(cache, "build-state")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	missing := []string{}
	probe := abs
	for {
		if _, err := os.Lstat(probe); err == nil {
			break
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		parent := filepath.Dir(probe)
		if parent == probe {
			return "", fmt.Errorf("cannot resolve build state path")
		}
		missing = append(missing, filepath.Base(probe))
		probe = parent
	}
	canonical, err := filepath.EvalSymlinks(probe)
	if err != nil {
		return "", err
	}
	for i := len(missing) - 1; i >= 0; i-- {
		canonical = filepath.Join(canonical, missing[i])
	}
	return canonical, nil
}

func pathWithin(parent, child string) bool {
	rel, err := filepath.Rel(parent, child)
	return err == nil && (rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))))
}

func openProjectBuildState(base, project string) (*os.Root, error) {
	root, err := os.OpenRoot(base)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	sum := sha256.Sum256([]byte(project))
	rel := filepath.ToSlash(filepath.Join("projects", hex.EncodeToString(sum[:])))
	if err := root.MkdirAll(rel, 0700); err != nil {
		return nil, err
	}
	info, err := root.Lstat(rel)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, fmt.Errorf("project build state is not a private directory")
	}
	return root.OpenRoot(rel)
}

func findExistingJournalBase(candidate, project string) (string, bool, error) {
	info, err := os.Lstat(candidate)
	if errors.Is(err, os.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return "", false, fmt.Errorf("existing build state root is not a private directory")
	}
	if err := validateBuildStateOwner(info); err != nil {
		return "", false, err
	}
	base, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return "", false, err
	}
	state, err := openExistingProjectBuildState(base, project)
	if errors.Is(err, os.ErrNotExist) {
		return base, false, nil
	}
	if err != nil {
		return "", false, err
	}
	defer state.Close()
	journal, err := state.Lstat(buildJournalName)
	if errors.Is(err, os.ErrNotExist) {
		return base, false, nil
	}
	if err != nil {
		return "", false, err
	}
	if !journal.Mode().IsRegular() || journal.Mode().Perm()&0077 != 0 {
		return "", false, fmt.Errorf("existing build journal is not private")
	}
	return base, true, nil
}

func openExistingProjectBuildState(base, project string) (*os.Root, error) {
	root, err := os.OpenRoot(base)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	sum := sha256.Sum256([]byte(project))
	rel := filepath.ToSlash(filepath.Join("projects", hex.EncodeToString(sum[:])))
	info, err := root.Lstat(rel)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("existing project build state is not private")
	}
	return root.OpenRoot(rel)
}

func validateBuilder(builder string) error {
	if builder != "" && builder != "local" && builder != "docker" {
		return fmt.Errorf("unsupported builder %q; supported builders: local, docker", builder)
	}
	return nil
}

func buildWithLocalNPM(ctx context.Context, state, root *os.Root, dir string, stdout, stderr io.Writer, allowStale bool, environment BuildEnvironment) error {
	npm, err := environment.NPM, environment.NPMError
	if npm == "" || err != nil {
		if allowStale {
			if info, statErr := os.Stat(filepath.Join(dir, "dist")); statErr == nil && info.IsDir() {
				if stderr != nil {
					fmt.Fprintf(stderr, "Skipping build by explicit stale-dist policy: npm was not found, using existing dist/ output\n")
				}
				return nil
			}
		}
		return fmt.Errorf("build failed: npm was not found; install Node 22/npm, use --builder docker, or explicitly allow stale dist")
	}
	if err := validateNodeRuntime(ctx, npm, environment); err != nil {
		return err
	}
	stage, err := stageProject(ctx, root, dir, false)
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	if environment.Run == nil {
		return fmt.Errorf("build process dependency is required")
	}
	if _, err := environment.Run(ctx, npm, []string{"run", "build"}, stage, withPathPrefix(environment.Environment, filepath.Dir(npm)), stdout, stderr, false); err != nil {
		return fmt.Errorf("build failed: %w", err)
	}
	return publishDist(ctx, state, root, filepath.Join(stage, "dist"))
}

func withPathPrefix(env []string, dir string) []string {
	prefix := "PATH="
	for i, value := range env {
		if strings.HasPrefix(value, prefix) {
			copyEnv := append([]string(nil), env...)
			copyEnv[i] = prefix + dir + string(os.PathListSeparator) + strings.TrimPrefix(value, prefix)
			return copyEnv
		}
	}
	return append(append([]string(nil), env...), prefix+dir)
}

func validateNodeRuntime(ctx context.Context, npm string, environment BuildEnvironment) error {
	node := environment.Node
	if node == "" || environment.NodeError != nil {
		return fmt.Errorf("build failed: Node 22 was not found next to npm or on captured PATH")
	}
	if environment.Run == nil {
		return fmt.Errorf("build process dependency is required")
	}
	out, err := environment.Run(ctx, node, []string{"--version"}, "", environment.Environment, nil, nil, true)
	if err != nil {
		return fmt.Errorf("build failed: determine Node version: %w", err)
	}
	version := strings.TrimSpace(string(out))
	if !strings.HasPrefix(version, "v22.") {
		return fmt.Errorf("build failed: Node %q does not match the supported execution runtime (v22.x)", version)
	}
	return nil
}

func buildWithDocker(ctx context.Context, state, root *os.Root, dir string, stdout, stderr io.Writer, environment BuildEnvironment) error {
	if _, err := root.Stat("package-lock.json"); err != nil {
		return fmt.Errorf("docker release build requires package-lock.json and npm ci")
	}
	docker, err := environment.Docker, environment.DockerError
	if docker == "" || err != nil {
		return fmt.Errorf("build failed: docker was not found; install Docker or use --builder local")
	}
	tmp, err := os.MkdirTemp("", "adversary-pack-docker-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	contextDir, err := stageProject(ctx, root, dir, true)
	if err != nil {
		return err
	}
	defer os.RemoveAll(contextDir)
	dockerfile := filepath.Join(tmp, "Dockerfile")
	if err := os.WriteFile(dockerfile, []byte(dockerBuildfile()), 0644); err != nil {
		return err
	}
	outDir := filepath.Join(tmp, "out")
	if environment.Run == nil {
		return fmt.Errorf("build process dependency is required")
	}
	if _, err := environment.Run(ctx, docker, []string{"build", "--output", "type=local,dest=" + outDir, "-f", dockerfile, contextDir}, "", environment.Environment, stdout, stderr, false); err != nil {
		return fmt.Errorf("docker build failed: %w", err)
	}
	builtDist := filepath.Join(outDir, "dist")
	if info, err := os.Stat(builtDist); err != nil || !info.IsDir() {
		return fmt.Errorf("docker build did not produce dist/")
	}
	return publishDist(ctx, state, root, builtDist)
}

func dockerBuildfile() string {
	return `FROM ` + nodeBuilderImage + ` AS build
WORKDIR /workspace
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM scratch
COPY --from=build /workspace/dist /dist
`
}

func stageProject(ctx context.Context, source *os.Root, dir string, excludeNodeModules bool) (string, error) {
	stage, err := os.MkdirTemp(filepath.Dir(dir), ".adversary-build-*")
	if err != nil {
		return "", fmt.Errorf("create build staging directory: %w", err)
	}
	ok := false
	defer func() {
		if !ok {
			os.RemoveAll(stage)
		}
	}()
	destination, err := os.OpenRoot(stage)
	if err != nil {
		return "", err
	}
	defer destination.Close()
	var snapshotFiles int
	var snapshotBytes int64
	err = fs.WalkDir(source.FS(), ".", func(rel string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		top := strings.SplitN(filepath.ToSlash(rel), "/", 2)[0]
		if top == "dist" || top == ".git" || top == ".publication-locks" || (excludeNodeModules && top == "node_modules") {
			return filepath.SkipDir
		}
		rel = filepath.ToSlash(rel)
		before, err := source.Lstat(rel)
		if err != nil {
			return err
		}
		if before.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("build source contains unsupported symlink %q", rel)
		}
		if entry.IsDir() {
			return destination.Mkdir(rel, before.Mode().Perm())
		}
		if !before.Mode().IsRegular() {
			return fmt.Errorf("build source contains unsupported file %q", rel)
		}
		snapshotFiles++
		if snapshotFiles > maxBuildSnapshotFiles || before.Size() < 0 || before.Size() > maxBuildSnapshotBytes-snapshotBytes {
			return fmt.Errorf("build source exceeds snapshot limit (%d files, %d bytes)", maxBuildSnapshotFiles, maxBuildSnapshotBytes)
		}
		snapshotBytes += before.Size()
		if beforeBuildSnapshotOpen != nil {
			beforeBuildSnapshotOpen(rel)
		}
		in, err := source.Open(rel)
		if err != nil {
			return err
		}
		after, err := in.Stat()
		if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) {
			in.Close()
			return fmt.Errorf("build source changed while opening %q", rel)
		}
		out, err := destination.OpenFile(rel, os.O_CREATE|os.O_EXCL|os.O_WRONLY, before.Mode().Perm())
		if err != nil {
			in.Close()
			return err
		}
		n, copyErr := io.CopyBuffer(out, &contextReader{ctx: ctx, r: io.LimitReader(in, before.Size()+1)}, make([]byte, 32<<10))
		inCloseErr := in.Close()
		closeErr := out.Close()
		if copyErr != nil {
			return copyErr
		}
		if n != before.Size() {
			return fmt.Errorf("build source changed while reading %q", rel)
		}
		if inCloseErr != nil {
			return inCloseErr
		}
		return closeErr
	})
	if err != nil {
		return "", fmt.Errorf("stage build source: %w", err)
	}
	ok = true
	return stage, nil
}

var beforeDistPublish func()
var afterDistRename func(string) error
var beforeBuildSnapshotOpen func(string)
var directorySyncHook func(string, int) error

type PublicationDurabilityError struct {
	Phase string
	Err   error
}

func (e *PublicationDurabilityError) Error() string {
	return fmt.Sprintf("publication durability failed during %s: %v", e.Phase, e.Err)
}
func (e *PublicationDurabilityError) Unwrap() error { return e.Err }

const buildJournalName = "publication.json"

type buildJournal struct {
	Project, State, Stage, Backup string
	HadDist                       bool
}

func publishDist(ctx context.Context, state, project *os.Root, builtDist string) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("build canceled before output validation: %w", err)
	}
	stageName, err := randomBuildName(".dist-adversary-stage-")
	if err != nil {
		return err
	}
	backup, err := randomBuildName(".dist-adversary-backup-")
	if err != nil {
		return err
	}
	hadDist := false
	if _, err := project.Lstat("dist"); err == nil {
		hadDist = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	j := buildJournal{Project: projectCorrelation(project), State: "staging", Stage: stageName, Backup: backup, HadDist: hadDist}
	if err := writeBuildJournal(state, j); err != nil {
		return err
	}
	if err := project.Mkdir(stageName, 0700); err != nil {
		_ = removeBuildJournal(state)
		return err
	}
	if err := project.Mkdir(backup, 0700); err != nil {
		_ = project.RemoveAll(stageName)
		_ = removeBuildJournal(state)
		return err
	}
	source, err := os.OpenRoot(builtDist)
	if err != nil {
		_ = recoverDistPublication(state, project)
		return err
	}
	defer source.Close()
	stageRoot, err := project.OpenRoot(stageName)
	if err != nil {
		_ = recoverDistPublication(state, project)
		return err
	}
	if err := copyRootTree(ctx, source, stageRoot); err != nil {
		stageRoot.Close()
		_ = recoverDistPublication(state, project)
		return fmt.Errorf("stage dist: %w", err)
	}
	if err := stageRoot.Close(); err != nil {
		_ = recoverDistPublication(state, project)
		return err
	}
	j.State = "prepared"
	if err := writeBuildJournal(state, j); err != nil {
		_ = recoverDistPublication(state, project)
		return err
	}
	if beforeDistPublish != nil {
		beforeDistPublish()
	}
	if err := ctx.Err(); err != nil {
		_ = recoverDistPublication(state, project)
		return fmt.Errorf("build canceled before dist publication: %w", err)
	}
	if hadDist {
		if err := project.Remove(backup); err != nil {
			_ = recoverDistPublication(state, project)
			return err
		}
		if err := project.Rename("dist", backup); err != nil {
			_ = recoverDistPublication(state, project)
			return fmt.Errorf("prepare dist replacement: %w", err)
		}
		if err := syncRootDurable(project, "project-backup-rename"); err != nil {
			if recoveryErr := recoverDistPublication(state, project); recoveryErr != nil {
				return fmt.Errorf("%w (recovery failed: %v)", err, recoveryErr)
			}
			return err
		}
	}
	if !hadDist {
		_ = project.Remove(backup)
	}
	j.State = "backup-moved"
	if err := writeBuildJournal(state, j); err != nil {
		_ = recoverDistPublication(state, project)
		return err
	}
	if afterDistRename != nil {
		if err := afterDistRename("backup-moved"); err != nil {
			_ = recoverDistPublication(state, project)
			return err
		}
	}
	if err := project.Rename(stageName, "dist"); err != nil {
		rollbackErr := recoverDistPublication(state, project)
		if rollbackErr != nil {
			return fmt.Errorf("publish dist: %w (recovery failed: %v)", err, rollbackErr)
		}
		return fmt.Errorf("publish dist: %w", err)
	}
	if afterDistRename != nil {
		if err := afterDistRename("published-rename"); err != nil {
			_ = recoverDistPublication(state, project)
			return err
		}
	}
	if err := syncRootDurable(project, "project-published-rename"); err != nil {
		recoveryErr := recoverDistPublication(state, project)
		if recoveryErr != nil {
			return fmt.Errorf("%w (recovery failed: %v)", err, recoveryErr)
		}
		return err
	}
	j.State = "published"
	if err := writeBuildJournal(state, j); err != nil {
		j.State = "backup-moved"
		if resetErr := writeBuildJournal(state, j); resetErr != nil {
			if recoveryErr := rollbackKnownPublication(state, project, j); recoveryErr != nil {
				return fmt.Errorf("%w (could not sync rollback intent: %v; rollback failed: %v)", err, resetErr, recoveryErr)
			}
			return fmt.Errorf("%w (could not sync rollback intent: %v; rolled back from in-memory transaction state)", err, resetErr)
		}
		recoveryErr := recoverDistPublication(state, project)
		if recoveryErr != nil {
			return fmt.Errorf("commit dist publication: %w (recovery failed: %v)", err, recoveryErr)
		}
		return fmt.Errorf("commit dist publication: %w", err)
	}
	if hadDist {
		// Publication is already committed; cleanup failure must not report a
		// failed build after changing visible output. A leftover hidden backup
		// is safe and can be removed by the next maintenance pass.
		_ = project.RemoveAll(backup)
	}
	_ = removeBuildJournal(state)
	return nil
}

func rollbackKnownPublication(state, project *os.Root, j buildJournal) error {
	_ = project.RemoveAll("dist")
	if j.HadDist {
		if err := project.Rename(j.Backup, "dist"); err != nil {
			return err
		}
	} else {
		_ = project.RemoveAll(j.Backup)
	}
	_ = project.RemoveAll(j.Stage)
	if err := syncRootDurable(project, "project-recovery"); err != nil {
		return err
	}
	_ = removeBuildJournal(state)
	return nil
}

func writeBuildJournal(root *os.Root, journal buildJournal) error {
	data, err := json.Marshal(journal)
	if err != nil {
		return err
	}
	tmp, err := randomBuildName("journal-")
	if err != nil {
		return err
	}
	f, err := root.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer root.Remove(tmp)
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err := root.Rename(tmp, buildJournalName); err != nil {
		return err
	}
	return syncRootDurable(root, "state-"+journal.State)
}

func removeBuildJournal(root *os.Root) error {
	err := root.Remove(buildJournalName)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return syncProjectRoot(root)
}

func syncProjectRoot(root *os.Root) error {
	f, err := root.Open(".")
	if err != nil {
		return err
	}
	defer f.Close()
	err = f.Sync()
	if runtime.GOOS == "windows" {
		return nil
	}
	return err
}

func syncRootDurable(root *os.Root, phase string) error {
	var last error
	for attempt := 1; attempt <= 3; attempt++ {
		if directorySyncHook != nil {
			if err := directorySyncHook(phase, attempt); err != nil {
				last = err
				continue
			}
		}
		if err := syncProjectRoot(root); err != nil {
			last = err
			continue
		}
		return nil
	}
	return &PublicationDurabilityError{Phase: phase, Err: last}
}

func recoverDistPublication(state, project *os.Root) error {
	data, err := state.ReadFile(buildJournalName)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var j buildJournal
	if err := json.Unmarshal(data, &j); err != nil {
		return fmt.Errorf("invalid build journal: %w", err)
	}
	if j.Project != projectCorrelation(project) || !validBuildTemp(j.Stage, ".dist-adversary-stage-") || !validBuildTemp(j.Backup, ".dist-adversary-backup-") {
		return fmt.Errorf("invalid build journal paths")
	}
	switch j.State {
	case "staging":
		_ = project.RemoveAll(j.Stage)
		_ = project.RemoveAll(j.Backup)
	case "prepared":
		if j.HadDist {
			if _, distErr := project.Lstat("dist"); errors.Is(distErr, os.ErrNotExist) {
				if _, backupErr := project.Lstat(j.Backup); backupErr == nil {
					if err := project.Rename(j.Backup, "dist"); err != nil {
						return err
					}
				}
			} else {
				_ = project.RemoveAll(j.Backup)
			}
		}
		_ = project.RemoveAll(j.Stage)
		if !j.HadDist {
			_ = project.RemoveAll(j.Backup)
		}
	case "backup-moved":
		backupExists, err := rootedPathExists(project, j.Backup)
		if err != nil {
			return err
		}
		distExists, err := rootedPathExists(project, "dist")
		if err != nil {
			return err
		}
		switch {
		case backupExists:
			if err := validateRootedDist(project, j.Backup); err != nil {
				return fmt.Errorf("refuse rollback from invalid backup: %w", err)
			}
			// If both exist, dist is the uncommitted new output and the validated
			// backup is the authoritative old output. If only backup exists, the
			// crash occurred between the two renames.
			if distExists {
				_ = project.RemoveAll(j.Stage)
				if err := project.Rename("dist", j.Stage); err != nil {
					return err
				}
				if err := project.Rename(j.Backup, "dist"); err != nil {
					_ = project.Rename(j.Stage, "dist")
					return err
				}
			} else if err := project.Rename(j.Backup, "dist"); err != nil {
				return err
			}
		case j.HadDist && distExists:
			// A previous recovery already consumed the backup. Preserve the
			// validated restored output; stale external journal durability must
			// never turn recovery into deletion.
			if err := validateRootedDist(project, "dist"); err != nil {
				return fmt.Errorf("backup is absent and visible dist is invalid: %w", err)
			}
		case !j.HadDist && distExists:
			// The pre-build state had no dist, so visible output is necessarily
			// the uncommitted second rename.
			_ = project.RemoveAll("dist")
		case j.HadDist && !distExists:
			return fmt.Errorf("cannot recover publication: both prior dist backup and visible dist are absent")
		}
		_ = project.RemoveAll(j.Stage)
	case "published":
		_ = project.RemoveAll(j.Backup)
		_ = project.RemoveAll(j.Stage)
	default:
		return fmt.Errorf("invalid build journal state %q", j.State)
	}
	if err := syncRootDurable(project, "project-recovery"); err != nil {
		return err
	}
	return removeBuildJournal(state)
}

func rootedPathExists(root *os.Root, path string) (bool, error) {
	_, err := root.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

func validateRootedDist(project *os.Root, name string) error {
	dist, err := project.OpenRoot(name)
	if err != nil {
		return err
	}
	defer dist.Close()
	files := 0
	err = fs.WalkDir(dist.FS(), ".", func(rel string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if rel == "." {
			return nil
		}
		info, err := dist.Lstat(filepath.ToSlash(rel))
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("contains symlink %q", rel)
		}
		if !info.IsDir() {
			if !info.Mode().IsRegular() {
				return fmt.Errorf("contains non-regular file %q", rel)
			}
			files++
		}
		return nil
	})
	if err != nil {
		return err
	}
	if files == 0 {
		return fmt.Errorf("is empty")
	}
	return nil
}

func validBuildTemp(name, prefix string) bool {
	if name != filepath.Base(name) || !strings.HasPrefix(name, prefix) {
		return false
	}
	suffix := strings.TrimPrefix(name, prefix)
	if len(suffix) != 32 {
		return false
	}
	_, err := hex.DecodeString(suffix)
	return err == nil
}

func randomBuildName(prefix string) (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(value[:]), nil
}

func projectCorrelation(project *os.Root) string {
	name := project.Name()
	if canonical, err := filepath.EvalSymlinks(name); err == nil {
		name = canonical
	}
	if absolute, err := filepath.Abs(name); err == nil {
		name = absolute
	}
	sum := sha256.Sum256([]byte(name))
	return hex.EncodeToString(sum[:])
}

func journalIsPublished(state, project *os.Root) bool {
	data, err := state.ReadFile(buildJournalName)
	if err != nil {
		return false
	}
	var j buildJournal
	return json.Unmarshal(data, &j) == nil && j.Project == projectCorrelation(project) && j.State == "published"
}

func validatePublishedDist(project *os.Root) error {
	dist, err := project.OpenRoot("dist")
	if err != nil {
		return err
	}
	defer dist.Close()
	files := 0
	err = fs.WalkDir(dist.FS(), ".", func(rel string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if rel == "." {
			return nil
		}
		info, err := dist.Lstat(filepath.ToSlash(rel))
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("published dist contains symlink")
		}
		if !info.IsDir() {
			if !info.Mode().IsRegular() {
				return fmt.Errorf("published dist contains non-regular file")
			}
			files++
		}
		return nil
	})
	if err != nil {
		return err
	}
	if files == 0 {
		return fmt.Errorf("published dist is empty")
	}
	return nil
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r *contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}

func copyRootTree(ctx context.Context, source, destination *os.Root) error {
	files := 0
	var total int64
	err := fs.WalkDir(source.FS(), ".", func(rel string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		rel = filepath.ToSlash(rel)
		before, err := source.Lstat(rel)
		if err != nil {
			return err
		}
		if before.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("source contains unsupported symlink %q", rel)
		}
		if before.IsDir() {
			return destination.Mkdir(rel, before.Mode().Perm())
		}
		if !before.Mode().IsRegular() {
			return fmt.Errorf("source contains unsupported file %q", rel)
		}
		files++
		if files > maxBuildSnapshotFiles || before.Size() < 0 || before.Size() > maxBuildSnapshotBytes-total {
			return fmt.Errorf("build output exceeds snapshot limit (%d files, %d bytes)", maxBuildSnapshotFiles, maxBuildSnapshotBytes)
		}
		total += before.Size()
		if beforeBuildSnapshotOpen != nil {
			beforeBuildSnapshotOpen(rel)
		}
		in, err := source.Open(rel)
		if err != nil {
			return err
		}
		after, err := in.Stat()
		if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) {
			in.Close()
			return fmt.Errorf("source changed while opening %q", rel)
		}
		out, err := destination.OpenFile(rel, os.O_CREATE|os.O_EXCL|os.O_WRONLY, before.Mode().Perm())
		if err != nil {
			in.Close()
			return err
		}
		n, copyErr := io.CopyBuffer(out, &contextReader{ctx: ctx, r: io.LimitReader(in, before.Size()+1)}, make([]byte, 32<<10))
		inErr := in.Close()
		outErr := out.Close()
		if copyErr != nil {
			return copyErr
		}
		if n != before.Size() {
			return fmt.Errorf("source changed while reading %q", rel)
		}
		if inErr != nil {
			return inErr
		}
		return outErr
	})
	if err != nil {
		return err
	}
	if files == 0 {
		return fmt.Errorf("build produced an empty dist/")
	}
	return nil
}

func collectFiles(dir string) ([]File, error) {
	ignore := loadIgnore(dir)
	files := make([]File, 0)
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
		files = append(files, File{Path: rel, Size: info.Size(), SHA256: hex.EncodeToString(h.Sum(nil)), Mode: normalizedFileMode(info.Mode())})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files, nil
}

func normalizedFileMode(mode fs.FileMode) int64 {
	if mode.Perm()&0111 != 0 {
		return 0755
	}
	return 0644
}

func detectRuntime(files []File, m manifest.Manifest) string {
	if inventoryContains(files, "package.json") {
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
		"node_modules/", ".git/", ".publication-locks/", ".env", ".env.*", ".DS_Store", "coverage/", "tmp/", ".cache/", "Dockerfile",
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
