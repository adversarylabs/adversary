package adversary

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	canonical "github.com/adversarylabs/adversary/pkg/manifest"
)

type capturingExecutor struct {
	spec  RuntimeSpec
	files RuntimeFiles
}

func (*capturingExecutor) Backend() ExecutorBackend           { return NativeSandboxExecutorBackend }
func (*capturingExecutor) Capabilities() ExecutorCapabilities { return allTestExecutorCapabilities() }

type recordingFiles struct {
	OSRuntimeFiles
	writes map[string][]byte
}

func (f *recordingFiles) WriteFile(path string, data []byte, mode fs.FileMode) error {
	if f.writes == nil {
		f.writes = map[string][]byte{}
	}
	f.writes[path] = append([]byte(nil), data...)
	return nil
}
func (f *recordingFiles) Open(path string) (io.ReadCloser, error) {
	data, ok := f.writes[path]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

func (e *capturingExecutor) Run(_ context.Context, spec RuntimeSpec) (RuntimeResult, error) {
	e.spec = spec
	if err := e.files.WriteFile(filepath.Join(spec.RunDir, "output.json"), minimalEnvelope(), 0o600); err != nil {
		return RuntimeResult{}, err
	}
	return RuntimeResult{}, nil
}

func TestRunnerUsesInjectedRuntimeDependencies(t *testing.T) {
	project := writeRunnerProject(t, "")
	root := t.TempDir()
	runDir := filepath.Join(root, "owned-run")
	var mkdirBase string
	removed := false
	times := []time.Time{time.Unix(10, 0), time.Unix(11, 0), time.Unix(13, 0), time.Unix(17, 0)}
	n := 0
	files := &recordingFiles{}
	executor := &capturingExecutor{files: files}
	err := (Runner{
		Stdout:   &bytes.Buffer{},
		Stderr:   &bytes.Buffer{},
		Executor: executor,
		Files:    files,
		TempDir:  root,
		Now: func() time.Time {
			got := times[n]
			n++
			return got
		},
		MkdirTemp: func(dir, _ string) (string, error) {
			mkdirBase = dir
			return runDir, os.MkdirAll(runDir, 0o700)
		},
		RemoveAll: func(path string) error {
			if path != runDir {
				t.Fatalf("cleanup path = %q", path)
			}
			removed = true
			return os.RemoveAll(path)
		},
	}).Run(context.Background(), RunOptions{AdversaryRef: project, RepoPath: t.TempDir(), Format: "json"})
	if err != nil {
		t.Fatal(err)
	}
	if mkdirBase != root || executor.spec.RunDir != runDir || !removed || len(files.writes) != 2 {
		t.Fatalf("injected runtime dependencies not honored: base=%q run=%q removed=%v", mkdirBase, executor.spec.RunDir, removed)
	}
}

func TestHostExecutorRequiresInjectedNodeResolverBeforeLaunching(t *testing.T) {
	_, err := (HostExecutor{}).Run(context.Background(), RuntimeSpec{RuntimeName: "node", Command: []string{"node", "does-not-run.js"}})
	if err == nil || err.Error() != "host execution Node.js resolver dependency is required" {
		t.Fatalf("error = %v", err)
	}
}

type injectedFileInfo struct{ name string }

func (i injectedFileInfo) Name() string     { return i.name }
func (injectedFileInfo) Size() int64        { return 0 }
func (injectedFileInfo) Mode() fs.FileMode  { return 0o600 }
func (injectedFileInfo) ModTime() time.Time { return time.Time{} }
func (injectedFileInfo) IsDir() bool        { return false }
func (injectedFileInfo) Sys() any           { return nil }

type injectedManifestFiles struct {
	manifestPath string
	repository   string
	reader       func() io.ReadCloser
	opened       bool
	readDir      bool
}

func (f *injectedManifestFiles) Abs(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", errors.New("test path must be absolute")
	}
	return filepath.Clean(path), nil
}
func (f *injectedManifestFiles) EvalSymlinks(string) (string, error) {
	return "", errors.New("unexpected EvalSymlinks")
}
func (f *injectedManifestFiles) Stat(path string) (fs.FileInfo, error) {
	if path != f.manifestPath {
		return nil, fs.ErrNotExist
	}
	return injectedFileInfo{name: filepath.Base(path)}, nil
}
func (f *injectedManifestFiles) WriteFile(string, []byte, fs.FileMode) error {
	return errors.New("unexpected WriteFile")
}
func (f *injectedManifestFiles) Open(path string) (io.ReadCloser, error) {
	if path != f.manifestPath {
		return nil, fs.ErrNotExist
	}
	f.opened = true
	return f.reader(), nil
}
func (f *injectedManifestFiles) Glob(string) ([]string, error) {
	return nil, errors.New("unexpected Glob")
}
func (f *injectedManifestFiles) ReadDir(path string) ([]fs.DirEntry, error) {
	if path != f.repository {
		return nil, errors.New("unexpected ReadDir")
	}
	f.readDir = true
	return []fs.DirEntry{}, nil
}
func (f *injectedManifestFiles) MkdirTemp(string, string) (string, error) {
	return "", errors.New("unexpected MkdirTemp")
}
func (f *injectedManifestFiles) RemoveAll(string) error {
	return errors.New("unexpected RemoveAll")
}

func TestRunnerInspectUsesInjectedRuntimeFiles(t *testing.T) {
	root := t.TempDir()
	adversaryPath := filepath.Join(root, "virtual-adversary")
	repositoryPath := filepath.Join(root, "virtual-repository")
	manifestPath := filepath.Join(adversaryPath, canonical.FileName)
	manifest := []byte("name: local/injected\nversion: 1.0.0\nruntime:\n  name: process\n  version: 1.0.0\n  command: [scanner]\n")
	files := &injectedManifestFiles{manifestPath: manifestPath, repository: repositoryPath, reader: func() io.ReadCloser {
		return io.NopCloser(bytes.NewReader(manifest))
	}}
	var output bytes.Buffer
	err := (Runner{Stdout: &output, Files: files, Resolver: &Resolver{}, RequireInjectedResolver: true}).Inspect(RunOptions{AdversaryRef: adversaryPath, RepoPath: repositoryPath})
	if err != nil {
		t.Fatal(err)
	}
	if !files.opened || !files.readDir {
		t.Fatalf("injected filesystem was not used: opened=%v readDir=%v", files.opened, files.readDir)
	}
	for _, want := range []string{"local/injected", adversaryPath, repositoryPath, "scanner"} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("inspect output missing %q:\n%s", want, output.String())
		}
	}
}

type countingReadCloser struct {
	remaining int
	read      int
	closed    bool
}

func (r *countingReadCloser) Read(p []byte) (int, error) {
	if r.remaining == 0 {
		return 0, io.EOF
	}
	n := len(p)
	if n > r.remaining {
		n = r.remaining
	}
	for i := 0; i < n; i++ {
		p[i] = 'x'
	}
	r.remaining -= n
	r.read += n
	return n, nil
}
func (r *countingReadCloser) Close() error { r.closed = true; return nil }

func TestInjectedManifestReaderIsBounded(t *testing.T) {
	root := t.TempDir()
	adversaryPath := filepath.Join(root, "oversized-adversary")
	manifestPath := filepath.Join(adversaryPath, canonical.FileName)
	reader := &countingReadCloser{remaining: canonical.MaxSize * 4}
	files := &injectedManifestFiles{manifestPath: manifestPath, reader: func() io.ReadCloser { return reader }}
	_, err := ResolveReferenceWithRuntime(adversaryPath, Resolver{}, files)
	if err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("error = %v", err)
	}
	if reader.read != canonical.MaxSize+1 {
		t.Fatalf("reader consumed %d bytes, want bounded %d", reader.read, canonical.MaxSize+1)
	}
	if !reader.closed {
		t.Fatal("oversized manifest reader was not closed")
	}
}
