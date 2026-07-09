package cmd

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/adversarylabs/adversary/pkg/oci"
)

func TestInitCommandGeneratesTypeScriptProject(t *testing.T) {
	dir := t.TempDir()
	destination := filepath.Join(dir, "hello-world")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd := NewRootCommand(&stdout, &stderr)
	cmd.SetArgs([]string{"init", destination, "--sdk", "typescript"})

	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}

	for _, rel := range []string{
		"adversary.yaml",
		"Dockerfile",
		"package.json",
		"tsconfig.json",
		"README.md",
		"AGENTS.md",
		".gitignore",
		"dist/index.js",
		"dist/index.d.ts",
		"src/index.ts",
		"test/index.test.ts",
		"fixtures/clean/README.md",
		"fixtures/vulnerable/.gitkeep",
		"vendor/adversary-sdk/dist/index.js",
	} {
		if _, err := os.Stat(filepath.Join(destination, rel)); err != nil {
			t.Fatalf("expected generated file %s: %v", rel, err)
		}
	}

	distPath := filepath.Join(destination, "dist/index.js")
	if err := os.WriteFile(distPath, []byte("// overwritten by build\n"), 0644); err != nil {
		t.Fatalf("generated dist file should be writable: %v", err)
	}

	manifest := readFile(t, filepath.Join(destination, "adversary.yaml"))
	if !strings.Contains(manifest, "name: local/hello-world") {
		t.Fatalf("manifest did not substitute name:\n%s", manifest)
	}
	if !strings.Contains(manifest, "manual: true") {
		t.Fatalf("manifest missing manual trigger:\n%s", manifest)
	}
	if strings.Contains(manifest, "files_changed") {
		t.Fatalf("manifest should not include files_changed:\n%s", manifest)
	}

	agents := readFile(t, filepath.Join(destination, "AGENTS.md"))
	for _, want := range []string{
		"This repository contains an Adversary Labs adversary.",
		"Parse files once whenever practical.",
		"Include evidence with every finding.",
		"Never modify the scanned repository.",
	} {
		if !strings.Contains(agents, want) {
			t.Fatalf("AGENTS.md missing %q in:\n%s", want, agents)
		}
	}

	output := stdout.String()
	for _, want := range []string{
		"✓ Generated project",
		"SDK",
		"TypeScript",
		"npm install",
		"npm run build",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("init output missing %q in:\n%s", want, output)
		}
	}
}

func TestInitCommandRejectsUnsupportedSDK(t *testing.T) {
	dir := t.TempDir()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd := NewRootCommand(&stdout, &stderr)
	cmd.SetArgs([]string{"init", filepath.Join(dir, "hello-world"), "--sdk", "python"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), `unsupported SDK "python"; supported SDKs: typescript`) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestInitCommandRejectsExistingDestination(t *testing.T) {
	dir := t.TempDir()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd := NewRootCommand(&stdout, &stderr)
	cmd.SetArgs([]string{"init", dir})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "destination already exists") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVersionCommand(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd := NewRootCommand(&stdout, &stderr)
	cmd.SetArgs([]string{"version"})

	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if got, want := stdout.String(), "adversary dev\n"; got != want {
		t.Fatalf("version output = %q, want %q", got, want)
	}
}

func TestLoginHelpShowsAPIURLFlag(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd := NewRootCommand(&stdout, &stderr)
	cmd.SetArgs([]string{"login", "--help"})

	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	output := stdout.String()
	if !strings.Contains(output, "--api-url") {
		t.Fatalf("login help missing --api-url:\n%s", output)
	}
	if !strings.Contains(output, "https://adversarylabs.ai/api") {
		t.Fatalf("login help missing default API URL:\n%s", output)
	}
}

func TestWhoamiCommandWhenLoggedOut(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd := NewRootCommand(&stdout, &stderr)
	cmd.SetArgs([]string{"whoami"})

	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	output := stdout.String()
	if !strings.Contains(output, "Not logged in.") {
		t.Fatalf("whoami output missing logged-out message:\n%s", output)
	}
	if !strings.Contains(output, "adversary login") {
		t.Fatalf("whoami output missing login hint:\n%s", output)
	}
}

func TestPushPullAgainstLocalOCIRegistry(t *testing.T) {
	registry := newTestOCIRegistry()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("local listener unavailable: %v", err)
	}
	server := httptest.NewUnstartedServer(registry)
	server.Listener = listener
	server.Start()
	defer server.Close()

	home := t.TempDir()
	t.Setenv("HOME", home)

	project := t.TempDir()
	writeProject(t, project)
	t.Chdir(project)

	host := strings.TrimPrefix(server.URL, "http://")
	var pushStdout bytes.Buffer
	var pushStderr bytes.Buffer
	push := NewRootCommand(&pushStdout, &pushStderr)
	push.SetArgs([]string{"push", host + "/acme/security-reviewer:v1"})
	if err := push.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(pushStdout.String(), "Digest:\n\nsha256:") {
		t.Fatalf("push output missing digest:\n%s", pushStdout.String())
	}
	if registry.manifestCount() != 1 {
		t.Fatalf("expected one pushed manifest, got %d", registry.manifestCount())
	}

	pullDir := t.TempDir()
	t.Chdir(pullDir)
	var pullStdout bytes.Buffer
	var pullStderr bytes.Buffer
	pull := NewRootCommand(&pullStdout, &pullStderr)
	pull.SetArgs([]string{"pull", host + "/acme/security-reviewer:v1"})
	if err := pull.Execute(); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Installed:", "local/security-reviewer", "Version:", "1.4.2"} {
		if !strings.Contains(pullStdout.String(), want) {
			t.Fatalf("pull output missing %q:\n%s", want, pullStdout.String())
		}
	}

	cacheIndex := filepath.Join(home, ".adversary", "cache", "index")
	if _, err := os.Stat(cacheIndex); err != nil {
		t.Fatalf("expected cache index: %v", err)
	}
}

type testOCIRegistry struct {
	mu        sync.Mutex
	blobs     map[string][]byte
	manifests map[string][]byte
}

func newTestOCIRegistry() *testOCIRegistry {
	return &testOCIRegistry{
		blobs:     map[string][]byte{},
		manifests: map[string][]byte{},
	}
}

func (r *testOCIRegistry) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.URL.Path == "/v2/" {
		w.WriteHeader(http.StatusOK)
		return
	}
	if !strings.HasPrefix(req.URL.Path, "/v2/") {
		http.NotFound(w, req)
		return
	}
	path := strings.TrimPrefix(req.URL.Path, "/v2/")
	switch {
	case strings.Contains(path, "/blobs/uploads/") && req.Method == http.MethodPost:
		w.Header().Set("Location", "/v2/"+path+"test-upload")
		w.WriteHeader(http.StatusAccepted)
	case strings.Contains(path, "/blobs/uploads/") && req.Method == http.MethodPut:
		digest := req.URL.Query().Get("digest")
		data, _ := io.ReadAll(req.Body)
		r.mu.Lock()
		r.blobs[digest] = data
		r.mu.Unlock()
		w.Header().Set("Docker-Content-Digest", digest)
		w.WriteHeader(http.StatusCreated)
	case strings.Contains(path, "/blobs/"):
		_, digest, _ := strings.Cut(path, "/blobs/")
		r.mu.Lock()
		data, ok := r.blobs[digest]
		r.mu.Unlock()
		if !ok {
			http.NotFound(w, req)
			return
		}
		w.Header().Set("Docker-Content-Digest", digest)
		if req.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		_, _ = w.Write(data)
	case strings.Contains(path, "/manifests/") && req.Method == http.MethodPut:
		data, _ := io.ReadAll(req.Body)
		key := manifestKey(path)
		digest := oci.Digest(data)
		r.mu.Lock()
		r.manifests[key] = data
		r.mu.Unlock()
		w.Header().Set("Docker-Content-Digest", digest)
		w.WriteHeader(http.StatusCreated)
	case strings.Contains(path, "/manifests/") && req.Method == http.MethodGet:
		key := manifestKey(path)
		r.mu.Lock()
		data, ok := r.manifests[key]
		r.mu.Unlock()
		if !ok {
			http.NotFound(w, req)
			return
		}
		w.Header().Set("Content-Type", oci.ImageManifestMediaType)
		w.Header().Set("Docker-Content-Digest", oci.Digest(data))
		_, _ = w.Write(data)
	default:
		http.NotFound(w, req)
	}
}

func (r *testOCIRegistry) manifestCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.manifests)
}

func manifestKey(path string) string {
	repo, ref, _ := strings.Cut(path, "/manifests/")
	return fmt.Sprintf("%s/%s", repo, ref)
}

func writeProject(t *testing.T, dir string) {
	t.Helper()
	files := map[string]string{
		"adversary.yaml": `name: local/security-reviewer
version: 1.4.2
runtime:
  image: security-reviewer:local
  command:
    - node
    - dist/index.js
`,
		"README.md":     "# Security Reviewer\n",
		"LICENSE":       "MIT\n",
		"dist/index.js": "console.log('ok')\n",
	}
	for rel, content := range files {
		path := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
