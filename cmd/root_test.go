package cmd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	internaladversary "github.com/adversarylabs/adversary/internal/adversary"
	"github.com/adversarylabs/adversary/internal/application"
	"github.com/adversarylabs/adversary/pkg/adversarylabs"
	"github.com/adversarylabs/adversary/pkg/oci"
	"github.com/adversarylabs/adversary/pkg/pack"
	"github.com/adversarylabs/adversary/pkg/repository"
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
		"package.json",
		"package-lock.json",
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
		"npm ci",
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

func TestRunRejectsUnsafeShellFlagCombinations(t *testing.T) {
	for name, args := range map[string][]string{
		"network": {"run", "./test", "--shell", "--no-network", "--allow-unsafe-host-execution"},
		"json":    {"run", "./test", "--shell", "--json", "--allow-unsafe-host-execution"},
	} {
		t.Run(name, func(t *testing.T) {
			cmd := NewRootCommand(&bytes.Buffer{}, &bytes.Buffer{})
			cmd.SetArgs(args)
			err := cmd.Execute()
			if err == nil || !strings.Contains(err.Error(), "cannot be combined") {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestRunHelpLabelsUnsafeHostExecution(t *testing.T) {
	var stdout bytes.Buffer
	cmd := NewRootCommand(&stdout, &bytes.Buffer{})
	cmd.SetArgs([]string{"run", "--help"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"--allow-unsafe-host-execution", "UNSAFE", "fails if the executor cannot enforce it"} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("help missing %q:\n%s", want, stdout.String())
		}
	}
}

func TestRunHelpDocumentsExplicitLifecycleControls(t *testing.T) {
	var stdout bytes.Buffer
	cmd := NewRootCommand(&stdout, &bytes.Buffer{})
	cmd.SetArgs([]string{"run", "--help"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"--build", "--build-timeout", "--timeout"} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("help missing %q:\n%s", want, stdout.String())
		}
	}
}

func TestRunRejectsConflictingAndNegativeLifecycleFlagsBeforeWork(t *testing.T) {
	for name, args := range map[string][]string{
		"build policy":     {"run", "./test", "--build", "--no-build"},
		"negative timeout": {"run", "./test", "--timeout=-1s"},
	} {
		t.Run(name, func(t *testing.T) {
			cmd := NewRootCommand(&bytes.Buffer{}, &bytes.Buffer{})
			cmd.SetArgs(args)
			if err := cmd.Execute(); err == nil {
				t.Fatal("expected validation error")
			}
		})
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

func TestPackHelpShowsBuilderFlag(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd := NewRootCommand(&stdout, &stderr)
	cmd.SetArgs([]string{"pack", "--help"})

	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	output := stdout.String()
	for _, want := range []string{"--builder", "local or docker", "--name"} {
		if !strings.Contains(output, want) {
			t.Fatalf("pack help missing %q:\n%s", want, output)
		}
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

func TestPackListAndInspectCommands(t *testing.T) {
	t.Setenv("ADVERSARY_DATA_DIR", t.TempDir())
	project := t.TempDir()
	writeProject(t, project)
	t.Chdir(project)

	var packStdout bytes.Buffer
	var packStderr bytes.Buffer
	packCmd := NewRootCommand(&packStdout, &packStderr)
	packCmd.SetArgs([]string{"pack", "."})
	if err := packCmd.Execute(); err != nil {
		t.Fatal(err)
	}
	packOutput := packStdout.String()
	if !strings.Contains(packOutput, "security-reviewer:1.4.2") || !strings.Contains(packOutput, "security-reviewer:latest") {
		t.Fatalf("pack output missing refs:\n%s", packOutput)
	}
	digest := extractDigest(t, packOutput)

	var lsStdout bytes.Buffer
	var lsStderr bytes.Buffer
	lsCmd := NewRootCommand(&lsStdout, &lsStderr)
	lsCmd.SetArgs([]string{"ls"})
	if err := lsCmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(lsStdout.String(), "security-reviewer") || !strings.Contains(lsStdout.String(), "1.4.2") {
		t.Fatalf("ls output missing record:\n%s", lsStdout.String())
	}

	var listJSONStdout bytes.Buffer
	var listJSONStderr bytes.Buffer
	listCmd := NewRootCommand(&listJSONStdout, &listJSONStderr)
	listCmd.SetArgs([]string{"list", "--json"})
	if err := listCmd.Execute(); err != nil {
		t.Fatal(err)
	}
	var records []repository.Record
	if err := json.Unmarshal(listJSONStdout.Bytes(), &records); err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Digest != digest {
		t.Fatalf("list records = %#v, digest %s", records, digest)
	}

	for _, ref := range []string{"security-reviewer", "security-reviewer:1.4.2", digest} {
		var inspectStdout bytes.Buffer
		var inspectStderr bytes.Buffer
		inspectCmd := NewRootCommand(&inspectStdout, &inspectStderr)
		inspectCmd.SetArgs([]string{"inspect", ref})
		if err := inspectCmd.Execute(); err != nil {
			t.Fatalf("inspect %q: %v", ref, err)
		}
		if !strings.Contains(inspectStdout.String(), "Digest: "+digest) {
			t.Fatalf("inspect %q output missing digest:\n%s", ref, inspectStdout.String())
		}
	}
	var inspectJSONStdout bytes.Buffer
	var inspectJSONStderr bytes.Buffer
	inspectJSONCmd := NewRootCommand(&inspectJSONStdout, &inspectJSONStderr)
	inspectJSONCmd.SetArgs([]string{"inspect", "security-reviewer", "--json"})
	if err := inspectJSONCmd.Execute(); err != nil {
		t.Fatal(err)
	}
	var record repository.Record
	if err := json.Unmarshal(inspectJSONStdout.Bytes(), &record); err != nil {
		t.Fatal(err)
	}
	if record.Digest != digest {
		t.Fatalf("inspect json digest = %q, want %q", record.Digest, digest)
	}
}

func TestAppBoundArtifactCommandsIgnoreConflictingDefaultRepository(t *testing.T) {
	registry := newTestOCIRegistry()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("local listener unavailable: %v", err)
	}
	server := httptest.NewUnstartedServer(registry)
	server.Listener = listener
	server.Start()
	defer server.Close()

	defaultData := t.TempDir()
	t.Cleanup(func() { makeTestTreeWritable(defaultData) })
	t.Setenv("HOME", t.TempDir())
	t.Setenv("ADVERSARY_DATA_DIR", defaultData)
	defaultResolver, err := internaladversary.DefaultResolver()
	if err != nil {
		t.Fatal(err)
	}
	conflictProject := t.TempDir()
	writeProject(t, conflictProject)
	if err := os.WriteFile(filepath.Join(conflictProject, "dist", "index.js"), []byte("console.log('default repository payload')\n"), 0644); err != nil {
		t.Fatal(err)
	}
	conflict, err := pack.Create(context.Background(), pack.Options{Dir: conflictProject})
	if err != nil {
		t.Fatal(err)
	}
	defaultRecord, err := defaultResolver.ImportPacked(conflict, "security-reviewer:1.4.2")
	if err != nil {
		t.Fatal(err)
	}

	appRoot := t.TempDir()
	t.Cleanup(func() { makeTestTreeWritable(appRoot) })
	appRepo := repository.Repository{Root: appRoot}
	project := t.TempDir()
	writeProject(t, project)
	var appOut, appErr bytes.Buffer
	app := lifecycleTestApp(t, appRepo, &appOut, &appErr)
	packCmd := NewRootCommandWithApp(app)
	packCmd.SetArgs([]string{"pack", project})
	if err := packCmd.Execute(); err != nil {
		t.Fatal(err)
	}
	appDigest := extractDigest(t, appOut.String())
	if appDigest == defaultRecord.Digest {
		t.Fatal("test setup produced identical App and default artifacts")
	}
	if got, err := appRepo.Resolve("security-reviewer:1.4.2"); err != nil || got.Digest != appDigest {
		t.Fatalf("pack did not write App repository: record=%#v err=%v", got, err)
	}
	if got, err := defaultResolver.Repository.Resolve("security-reviewer:1.4.2"); err != nil || got.Digest != defaultRecord.Digest {
		t.Fatalf("pack changed default repository: record=%#v err=%v", got, err)
	}

	appOut.Reset()
	listCmd := NewRootCommandWithApp(app)
	listCmd.SetArgs([]string{"list", "--json"})
	if err := listCmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(appOut.String(), appDigest) || strings.Contains(appOut.String(), defaultRecord.Digest) {
		t.Fatalf("list did not exclusively report App repository: %s", appOut.String())
	}

	host := strings.TrimPrefix(server.URL, "http://")
	appOut.Reset()
	pushCmd := NewRootCommandWithApp(app)
	pushCmd.SetArgs([]string{"push", "security-reviewer:1.4.2", host + "/acme/security-reviewer:v1"})
	if err := pushCmd.Execute(); err != nil {
		t.Fatal(err)
	}
	pushedDigest := oci.Digest(registry.manifest(t, "acme/security-reviewer/v1"))
	if pushedDigest != appDigest {
		t.Fatalf("push selected digest %s, want App digest %s (default %s)", pushedDigest, appDigest, defaultRecord.Digest)
	}

	pullRoot := t.TempDir()
	t.Cleanup(func() { makeTestTreeWritable(pullRoot) })
	pullRepo := repository.Repository{Root: pullRoot}
	var pullOut, pullErr bytes.Buffer
	pullApp := lifecycleTestApp(t, pullRepo, &pullOut, &pullErr)
	pullCmd := NewRootCommandWithApp(pullApp)
	pullCmd.SetArgs([]string{"pull", host + "/acme/security-reviewer:v1"})
	if err := pullCmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if got, err := pullRepo.Resolve(host + "/acme/security-reviewer:v1"); err != nil || got.Digest != appDigest {
		t.Fatalf("pull did not register App repository: record=%#v err=%v", got, err)
	}
	if _, err := defaultResolver.Repository.Resolve(appDigest); !os.IsNotExist(err) {
		t.Fatalf("pull imported into default repository: err=%v", err)
	}
}

func TestInjectedPushPullNeedNoProcessEnvironment(t *testing.T) {
	remote := newTestOCIRegistry()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("local listener unavailable: %v", err)
	}
	server := httptest.NewUnstartedServer(remote)
	server.Listener = listener
	server.Start()
	defer server.Close()
	host := strings.TrimPrefix(server.URL, "http://")

	sourceRepo := repository.Repository{Root: t.TempDir()}
	project := t.TempDir()
	writeProject(t, project)
	var out, errOut bytes.Buffer
	app := lifecycleTestApp(t, sourceRepo, &out, &errOut)
	packCmd := NewRootCommandWithApp(app)
	packCmd.SetArgs([]string{"pack", project})
	if err := packCmd.Execute(); err != nil {
		t.Fatal(err)
	}
	digest := extractDigest(t, out.String())
	out.Reset()
	push := NewRootCommandWithApp(app)
	push.SetArgs([]string{"push", digest, host + "/acme/reviewer:v1"})
	if err := push.Execute(); err != nil {
		t.Fatal(err)
	}

	destinationRepo := repository.Repository{Root: t.TempDir()}
	var pullOut, pullErr bytes.Buffer
	pullApp := lifecycleTestApp(t, destinationRepo, &pullOut, &pullErr)
	pull := NewRootCommandWithApp(pullApp)
	pull.SetArgs([]string{"pull", host + "/acme/reviewer:v1"})
	if err := pull.Execute(); err != nil {
		t.Fatal(err)
	}
	installed, err := destinationRepo.Resolve(host + "/acme/reviewer:v1")
	if err != nil {
		t.Fatal(err)
	}
	if installed.Digest != digest {
		t.Fatalf("installed digest=%s want=%s", installed.Digest, digest)
	}
}

func TestPackNameOverride(t *testing.T) {
	t.Setenv("ADVERSARY_DATA_DIR", t.TempDir())
	project := t.TempDir()
	writeProject(t, project)

	var packStdout bytes.Buffer
	var packStderr bytes.Buffer
	packCmd := NewRootCommand(&packStdout, &packStderr)
	packCmd.SetArgs([]string{"pack", project, "--name", "ghcr.io/acme/security-reviewer"})
	if err := packCmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(packStdout.String(), "ghcr.io/acme/security-reviewer:1.4.2") {
		t.Fatalf("pack output missing overridden ref:\n%s", packStdout.String())
	}

	resolver, err := internaladversary.DefaultResolver()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.Repository.Resolve("ghcr.io/acme/security-reviewer:1.4.2"); err != nil {
		t.Fatalf("overridden ref not inspectable: %v", err)
	}
}

func TestDefaultAdversaryLabsPushRefUsesStoredNamespace(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("ADVERSARY_REGISTRY_HOST", "localhost:5000")
	configStore, err := adversarylabs.DefaultConfigStore()
	if err != nil {
		t.Fatal(err)
	}
	if err := configStore.SetAuth("localhost:5000", adversarylabs.Auth{
		Token:             "secret-token",
		RegistryNamespace: "Acme Security",
		ExpiresAt:         "2099-01-01T00:00:00Z",
	}); err != nil {
		t.Fatal(err)
	}

	ref, err := defaultAdversaryLabsPushRef(context.Background(), application.Dependencies{Auth: configStore, API: processAPIFactory{store: configStore, http: http.DefaultClient}, RegistryHost: "localhost:5000"}, "dockerfile-reviewer:0.1.0", pushRecord{
		Name:    "dockerfile-reviewer",
		Version: "0.1.0",
	}, "", "default")
	if err != nil {
		t.Fatal(err)
	}
	want := "localhost:5000/acme-security/dockerfile-reviewer:0.1.0"
	if ref != want {
		t.Fatalf("ref = %q, want %q", ref, want)
	}
}

func TestDefaultPushRefUsesLibraryForRegistryHostOverrideWithoutLogin(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("ADVERSARY_REGISTRY_HOST", "localhost:8787")

	store := adversarylabs.ConfigStore{Path: filepath.Join(t.TempDir(), "config.json")}
	ref, err := defaultAdversaryLabsPushRef(context.Background(), application.Dependencies{Auth: store, API: processAPIFactory{store: store, http: http.DefaultClient}, RegistryHost: "localhost:8787"}, "dockerfile-reviewer:0.1.0", pushRecord{
		Name:    "dockerfile-reviewer",
		Version: "0.1.0",
	}, "", "default")
	if err != nil {
		t.Fatal(err)
	}
	want := "localhost:8787/library/dockerfile-reviewer:0.1.0"
	if ref != want {
		t.Fatalf("ref = %q, want %q", ref, want)
	}
}

func TestRegistryAuthRealmUsesAppAuthRoute(t *testing.T) {
	tests := map[string]string{
		"http://localhost:3000/api":       "http://localhost:3000/auth/registry",
		"http://localhost:3000/api/":      "http://localhost:3000/auth/registry",
		"https://adversarylabs.ai/api":    "https://adversarylabs.ai/auth/registry",
		"https://example.com/custom/api":  "https://example.com/custom/auth/registry",
		"https://example.com/custom/api/": "https://example.com/custom/auth/registry",
	}
	for input, want := range tests {
		if got := registryAuthRealm(input); got != want {
			t.Fatalf("registryAuthRealm(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestRegistryNamespaceFromAccountUsesTeamSlug(t *testing.T) {
	got := registryNamespaceFromAccount(adversarylabs.WhoamiResponse{
		Team: adversarylabs.Team{Slug: "red-team"},
	})
	if got != "red-team" {
		t.Fatalf("namespace = %q", got)
	}
}

func TestPushErrorWithNamespaceHintForRegistryDenied(t *testing.T) {
	ref := oci.Reference{
		Registry:   "localhost:8787",
		Repository: "library/dockerfile-adversary",
		Tag:        "0.1.0",
	}
	err := pushErrorWithNamespaceHint(
		&oci.RegistryError{Operation: "token", Registry: ref.Registry, Repository: ref.Repository, StatusCode: http.StatusForbidden, Status: "403 Forbidden", Codes: []oci.RegistryErrorCode{{Code: "DENIED", Message: "Requested registry access is not authorized."}}},
		"dockerfile-adversary:0.1.0",
		ref,
	)
	text := err.Error()
	for _, want := range []string{
		"push is not authorized for localhost:8787/library/dockerfile-adversary:0.1.0",
		`remote namespace "library" may not match your Adversary Labs team slug`,
		"adversary push dockerfile-adversary:0.1.0 localhost:8787/<slug>/dockerfile-adversary:0.1.0",
		"ADVERSARY_REGISTRY_NAMESPACE=<slug>",
		"Original error: OCI token localhost:8787/library/dockerfile-adversary failed: 403 Forbidden",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("error %q missing %q", text, want)
		}
	}
}

func TestPushErrorWithNamespaceHintLeavesOtherErrorsAlone(t *testing.T) {
	original := fmt.Errorf("dial tcp: connection refused")
	ref := oci.Reference{
		Registry:   "localhost:8787",
		Repository: "library/dockerfile-adversary",
		Tag:        "0.1.0",
	}
	if got := pushErrorWithNamespaceHint(original, "dockerfile-adversary:0.1.0", ref); got != original {
		t.Fatalf("error = %v, want original %v", got, original)
	}
}

func TestPushPullAgainstLocalOCIRegistry(t *testing.T) {
	nodePath, nodeErr := exec.LookPath("node")
	if nodeErr != nil {
		t.Skip("Node 22 is required for the pulled-artifact E2E")
	}
	versionOut, versionErr := exec.Command(nodePath, "--version").Output()
	if versionErr != nil || !strings.HasPrefix(strings.TrimSpace(string(versionOut)), "v22.") {
		t.Skipf("Node 22 is required for the pulled-artifact E2E; found %q", strings.TrimSpace(string(versionOut)))
	}
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
	t.Cleanup(func() { makeTestTreeWritable(home) })
	t.Setenv("HOME", home)
	t.Setenv("ADVERSARY_DATA_DIR", t.TempDir())

	project := t.TempDir()
	writeProject(t, project)
	copyTestTree(t, filepath.Join("..", "templates", "typescript", "vendor", "adversary-sdk"), filepath.Join(project, "vendor", "adversary-sdk"))
	if err := os.WriteFile(filepath.Join(project, "dist", "index.js"), []byte(`import { parseInput, writeOutput } from "@adversary/sdk";
await parseInput();
await writeOutput({protocolVersion:1,result:{adversary:{name:"local/security-reviewer"},target:{},positives:[],observations:[{key:"sdk-stage",summary:"SDK parse/write executed."}],findings:[],suppressed:{observations:0,findings:0}}});
`), 0644); err != nil {
		t.Fatal(err)
	}
	t.Chdir(project)

	var packStdout bytes.Buffer
	var packStderr bytes.Buffer
	packCmd := NewRootCommand(&packStdout, &packStderr)
	packCmd.SetArgs([]string{"pack", "."})
	if err := packCmd.Execute(); err != nil {
		t.Fatal(err)
	}

	host := strings.TrimPrefix(server.URL, "http://")
	var pushStdout bytes.Buffer
	var pushStderr bytes.Buffer
	push := NewRootCommand(&pushStdout, &pushStderr)
	push.SetArgs([]string{"push", "security-reviewer:1.4.2", host + "/acme/security-reviewer:v1"})
	if err := push.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(pushStdout.String(), "Image digest\n\nsha256:") {
		t.Fatalf("push output missing image digest:\n%s", pushStdout.String())
	}
	if !strings.Contains(pushStdout.String(), "Published adversary manifest referrer\n\nsha256:") {
		t.Fatalf("push output missing adversary manifest referrer digest:\n%s", pushStdout.String())
	}
	if registry.manifestCount() != 2 {
		t.Fatalf("expected image and artifact manifests, got %d", registry.manifestCount())
	}
	imageKey := "acme/security-reviewer/v1"
	imageManifest := registry.manifest(t, imageKey)
	imageDigest := oci.Digest(imageManifest)
	artifactTag, err := oci.AdversaryManifestArtifactTag(imageDigest)
	if err != nil {
		t.Fatal(err)
	}
	if artifactTag == "v1" {
		t.Fatal("artifact tag must not overwrite image tag")
	}
	artifactManifest := registry.manifest(t, "acme/security-reviewer/"+artifactTag)
	if registry.manifestContentType("acme/security-reviewer/"+artifactTag) != oci.OCIArtifactManifestMediaType {
		t.Fatalf("artifact manifest content type = %q", registry.manifestContentType("acme/security-reviewer/"+artifactTag))
	}
	var artifact oci.ArtifactManifest
	if err := json.Unmarshal(artifactManifest, &artifact); err != nil {
		t.Fatal(err)
	}
	manifestBytes := []byte(`name: local/security-reviewer
version: 1.4.2
runtime:
  name: node
  version: "22"
  command:
    - dist/index.js
`)
	if artifact.MediaType != oci.OCIArtifactManifestMediaType {
		t.Fatalf("artifact mediaType = %q", artifact.MediaType)
	}
	if artifact.ArtifactType != oci.AdversaryManifestMediaType {
		t.Fatalf("artifactType = %q", artifact.ArtifactType)
	}
	if artifact.Subject.MediaType != oci.ImageManifestMediaType || artifact.Subject.Digest != imageDigest {
		t.Fatalf("subject = %#v, image digest %s", artifact.Subject, imageDigest)
	}
	if len(artifact.Blobs) != 1 {
		t.Fatalf("artifact blobs = %d", len(artifact.Blobs))
	}
	yamlBlob := artifact.Blobs[0]
	if yamlBlob.MediaType != oci.AdversaryManifestMediaType || yamlBlob.Digest != oci.Digest(manifestBytes) || yamlBlob.Size != int64(len(manifestBytes)) {
		t.Fatalf("yaml blob descriptor = %#v", yamlBlob)
	}
	if registry.blobContentType(yamlBlob.Digest) != oci.AdversaryManifestMediaType {
		t.Fatalf("yaml blob content type = %q", registry.blobContentType(yamlBlob.Digest))
	}
	if got := string(registry.blob(t, yamlBlob.Digest)); got != string(manifestBytes) {
		t.Fatalf("yaml blob bytes changed:\n%s", got)
	}
	if got := registry.manifest(t, imageKey); string(got) != string(imageManifest) {
		t.Fatal("image tag no longer resolves to runnable image manifest")
	}
	var retryStdout bytes.Buffer
	var retryStderr bytes.Buffer
	retry := NewRootCommand(&retryStdout, &retryStderr)
	retry.SetArgs([]string{"push", "security-reviewer:1.4.2", host + "/acme/security-reviewer:v1"})
	if err := retry.Execute(); err != nil {
		t.Fatalf("retry push: %v", err)
	}
	if registry.manifestCount() != 2 {
		t.Fatalf("retry should not create extra manifest refs, got %d", registry.manifestCount())
	}

	pullDir := t.TempDir()
	freshHome := t.TempDir()
	freshData := t.TempDir()
	t.Cleanup(func() { makeTestTreeWritable(freshData) })
	t.Setenv("HOME", freshHome)
	t.Setenv("ADVERSARY_DATA_DIR", freshData)
	t.Chdir(pullDir)
	var pullStdout bytes.Buffer
	var pullStderr bytes.Buffer
	pull := NewRootCommand(&pullStdout, &pullStderr)
	pull.SetArgs([]string{"pull", host + "/acme/security-reviewer:v1"})
	if err := pull.Execute(); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Installed:", "local/security-reviewer", "Version:", "1.4.2", "Tag:", "v1"} {
		if !strings.Contains(pullStdout.String(), want) {
			t.Fatalf("pull output missing %q:\n%s", want, pullStdout.String())
		}
	}
	nodeStageRan := false
	{
		for _, args := range [][]string{{"init"}, {"config", "user.email", "test@example.com"}, {"config", "user.name", "Test"}} {
			c := exec.Command("git", args...)
			c.Dir = pullDir
			if out, err := c.CombinedOutput(); err != nil {
				t.Fatalf("git %v: %v %s", args, err, out)
			}
		}
		if err := os.WriteFile(filepath.Join(pullDir, "README.md"), []byte("target\n"), 0644); err != nil {
			t.Fatal(err)
		}
		for _, args := range [][]string{{"add", "."}, {"commit", "-m", "initial"}} {
			c := exec.Command("git", args...)
			c.Dir = pullDir
			if out, err := c.CombinedOutput(); err != nil {
				t.Fatalf("git %v: %v %s", args, err, out)
			}
		}
		var runOut, runErr bytes.Buffer
		run := NewRootCommand(&runOut, &runErr)
		run.SetArgs([]string{"run", imageDigest, "--repo", pullDir, "--all-files", "--allow-unsafe-host-execution", "--format", "json"})
		if err := run.Execute(); err != nil {
			t.Fatalf("run pulled digest: %v stderr=%s", err, runErr.String())
		}
		if !strings.Contains(runOut.String(), `"protocolVersion": 1`) {
			t.Fatalf("run output=%s", runOut.String())
		}
		if !strings.Contains(runOut.String(), "SDK parse/write executed.") {
			t.Fatalf("Node SDK stage did not run: %s", runOut.String())
		}
		nodeStageRan = true
	}
	if !nodeStageRan {
		t.Fatal("Node SDK stage was bypassed")
	}
	var inspectOut, inspectErr bytes.Buffer
	inspect := NewRootCommand(&inspectOut, &inspectErr)
	inspect.SetArgs([]string{"inspect", imageDigest, "--json"})
	if err := inspect.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(inspectOut.String(), imageDigest) || !strings.Contains(inspectOut.String(), host+"/acme/security-reviewer:v1") {
		t.Fatalf("inspect output=%s", inspectOut.String())
	}
	var listOut bytes.Buffer
	list := NewRootCommand(&listOut, &bytes.Buffer{})
	list.SetArgs([]string{"ls", "--json"})
	if err := list.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(listOut.String(), imageDigest) {
		t.Fatalf("list output=%s", listOut.String())
	}
	var repushOut, repushErr bytes.Buffer
	repush := NewRootCommand(&repushOut, &repushErr)
	repush.SetArgs([]string{"push", imageDigest, host + "/acme/security-reviewer:v2"})
	if err := repush.Execute(); err != nil {
		t.Fatalf("repush: %v stderr=%s", err, repushErr.String())
	}
	if got := oci.Digest(registry.manifest(t, "acme/security-reviewer/v2")); got != imageDigest {
		t.Fatalf("repush digest=%s want=%s", got, imageDigest)
	}

}

func makeTestTreeWritable(root string) {
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err == nil {
			_ = os.Chmod(path, info.Mode().Perm()|0700)
		}
		return nil
	})
}

func TestPushMissingAdversaryManifestFailsBeforeImageUpload(t *testing.T) {
	registry := newTestOCIRegistry()
	server := httptest.NewServer(registry)
	defer server.Close()

	t.Setenv("HOME", t.TempDir())
	t.Setenv("ADVERSARY_DATA_DIR", t.TempDir())
	project := t.TempDir()
	writeProject(t, project)
	t.Chdir(project)

	var packStdout bytes.Buffer
	var packStderr bytes.Buffer
	packCmd := NewRootCommand(&packStdout, &packStderr)
	packCmd.SetArgs([]string{"pack", "."})
	if err := packCmd.Execute(); err != nil {
		t.Fatal(err)
	}
	resolver, err := internaladversary.DefaultResolver()
	if err != nil {
		t.Fatal(err)
	}
	record, err := resolver.Repository.Resolve("security-reviewer:1.4.2")
	if err != nil {
		t.Fatal(err)
	}
	digestKey := fmt.Sprintf("v1-%x", sha256.Sum256([]byte(record.AdversaryManifestDigest)))
	if err := os.Remove(filepath.Join(resolver.Repository.RootPath(), "adversary-manifests", digestKey)); err != nil {
		t.Fatal(err)
	}

	host := strings.TrimPrefix(server.URL, "http://")
	var pushStdout bytes.Buffer
	var pushStderr bytes.Buffer
	push := NewRootCommand(&pushStdout, &pushStderr)
	push.SetArgs([]string{"push", "security-reviewer:1.4.2", host + "/acme/security-reviewer:v1"})
	err = push.Execute()
	if err == nil {
		t.Fatal("expected missing adversary.yaml error")
	}
	if !strings.Contains(err.Error(), "no such file") {
		t.Fatalf("unexpected error: %v", err)
	}
	if registry.manifestCount() != 0 {
		t.Fatalf("image should not be pushed after missing manifest validation, got %d manifests", registry.manifestCount())
	}
}

func TestPackRejectsOversizedAdversaryManifest(t *testing.T) {
	t.Setenv("ADVERSARY_DATA_DIR", t.TempDir())
	project := t.TempDir()
	writeProject(t, project)
	f, err := os.OpenFile(filepath.Join(project, "adversary.yaml"), os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.WriteString("# " + strings.Repeat("x", 1<<20) + "\n")
	if closeErr := f.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	if err != nil {
		t.Fatal(err)
	}

	var packStdout bytes.Buffer
	var packStderr bytes.Buffer
	packCmd := NewRootCommand(&packStdout, &packStderr)
	packCmd.SetArgs([]string{"pack", project})
	err = packCmd.Execute()
	if err == nil {
		t.Fatal("expected oversized adversary.yaml error")
	}
	if !strings.Contains(err.Error(), "adversary.yaml is too large") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPackAndInspectUseDurableCanonicalIdentityAndInventory(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("ADVERSARY_DATA_DIR", t.TempDir())
	t.Setenv("ADVERSARY_REGISTRY_HOST", "poison.invalid")
	project := t.TempDir()
	writeProject(t, project)

	var packOut, packErr bytes.Buffer
	packCmd := NewRootCommand(&packOut, &packErr)
	packCmd.SetArgs([]string{"pack", project, "--format", "json"})
	if err := packCmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(packOut.String(), "Packing adversary") {
		t.Fatalf("stdout contaminated: %s", packOut.String())
	}
	var packed struct {
		SchemaVersion int `json:"schemaVersion"`
		Data          struct {
			CanonicalReference string        `json:"canonicalReference"`
			Files              []packFileDTO `json:"files"`
		} `json:"data"`
	}
	if err := json.Unmarshal(packOut.Bytes(), &packed); err != nil {
		t.Fatal(err)
	}
	if got, want := packed.Data.CanonicalReference, "poison.invalid/library/security-reviewer:1.4.2"; got != want {
		t.Fatalf("canonical=%q want %q", got, want)
	}
	if len(packed.Data.Files) == 0 {
		t.Fatal("pack inventory missing")
	}

	// Simulate a restart with different registry configuration. Local identity
	// and exact shorthand lookup remain bound to durable repository indexes.
	t.Setenv("ADVERSARY_REGISTRY_HOST", "different.invalid")
	var inspectOut, inspectErr bytes.Buffer
	inspectCmd := NewRootCommand(&inspectOut, &inspectErr)
	inspectCmd.SetArgs([]string{"inspect", "security-reviewer:1.4.2", "--format", "json"})
	if err := inspectCmd.Execute(); err != nil {
		t.Fatal(err)
	}
	var inspected struct {
		SchemaVersion int `json:"schemaVersion"`
		Data          struct {
			CanonicalReference string           `json:"canonicalReference"`
			Files              artifactFilesDTO `json:"files"`
		} `json:"data"`
	}
	if err := json.Unmarshal(inspectOut.Bytes(), &inspected); err != nil {
		t.Fatalf("stdout=%q: %v", inspectOut.String(), err)
	}
	if inspected.SchemaVersion != 2 || inspected.Data.CanonicalReference != packed.Data.CanonicalReference {
		t.Fatalf("inspect=%+v", inspected)
	}
	if inspected.Data.Files.Status != "available" || len(inspected.Data.Files.Entries) != len(packed.Data.Files) {
		t.Fatalf("files=%+v", inspected.Data.Files)
	}
	for i := 1; i < len(inspected.Data.Files.Entries); i++ {
		if inspected.Data.Files.Entries[i-1].Path >= inspected.Data.Files.Entries[i].Path {
			t.Fatalf("unsorted files=%+v", inspected.Data.Files.Entries)
		}
	}

	var textOut, textErr bytes.Buffer
	textCmd := NewRootCommand(&textOut, &textErr)
	textCmd.SetArgs([]string{"inspect", "security-reviewer:1.4.2", "--files"})
	if err := textCmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(textOut.String(), "Files:\n") || !strings.Contains(textOut.String(), "sha256:") {
		t.Fatalf("files output=%s", textOut.String())
	}
	var listOut, listErr bytes.Buffer
	listCmd := NewRootCommand(&listOut, &listErr)
	listCmd.SetArgs([]string{"list", "--format", "json"})
	if err := listCmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(listOut.String(), `"status":"available"`) || strings.Contains(listOut.String(), `"status":"unavailable"`) {
		t.Fatalf("list inventory output=%s", listOut.String())
	}

	resolver, err := internaladversary.DefaultResolver()
	if err != nil {
		t.Fatal(err)
	}
	record, err := resolver.Repository.Resolve("security-reviewer:1.4.2")
	if err != nil {
		t.Fatal(err)
	}
	configKey := fmt.Sprintf("v1-%x", sha256.Sum256([]byte(record.ConfigDigest)))
	if err := os.WriteFile(filepath.Join(resolver.Repository.RootPath(), "blobs", configKey), []byte(`{"files":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	var corruptOut, corruptErr bytes.Buffer
	corruptCmd := NewRootCommand(&corruptOut, &corruptErr)
	corruptCmd.SetArgs([]string{"inspect", "security-reviewer:1.4.2", "--files"})
	if err := corruptCmd.Execute(); err == nil {
		t.Fatal("corrupt inventory accepted")
	}
	if corruptOut.Len() != 0 {
		t.Fatalf("failed inspect contaminated stdout: %q", corruptOut.String())
	}
}

func TestPackLatestRegistrationRetargetsAcrossVersionsAndRestart(t *testing.T) {
	repo := repository.Repository{Root: t.TempDir()}
	aProject, bProject := t.TempDir(), t.TempDir()
	writeProject(t, aProject)
	writeProject(t, bProject)
	bManifest := strings.ReplaceAll(readFile(t, filepath.Join(bProject, "adversary.yaml")), "version: 1.4.2", "version: 1.4.3")
	if err := os.WriteFile(filepath.Join(bProject, "adversary.yaml"), []byte(bManifest), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bProject, "dist", "index.js"), []byte("export default 'v2'\n"), 0644); err != nil {
		t.Fatal(err)
	}
	a, err := pack.Create(context.Background(), pack.Options{Dir: aProject})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := pack.Create(context.Background(), pack.Options{Dir: bProject})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	aRec, err := repo.ImportPacked(a, "security-reviewer:1.4.2")
	if err != nil {
		t.Fatal(err)
	}
	bRec, err := repo.ImportPacked(b, "security-reviewer:1.4.3")
	if err != nil {
		t.Fatal(err)
	}
	resolver := processResolver{resolver: internaladversary.Resolver{Repository: repo}}
	latest := "registry.adversarylabs.ai/library/security-reviewer:latest"
	if err := registerExactRef(resolver, latest, aRec.Digest); err != nil {
		t.Fatal(err)
	}
	if err := registerExactRef(resolver, latest, bRec.Digest); err != nil {
		t.Fatal(err)
	}
	got, err := (repository.Repository{Root: repo.Root}).Resolve("security-reviewer:latest")
	if err != nil || got.Digest != bRec.Digest {
		t.Fatalf("restart latest=%#v err=%v", got, err)
	}
}

func extractDigest(t *testing.T, output string) string {
	t.Helper()
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, "Digest: sha256:") {
			return strings.TrimPrefix(line, "Digest: ")
		}
	}
	t.Fatalf("digest not found in output:\n%s", output)
	return ""
}

type testOCIRegistry struct {
	mu                   sync.Mutex
	blobs                map[string][]byte
	blobContentTypes     map[string]string
	manifests            map[string][]byte
	manifestDigests      map[string][]byte
	manifestContentTypes map[string]string
	referrers            map[string][]oci.Descriptor
}

func newTestOCIRegistry() *testOCIRegistry {
	return &testOCIRegistry{
		blobs:                map[string][]byte{},
		blobContentTypes:     map[string]string{},
		manifests:            map[string][]byte{},
		manifestDigests:      map[string][]byte{},
		manifestContentTypes: map[string]string{},
		referrers:            map[string][]oci.Descriptor{},
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
		r.blobContentTypes[digest] = req.Header.Get("Content-Type")
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
		r.manifestDigests[digest] = data
		r.manifestContentTypes[key] = req.Header.Get("Content-Type")
		if req.Header.Get("Content-Type") == oci.OCIArtifactManifestMediaType {
			var artifact oci.ArtifactManifest
			if err := json.Unmarshal(data, &artifact); err == nil {
				r.referrers[artifact.Subject.Digest] = append(r.referrers[artifact.Subject.Digest], oci.Descriptor{
					MediaType:    oci.OCIArtifactManifestMediaType,
					Digest:       digest,
					Size:         int64(len(data)),
					ArtifactType: artifact.ArtifactType,
				})
			}
		}
		r.mu.Unlock()
		w.Header().Set("Docker-Content-Digest", digest)
		w.WriteHeader(http.StatusCreated)
	case strings.Contains(path, "/manifests/") && req.Method == http.MethodGet:
		key := manifestKey(path)
		_, ref, _ := strings.Cut(path, "/manifests/")
		r.mu.Lock()
		data, ok := r.manifests[key]
		if !ok && strings.HasPrefix(ref, "sha256:") {
			data, ok = r.manifestDigests[ref]
		}
		r.mu.Unlock()
		if !ok {
			http.NotFound(w, req)
			return
		}
		if strings.Contains(req.Header.Get("Accept"), oci.OCIArtifactManifestMediaType) {
			w.Header().Set("Content-Type", oci.OCIArtifactManifestMediaType)
		} else {
			w.Header().Set("Content-Type", oci.ImageManifestMediaType)
		}
		w.Header().Set("Docker-Content-Digest", oci.Digest(data))
		_, _ = w.Write(data)
	case strings.Contains(path, "/referrers/") && req.Method == http.MethodGet:
		_, digest, _ := strings.Cut(path, "/referrers/")
		r.mu.Lock()
		descriptors := append([]oci.Descriptor(nil), r.referrers[digest]...)
		r.mu.Unlock()
		if artifactType := req.URL.Query().Get("artifactType"); artifactType != "" {
			filtered := descriptors[:0]
			for _, descriptor := range descriptors {
				if descriptor.ArtifactType == artifactType {
					filtered = append(filtered, descriptor)
				}
			}
			descriptors = filtered
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(oci.ReferrersResponse{Manifests: descriptors})
	default:
		http.NotFound(w, req)
	}
}

func (r *testOCIRegistry) manifestCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.manifests)
}

func (r *testOCIRegistry) manifest(t *testing.T, key string) []byte {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	data, ok := r.manifests[key]
	if !ok {
		t.Fatalf("manifest %q not found", key)
	}
	return append([]byte(nil), data...)
}

func (r *testOCIRegistry) manifestContentType(key string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.manifestContentTypes[key]
}

func (r *testOCIRegistry) blob(t *testing.T, digest string) []byte {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	data, ok := r.blobs[digest]
	if !ok {
		t.Fatalf("blob %q not found", digest)
	}
	return append([]byte(nil), data...)
}

func (r *testOCIRegistry) blobContentType(digest string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.blobContentTypes[digest]
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
  name: node
  version: "22"
  command:
    - dist/index.js
`,
		"README.md":    "# Security Reviewer\n",
		"LICENSE":      "MIT\n",
		"package.json": `{"type":"module"}`,
		"dist/index.js": `import { writeFileSync } from "node:fs";
writeFileSync(process.env.ADVERSARY_OUTPUT, JSON.stringify({protocolVersion:1,result:{adversary:{name:"local/security-reviewer"},target:{},positives:[],observations:[],findings:[],suppressed:{observations:0,findings:0}}}));
`,
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
func copyTestTree(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, info.Mode().Perm())
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, info.Mode().Perm())
	})
	if err != nil {
		t.Fatal(err)
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

func TestReadPasswordLine(t *testing.T) {
	got, err := readPasswordLine(strings.NewReader("secret\r\n"))
	if err != nil || got != "secret" {
		t.Fatalf("password = %q, err = %v", got, err)
	}
	if _, err := readPasswordLine(strings.NewReader("\n")); err == nil {
		t.Fatal("expected empty password error")
	}
}

func TestReadTokenLine(t *testing.T) {
	got, err := readSecretLine(strings.NewReader("adv_sa_secret\r\n"), "token")
	if err != nil || got != "adv_sa_secret" {
		t.Fatalf("token = %q, err = %v", got, err)
	}
	if _, err := readSecretLine(strings.NewReader("\n"), "token"); err == nil || !strings.Contains(err.Error(), "token") {
		t.Fatalf("empty token error=%v", err)
	}
}

func TestScopedAuthNeverCrossesServiceOrProfile(t *testing.T) {
	store := adversarylabs.ConfigStore{Path: filepath.Join(t.TempDir(), "config.json")}
	for _, tc := range []struct{ api, profile, token string }{{"https://one.example/api", "default", "one"}, {"https://two.example/api", "work", "two"}} {
		if err := store.SetAuth(adversarylabs.AuthKey(tc.api, tc.profile), adversarylabs.Auth{Token: tc.token, RegistryHost: adversarylabs.ResolveRegistryHost()}); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct{ api, profile, token string }{{"https://one.example/api", "default", "one"}, {"https://two.example/api", "work", "two"}} {
		auth, ok, err := scopedAuth(store, tc.api, tc.profile, adversarylabs.DefaultRegistry)
		if err != nil || !ok || auth.Token != tc.token {
			t.Fatalf("%s/%s = %#v,%v,%v", tc.api, tc.profile, auth, ok, err)
		}
	}
	if _, ok, err := scopedAuth(store, "https://one.example/api", "work", adversarylabs.DefaultRegistry); err != nil || ok {
		t.Fatalf("cross-profile credential: ok=%v err=%v", ok, err)
	}
	if _, ok, err := scopedAuth(store, "https://three.example/api", "default", adversarylabs.DefaultRegistry); err != nil || ok {
		t.Fatalf("cross-service credential: ok=%v err=%v", ok, err)
	}
}

func TestLoginWithDeviceRendersInstructionsAndToken(t *testing.T) {
	client := adversarylabs.Client{BaseURL: "https://api.test", HTTP: &http.Client{Transport: cmdRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		if strings.HasSuffix(req.URL.Path, "/device/code") {
			return jsonHTTPResponse(http.StatusOK, `{"device_code":"device","user_code":"ABCD","verification_uri":"https://verify.test","expires_in":60}`), nil
		}
		return jsonHTTPResponse(http.StatusOK, `{"token":"token"}`), nil
	})}}
	var out bytes.Buffer
	token, err := loginWithDevice(context.Background(), newSystemClock(), &out, client, &loginOptions{ci: true})
	if err != nil || token.Token != "token" {
		t.Fatalf("token=%#v err=%v", token, err)
	}
	if !strings.Contains(out.String(), "https://verify.test") || !strings.Contains(out.String(), "ABCD") {
		t.Fatalf("output = %q", out.String())
	}
}

func TestLoginCISelectsDeviceFlowAndProfile(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	var deviceCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/v1/auth/device/code":
			deviceCalls++
			fmt.Fprint(w, `{"device_code":"device","user_code":"ABCD","verification_uri":"https://verify.test","expires_in":60}`)
		case "/v1/auth/device/token":
			fmt.Fprint(w, `{"token":"ci-token"}`)
		default:
			http.NotFound(w, req)
		}
	}))
	defer server.Close()
	var out, errOut bytes.Buffer
	cmd := NewRootCommand(&out, &errOut)
	cmd.SetArgs([]string{"--api-url", server.URL, "--profile", "ci", "login", "--ci"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if deviceCalls != 1 {
		t.Fatalf("device calls = %d", deviceCalls)
	}
	store, _ := adversarylabs.DefaultConfigStore()
	auth, ok, err := store.AuthE(adversarylabs.AuthKey(server.URL, "ci"))
	if err != nil || !ok || auth.Token != "ci-token" {
		t.Fatalf("stored auth=%#v ok=%v err=%v", auth, ok, err)
	}
}

func TestWaitForLoginCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	client := adversarylabs.Client{BaseURL: "https://api.test", HTTP: &http.Client{Transport: cmdRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		return jsonHTTPResponse(http.StatusBadGateway, `{}`), nil
	})}}
	_, err := waitForLogin(ctx, newSystemClock(), client, adversarylabs.DeviceLogin{DeviceCode: "device", ExpiresIn: 60, Interval: 1})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v", err)
	}
}

func TestWaitForLoginExpiry(t *testing.T) {
	client := adversarylabs.Client{BaseURL: "https://api.test", HTTP: &http.Client{Transport: cmdRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		return jsonHTTPResponse(http.StatusBadGateway, `{}`), nil
	})}}
	_, err := waitForLogin(context.Background(), newSystemClock(), client, adversarylabs.DeviceLogin{DeviceCode: "device", ExpiresIn: 1, Interval: 1})
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("error = %v", err)
	}
}

func TestWaitForLoginCancelsBlockedPollAtExpiryWithoutExtraPoll(t *testing.T) {
	var polls int
	canceled := make(chan struct{})
	client := adversarylabs.Client{BaseURL: "https://api.test", HTTP: &http.Client{Transport: cmdRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		polls++
		<-req.Context().Done()
		close(canceled)
		return nil, req.Context().Err()
	})}}
	_, err := waitForLogin(context.Background(), newSystemClock(), client, adversarylabs.DeviceLogin{DeviceCode: "device", ExpiresIn: 1, Interval: 1})
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("error = %v", err)
	}
	select {
	case <-canceled:
	default:
		t.Fatal("in-flight poll context was not canceled")
	}
	if polls != 1 {
		t.Fatalf("polls = %d", polls)
	}
}

func TestNewOCIRegistryAlwaysIncludesDockerFallback(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	store, _ := adversarylabs.DefaultConfigStore()
	factory := processRegistryFactory{store: store, docker: oci.DockerCredentialStore{}, host: adversarylabs.DefaultRegistry}
	created, err := factory.New("https://service.example/api", "missing")
	if err != nil {
		t.Fatal(err)
	}
	registry := created.(processOCIRegistry).HTTPRegistry
	chain, ok := registry.Credentials.(oci.ChainCredentialStore)
	if !ok || len(chain) != 1 {
		t.Fatalf("credentials = %#v", registry.Credentials)
	}
	if _, ok := chain[0].(oci.DockerCredentialStore); !ok {
		t.Fatalf("fallback = %T", chain[0])
	}
	if err := store.SetAuth(adversarylabs.AuthKey("https://service.example/api", "work"), adversarylabs.Auth{Token: "token", RegistryHost: adversarylabs.ResolveRegistryHost()}); err != nil {
		t.Fatal(err)
	}
	created, err = factory.New("https://service.example/api", "work")
	if err != nil {
		t.Fatal(err)
	}
	registry = created.(processOCIRegistry).HTTPRegistry
	chain, ok = registry.Credentials.(oci.ChainCredentialStore)
	if !ok || len(chain) != 2 {
		t.Fatalf("scoped credentials = %#v", registry.Credentials)
	}
	if _, ok := chain[1].(oci.DockerCredentialStore); !ok {
		t.Fatalf("fallback = %T", chain[1])
	}
}

type cmdRoundTripFunc func(*http.Request) (*http.Response, error)

func (f cmdRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }
func jsonHTTPResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Status: http.StatusText(status), Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(body))}
}
