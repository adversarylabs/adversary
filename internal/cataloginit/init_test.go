package cataloginit

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestCreateGeneratesLocalCatalog(t *testing.T) {
	destination := filepath.Join(t.TempDir(), "private-adversaries")
	result, err := Create(Options{Destination: destination})
	if err != nil {
		t.Fatal(err)
	}
	if result.Location != destination {
		t.Fatalf("location=%q want %q", result.Location, destination)
	}
	for _, name := range []string{
		"adversarylabs.yaml",
		"adversary.train.yaml",
		".gitignore",
		".github/workflows/adversary-review.yml",
		".github/workflows/version-adversaries.yml",
		".github/workflows/publish-adversary.yml",
		"README.md",
		"adversaries/data-integrity/README.md",
		"adversaries/migrations-and-backfills/README.md",
		"adversaries/tenant-and-access-boundaries/README.md",
		"adversaries/reliability-and-concurrency/README.md",
		"adversaries/compatibility/README.md",
		"adversaries/operability/README.md",
		"adversaries/engineering-conventions/README.md",
		"adversaries/tenant-and-access-boundaries/adversary.yaml",
		"adversaries/tenant-and-access-boundaries/package.json",
		"adversaries/tenant-and-access-boundaries/package-lock.json",
		"adversaries/tenant-and-access-boundaries/src/index.ts",
		"adversaries/tenant-and-access-boundaries/src/deterministic.ts",
		"adversaries/tenant-and-access-boundaries/dist/index.js",
		"adversaries/tenant-and-access-boundaries/test/index.test.ts",
		"adversaries/tenant-and-access-boundaries/docs/scope.md",
		"evaluations/.gitkeep",
		"exceptions/.gitkeep",
	} {
		if _, err := os.Stat(filepath.Join(destination, filepath.FromSlash(name))); err != nil {
			t.Fatalf("missing %s: %v", name, err)
		}
	}
	manifest, err := os.ReadFile(filepath.Join(destination, "adversarylabs.yaml"))
	if err != nil || !strings.Contains(string(manifest), "kind: AdversaryCatalog") {
		t.Fatalf("manifest=%q err=%v", manifest, err)
	}
	ignore, err := os.ReadFile(filepath.Join(destination, ".gitignore"))
	if err != nil || !strings.Contains(string(ignore), "node_modules/") || !strings.Contains(string(ignore), ".adversary/") {
		t.Fatalf("gitignore=%q err=%v", ignore, err)
	}
	var catalog struct {
		Spec struct {
			Adversaries []struct {
				ID      string `yaml:"id"`
				Path    string `yaml:"path"`
				Summary string `yaml:"summary"`
			} `yaml:"adversaries"`
		} `yaml:"spec"`
	}
	if err := yaml.Unmarshal(manifest, &catalog); err != nil {
		t.Fatalf("parse generated manifest: %v", err)
	}
	if len(catalog.Spec.Adversaries) != len(starterAdversaries) {
		t.Fatalf("manifest adversaries=%d want %d", len(catalog.Spec.Adversaries), len(starterAdversaries))
	}
	for index, adversary := range starterAdversaries {
		entry := catalog.Spec.Adversaries[index]
		if entry.ID != adversary.Slug || entry.Path != "adversaries/"+adversary.Slug || entry.Summary != adversary.Summary {
			t.Fatalf("manifest adversary[%d]=%+v", index, entry)
		}
		brief, err := os.ReadFile(filepath.Join(destination, "adversaries", adversary.Slug, "README.md"))
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{adversary.Title, adversary.Summary, "Evidence standard", "Learning notes"} {
			if !strings.Contains(string(brief), want) {
				t.Fatalf("%s brief missing %q", adversary.Slug, want)
			}
		}
		for _, name := range []string{"adversary.yaml", "package.json", "package-lock.json", "src/index.ts", "src/deterministic.ts", "dist/index.js", "dist/deterministic.js", "test/index.test.ts", "docs/scope.md"} {
			if _, err := os.Stat(filepath.Join(destination, "adversaries", adversary.Slug, filepath.FromSlash(name))); err != nil {
				t.Fatalf("%s is not runnable; missing %s: %v", adversary.Slug, name, err)
			}
		}
	}
	operability, err := os.ReadFile(filepath.Join(destination, "adversaries", "operability", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"User-facing errors", "concrete recovery step", "underlying cause", "leak secrets", "logs, metrics, and traces", "identifiers operators need"} {
		if !strings.Contains(string(operability), want) {
			t.Fatalf("operability brief missing %q:\n%s", want, operability)
		}
	}
	packageJSON, err := os.ReadFile(filepath.Join(destination, "adversaries", "operability", "package.json"))
	if err != nil || !strings.Contains(string(packageJSON), `"adversarylabsCatalogRuntime": 1`) {
		t.Fatalf("managed runtime package=%q err=%v", packageJSON, err)
	}
	source, err := os.ReadFile(filepath.Join(destination, "adversaries", "operability", "src", "index.ts"))
	if err != nil || !strings.Contains(string(source), "loadLearnedRules") || !strings.Contains(string(source), `../rules/`) || !strings.Contains(string(source), "registerDeterministicRules(app)") {
		t.Fatalf("managed runtime source does not discover learned rules: %q err=%v", source, err)
	}
	for name, wants := range map[string][]string{
		"adversary-review.yml":    {"paths:", "adversarylabs/actions/run@v1", "adversaries: adversarylabs/adversary", "matrix.adversary"},
		"version-adversaries.yml": {"workflow_dispatch:", "Continue serial versioning", "adversarylabs/actions/version@v1", "[skip-ci]", "gh workflow run publish-adversary.yml", "actions: write"},
		"publish-adversary.yml":   {"workflow_dispatch:", "id-token: write", "adversarylabs/actions/push@v1", "auth-mode: oidc", "ADVERSARY_REGISTRY_NAMESPACE", "inputs.commit"},
	} {
		raw, err := os.ReadFile(filepath.Join(destination, ".github", "workflows", name))
		if err != nil {
			t.Fatal(err)
		}
		var workflow any
		if err := yaml.Unmarshal(raw, &workflow); err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, want := range wants {
			if !strings.Contains(string(raw), want) {
				t.Fatalf("%s missing %q:\n%s", name, want, raw)
			}
		}
	}
}

func TestCreateGeneratesVersionActionCompatibleNodeRuntimes(t *testing.T) {
	destination := filepath.Join(t.TempDir(), "private-adversaries")
	if _, err := Create(Options{Destination: destination}); err != nil {
		t.Fatal(err)
	}

	for _, adversary := range starterAdversaries {
		dir := filepath.Join(destination, "adversaries", adversary.Slug)
		manifest, err := os.ReadFile(filepath.Join(dir, "adversary.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(manifest), "  command:\n    - dist/index.js\n") {
			t.Fatalf("%s runtime command is not a block-style string list:\n%s", adversary.Slug, manifest)
		}
		if strings.Contains(string(manifest), "command: [") {
			t.Fatalf("%s runtime command uses unsupported inline YAML:\n%s", adversary.Slug, manifest)
		}

		for _, name := range []string{"src/index.ts", "dist/index.js"} {
			source, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(name)))
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`readFileSync(new URL("../package.json", import.meta.url), "utf8")`,
				"version: packageVersion",
			} {
				if !strings.Contains(string(source), want) {
					t.Fatalf("%s/%s missing %q:\n%s", adversary.Slug, name, want, source)
				}
			}
			if strings.Contains(string(source), `version: "0.0.1"`) {
				t.Fatalf("%s/%s hard-codes the runtime version:\n%s", adversary.Slug, name, source)
			}
		}
	}
}

func TestUpgradePreservesPoliciesAndMakesEntriesRunnable(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "adversarylabs.yaml"), []byte("kind: AdversaryCatalog\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".gitignore"), []byte("custom-cache/\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "adversaries", "operability")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	policy := "# Operability\n\n## Purpose\n\nKeep failures actionable.\n"
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte(policy), 0o644); err != nil {
		t.Fatal(err)
	}
	result, err := Upgrade(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Upgraded) != 1 || result.Upgraded[0] != "operability" {
		t.Fatalf("result=%+v", result)
	}
	if !result.IgnoreUpdated {
		t.Fatal("upgrade did not harden the catalog .gitignore")
	}
	ignore, err := os.ReadFile(filepath.Join(root, ".gitignore"))
	if err != nil || !strings.Contains(string(ignore), "custom-cache/") || !strings.Contains(string(ignore), "node_modules/") {
		t.Fatalf("gitignore=%q err=%v", ignore, err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "README.md"))
	if err != nil || string(raw) != policy {
		t.Fatalf("README changed: %q err=%v", raw, err)
	}
	for _, name := range []string{"adversary.yaml", "package.json", "src/index.ts", "src/deterministic.ts", "dist/index.js", "test/index.test.ts"} {
		if _, err := os.Stat(filepath.Join(dir, filepath.FromSlash(name))); err != nil {
			t.Fatalf("missing %s: %v", name, err)
		}
	}
	again, err := Upgrade(root)
	if err != nil || len(again.Upgraded) != 0 || again.IgnoreUpdated {
		t.Fatalf("second upgrade=%+v err=%v", again, err)
	}
}

func TestUpgradeSynchronizesManagedV1RuntimeFiles(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "adversaries", "operability")
	if err := os.MkdirAll(filepath.Join(dir, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	originalPackage := `{"adversarylabsCatalogRuntime": 1, "dependencies": {"@adversarylabs/sdk": "^9.9.9"}}`
	originalLock := `{"lockfileVersion": 3, "catalogOwned": true}`
	for path, content := range map[string]string{
		"adversarylabs.yaml":                        "kind: AdversaryCatalog\n",
		"adversaries/operability/README.md":         "# Operability\n\n## Purpose\n\nKeep failures actionable.\n",
		"adversaries/operability/adversary.yaml":    "name: private/operability\n",
		"adversaries/operability/package.json":      originalPackage,
		"adversaries/operability/package-lock.json": originalLock,
		"adversaries/operability/src/index.ts":      "// managed v1\n",
	} {
		full := filepath.Join(root, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	result, err := Upgrade(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Upgraded) != 1 || result.Upgraded[0] != "operability" {
		t.Fatalf("result=%+v", result)
	}
	packageJSON, _ := os.ReadFile(filepath.Join(dir, "package.json"))
	packageLock, _ := os.ReadFile(filepath.Join(dir, "package-lock.json"))
	source, _ := os.ReadFile(filepath.Join(dir, "src", "index.ts"))
	readme, _ := os.ReadFile(filepath.Join(dir, "README.md"))
	if string(packageJSON) != originalPackage || string(packageLock) != originalLock || !strings.Contains(string(source), "loadLearnedRules") {
		t.Fatalf("runtime was not synchronized: package=%s source=%s", packageJSON, source)
	}
	if !strings.Contains(string(readme), "Keep failures actionable") {
		t.Fatalf("policy changed: %s", readme)
	}
}

func TestUpgradeRaisesOlderSDKWithoutReplacingPackageMetadata(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "adversaries", "operability")
	templateLock, err := os.ReadFile(filepath.Join("..", "..", "templates", "typescript", "package-lock.json"))
	if err != nil {
		t.Fatal(err)
	}
	oldLock := strings.ReplaceAll(string(templateLock), "{{name}}", "operability")
	oldLock = strings.ReplaceAll(oldLock, `"version": "something"`, `"version": "0.0.1"`)
	oldLock = strings.ReplaceAll(oldLock, "0.1.32", "0.1.23")
	oldLock = strings.ReplaceAll(oldLock, "fUXop08OXOyDYFaYJSh4boZ64DITA4720oYk15i1XJFMo5jtq0QmPXkLmCn+cCqrIxE7mQrnOrx74/ET6bRvkQ==", "old-integrity")
	oldPackage := `{
  "name": "operability",
  "adversarylabsCatalogRuntime": 1,
  "catalogOwned": true,
  "dependencies": {"@adversarylabs/sdk": "^0.1.23", "other": "1.2.3"}
}`
	for path, content := range map[string]string{
		"adversarylabs.yaml":                        "kind: AdversaryCatalog\n",
		"adversaries/operability/README.md":         "# Operability\n",
		"adversaries/operability/adversary.yaml":    "name: private/operability\n",
		"adversaries/operability/package.json":      oldPackage,
		"adversaries/operability/package-lock.json": oldLock,
		"adversaries/operability/src/index.ts":      "// managed v1\n",
	} {
		full := filepath.Join(root, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Upgrade(root); err != nil {
		t.Fatal(err)
	}
	packageJSON, _ := os.ReadFile(filepath.Join(dir, "package.json"))
	packageLock, _ := os.ReadFile(filepath.Join(dir, "package-lock.json"))
	expectedPackage := strings.Replace(oldPackage, "^0.1.23", "^0.1.32", 1)
	if string(packageJSON) != expectedPackage {
		t.Fatalf("package.json formatting changed:\n%s", packageJSON)
	}
	expectedLock := strings.ReplaceAll(oldLock, "0.1.23", "0.1.32")
	expectedLock = strings.Replace(expectedLock, "old-integrity", "fUXop08OXOyDYFaYJSh4boZ64DITA4720oYk15i1XJFMo5jtq0QmPXkLmCn+cCqrIxE7mQrnOrx74/ET6bRvkQ==", 1)
	if string(packageLock) != expectedLock {
		t.Fatal("package-lock.json formatting or unrelated metadata changed")
	}
	for _, required := range []string{`"catalogOwned": true`, `"other": "1.2.3"`, `"@adversarylabs/sdk": "^0.1.32"`} {
		if !strings.Contains(string(packageJSON), required) {
			t.Fatalf("package.json missing %s: %s", required, packageJSON)
		}
	}
	for _, required := range []string{`"@adversarylabs/sdk": "^0.1.32"`, `"version": "0.1.32"`, "ppoM1NLRRABGjUZtoI150/2PL/nFEkBFZ0pe5UeB2bhU0soQrbah6U4171/F4gfpKwcT+99LtI5H1WcWpjgglQ=="} {
		if !strings.Contains(string(packageLock), required) {
			t.Fatalf("package-lock.json missing %s", required)
		}
	}
}

func TestUpgradeCanPinSDKCommitForPremergeValidation(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "adversaries", "operability")
	dependency := "https://github.com/adversarylabs/adversary-sdk-typescript/archive/abc123.tar.gz"
	lockTemplate := filepath.Join(t.TempDir(), "package-lock.json")
	if err := os.WriteFile(lockTemplate, []byte(`{"packages":{"":{"dependencies":{"@adversarylabs/sdk":"`+dependency+`"}},"node_modules/@adversarylabs/sdk":{"version":"0.1.32","resolved":"`+dependency+`","integrity":"sha512-test"}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv(sdkDependencyOverrideEnv, dependency)
	t.Setenv(sdkLockOverrideEnv, lockTemplate)
	for path, content := range map[string]string{
		"README.md":         "# Operability\n",
		"adversary.yaml":    "name: private/operability\n",
		"package.json":      `{"adversarylabsCatalogRuntime":1,"dependencies":{"@adversarylabs/sdk":"^0.1.32"}}`,
		"package-lock.json": `{"packages":{"":{"dependencies":{"@adversarylabs/sdk":"^0.1.32"}},"node_modules/@adversarylabs/sdk":{"version":"0.1.32","resolved":"registry","integrity":"old"}}}`,
	} {
		full := filepath.Join(dir, path)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	updated, err := EnsureRunnableAdversary(dir, "operability")
	if err != nil || !updated {
		t.Fatalf("updated=%v err=%v", updated, err)
	}
	packageJSON, _ := os.ReadFile(filepath.Join(dir, "package.json"))
	packageLock, _ := os.ReadFile(filepath.Join(dir, "package-lock.json"))
	if !strings.Contains(string(packageJSON), dependency) || !strings.Contains(string(packageLock), dependency) || !strings.Contains(string(packageLock), "sha512-test") {
		t.Fatalf("SDK commit pin was not synchronized: package=%s lock=%s", packageJSON, packageLock)
	}
}

func TestUpgradePreservesCatalogOwnedDeterministicRegistrations(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "adversaries", "operability")
	custom := "export function registerDeterministicRules(app: unknown) { void app; }\n"
	for path, content := range map[string]string{
		"adversarylabs.yaml":                           "kind: AdversaryCatalog\n",
		"adversaries/operability/README.md":            "# Operability\n",
		"adversaries/operability/adversary.yaml":       "name: private/operability\n",
		"adversaries/operability/package.json":         `{"adversarylabsCatalogRuntime": 1}`,
		"adversaries/operability/src/index.ts":         "// managed v1\n",
		"adversaries/operability/src/deterministic.ts": custom,
	} {
		full := filepath.Join(root, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Upgrade(root); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "src", "deterministic.ts"))
	if err != nil || string(got) != custom {
		t.Fatalf("deterministic registrations changed: %q err=%v", got, err)
	}
}

func TestCreateRefusesExistingDestination(t *testing.T) {
	destination := t.TempDir()
	if _, err := Create(Options{Destination: destination}); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("err=%v", err)
	}
}

func TestRenderSuccessIncludesNextSteps(t *testing.T) {
	var output bytes.Buffer
	RenderSuccess(&output, Result{Location: "/tmp/private catalog"}, "linux")
	for _, want := range []string{"Generated catalog with 7 starter adversaries", "git init", "git commit", "'/tmp/private catalog'", "adversary catalog train", "adversary catalog train review"} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("output %q missing %q", output.String(), want)
		}
	}
}
