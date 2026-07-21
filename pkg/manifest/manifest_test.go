package manifest

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	distref "github.com/distribution/reference"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"go.yaml.in/yaml/v3"
)

const valid = `name: adversarylabs/example
version: 1.2.3
triggers:
  manual: true
  files_changed: ["**/*.go"]
runtime:
  name: node
  version: "22"
  command: [dist/index.js]
permissions:
  filesystem:
    read: ["."]
    write: [.adversary/results]
  network: false
  environment:
    allow: [CI]
findings:
  format: adversary.review.v1
`

func TestParseValid(t *testing.T) {
	m, err := Parse([]byte(valid))
	if err != nil {
		t.Fatal(err)
	}
	if m.Name != "adversarylabs/example" || len(m.Runtime.Command) != 1 || m.Permissions.Network == nil || *m.Permissions.Network {
		t.Fatalf("unexpected manifest: %#v", m)
	}
}

func TestParseDetectionContract(t *testing.T) {
	input := strings.Replace(valid, "runtime:\n", `detection:
  files: [Dockerfile, "**/Dockerfile"]
  repository_files: [package.json]
  change_types: [added, modified, renamed]
  entrypoint: dist/detect.js
runtime:
`, 1)
	m, err := Parse([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Detection.Files) != 2 || m.Detection.Entrypoint != "dist/detect.js" {
		t.Fatalf("detection = %#v", m.Detection)
	}
}

func TestParseDetectionRejectsInvalidContract(t *testing.T) {
	for _, detection := range []string{
		"  files: ['  ']\n",
		"  change_types: [conflicted]\n",
		"  entrypoint: ../detect.js\n",
		"  entrypoint: dist/detect.ts\n",
	} {
		input := strings.Replace(valid, "runtime:\n", "detection:\n"+detection+"runtime:\n", 1)
		if _, err := Parse([]byte(input)); err == nil {
			t.Fatalf("accepted detection declaration:\n%s", detection)
		}
	}
}

func TestDetectionEntrypointRequiresNodeRuntime(t *testing.T) {
	input := strings.Replace(valid, "runtime:\n  name: node\n  version: \"22\"\n  command: [dist/index.js]\n", "detection:\n  entrypoint: dist/detect.js\nruntime:\n  name: process\n  version: \"1\"\n  command: [bin/review]\n", 1)
	if _, err := Parse([]byte(input)); err == nil || !strings.Contains(err.Error(), "requires runtime.name node") {
		t.Fatalf("error = %v", err)
	}
}

func TestParseEnvironmentAllowPermission(t *testing.T) {
	input := strings.Replace(valid, "    allow: [CI]\n", "    allow: [CI, HOME]\n", 1)
	m, err := Parse([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	if got := m.Permissions.Environment.Allow; len(got) != 2 || got[0] != "CI" || got[1] != "HOME" {
		t.Fatalf("environment.allow=%#v", got)
	}
	if _, err := Parse([]byte(strings.Replace(input, "allow: [CI, HOME]", "allow: [BAD-NAME]", 1))); err == nil {
		t.Fatal("invalid environment.allow was accepted")
	}
}

func TestParsePermissionEnforcement(t *testing.T) {
	input := strings.Replace(valid, "permissions:\n", "permissions:\n  enforcement: required\n", 1)
	m, err := Parse([]byte(input))
	if err != nil || m.Permissions.Enforcement != "required" {
		t.Fatalf("enforcement=%q error=%v", m.Permissions.Enforcement, err)
	}
	if _, err := Parse([]byte(strings.Replace(input, "enforcement: required", "enforcement: best-effort", 1))); err == nil {
		t.Fatal("unsupported enforcement mode was accepted")
	}
}

func TestValidateProjectNameNPMBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name string
		ok   bool
	}{
		{strings.Repeat("a", 214), true},
		{strings.Repeat("a", 215), false},
		{"node-module", true},
		{"favicon-ico", true},
		{"https-review", true},
	} {
		if err := ValidateProjectName(tc.name); (err == nil) != tc.ok {
			t.Errorf("ValidateProjectName(len=%d, %q) error = %v, want valid=%t", len(tc.name), tc.name, err, tc.ok)
		}
	}
}

func TestValidateProjectNameRejectsMaintainedNPMReservedMatrix(t *testing.T) {
	for name := range npmReservedProjectNames {
		if err := ValidateProjectName(name); err == nil || !strings.Contains(err.Error(), "reserved") {
			t.Errorf("ValidateProjectName(%q) error = %v, want reserved-name error", name, err)
		}
	}
}

func TestParseRejectsUnsafeAndInvalidInput(t *testing.T) {
	tests := map[string]string{
		"unknown field":      valid + "unknown: true\n",
		"duplicate":          strings.Replace(valid, "name: adversarylabs/example", "name: adversarylabs/example\nname: other/example", 1),
		"alias":              strings.Replace(valid, "command: [dist/index.js]", "command: &cmd [dist/index.js]", 1),
		"name":               strings.Replace(valid, "adversarylabs/example", "Adversary Labs/example", 1),
		"version":            strings.Replace(valid, "1.2.3", "latest", 1),
		"runtime":            strings.Replace(valid, "name: node", "name: shell", 1),
		"command":            strings.Replace(valid, "command: [dist/index.js]", "command: []", 1),
		"findings":           strings.Replace(valid, "adversary.review.v1", "sarif", 1),
		"environment":        strings.Replace(valid, "allow: [CI]", "allow: [BAD-NAME]", 1),
		"path":               strings.Replace(valid, `read: ["."]`, `read: [""]`, 1),
		"absolute path":      strings.Replace(valid, `read: ["."]`, `read: ["/etc"]`, 1),
		"escaping path":      strings.Replace(valid, `read: ["."]`, `read: ["../secret"]`, 1),
		"duplicate path":     strings.Replace(valid, `write: [.adversary/results]`, `write: ["."]`, 1),
		"runtime constraint": strings.Replace(valid, `version: "22"`, `version: "latest"`, 1),
		"glob":               strings.Replace(valid, `files_changed: ["**/*.go"]`, `files_changed: [""]`, 1),
		"documents":          valid + "---\n" + valid,
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(input)); err == nil {
				t.Fatal("Parse succeeded")
			}
		})
	}
}

func TestValidateProjectChecksDeclaredRuntimeConsistency(t *testing.T) {
	dir := t.TempDir()
	m, err := Parse([]byte(valid))
	if err != nil {
		t.Fatal(err)
	}
	if err := m.ValidateProject(dir); err == nil || !strings.Contains(err.Error(), "package.json") {
		t.Fatalf("error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := m.ValidateProject(dir); err != nil {
		t.Fatal(err)
	}
	m.Runtime.Command[0] = "bin/tool"
	if err := m.ValidateProject(dir); err == nil || !strings.Contains(err.Error(), "JavaScript") {
		t.Fatalf("error = %v", err)
	}
}

func TestNodeEntrypointMustRemainWithinProjectWithoutRequiringBuildOutput(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	m, err := Parse([]byte(valid))
	if err != nil {
		t.Fatal(err)
	}
	// dist/index.js deliberately does not exist: validation is lexical and must
	// support a source checkout before its build step.
	if err := m.ValidateProject(dir); err != nil {
		t.Fatalf("not-yet-built entrypoint rejected: %v", err)
	}
	for _, entrypoint := range []string{"../evil.js", "/tmp/evil.js", `..\evil.js`, `C:\evil.js`, "C:/evil.js", "dist/../evil.js"} {
		t.Run(entrypoint, func(t *testing.T) {
			input := strings.Replace(valid, "command: [dist/index.js]", fmt.Sprintf("command: [%q]", entrypoint), 1)
			if _, err := Parse([]byte(input)); err == nil {
				t.Fatal("Parse succeeded")
			}
		})
	}
}

func TestMalformedYAMLPolicyCorpus(t *testing.T) {
	for name, input := range map[string]string{
		"multiline scalar command": strings.Replace(valid, "command: [dist/index.js]", "command: [|\n      dist/index.js]", 1),
		"unicode confusable key":   strings.Replace(valid, "runtime:", "runtіme:", 1),
		"alias use":                strings.Replace(valid, "command: [dist/index.js]", "command: &command [dist/index.js]\n  image: *command", 1),
		"nested duplicate":         strings.Replace(valid, "manual: true", "manual: true\n  manual: false", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(input)); err == nil {
				t.Fatal("Parse succeeded")
			}
		})
	}
}

func TestParseSizeBound(t *testing.T) {
	if _, err := Parse(make([]byte, MaxSize+1)); err == nil {
		t.Fatal("Parse succeeded")
	}
}

func TestSemanticVersionParity(t *testing.T) {
	validVersions := []string{"0.0.0", "1.2.3", "1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-0A", "1.0.0+build.7", "1.0.0-beta+exp.sha"}
	invalidVersions := []string{"01.2.3", "1.02.3", "1.2.03", "1.2", "1.2.3-", "1.2.3-01", "1.2.3-alpha..1", "1.2.3+", "1.2.3+build..1"}
	for _, version := range validVersions {
		t.Run("valid/"+version, func(t *testing.T) {
			if _, err := Parse([]byte(strings.Replace(valid, "1.2.3", version, 1))); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, version := range invalidVersions {
		t.Run("invalid/"+version, func(t *testing.T) {
			if _, err := Parse([]byte(strings.Replace(valid, "1.2.3", version, 1))); err == nil {
				t.Fatal("Parse succeeded")
			}
		})
	}
}

func TestRuntimeImageStillValidatesOptionalFields(t *testing.T) {
	base := strings.Replace(valid, "  name: node\n  version: \"22\"", "  image: example.invalid/adversary:1", 1)
	if _, err := Parse([]byte(base)); err != nil {
		t.Fatal(err)
	}
	for name, replacement := range map[string]string{
		"name":        "  image: example.invalid/adversary:1\n  name: process",
		"version":     "  image: example.invalid/adversary:1\n  version: \" 22\"",
		"empty image": "  image: \"\"",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(strings.Replace(base, "  image: example.invalid/adversary:1", replacement, 1))); err == nil {
				t.Fatal("Parse succeeded")
			}
		})
	}
}

func TestRuntimeExecutionIdentityAndImageReference(t *testing.T) {
	t.Setenv("ADVERSARY_REGISTRY_HOST", "evil.invalid")
	imageManifest := func(image string) string {
		return strings.Replace(valid, "  name: node\n  version: \"22\"\n  command: [dist/index.js]", fmt.Sprintf("  image: %q\n  command: [/usr/local/bin/review]", image), 1)
	}
	digest := "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	for _, tc := range []struct{ input, canonical string }{
		{"node:22", "docker.io/library/node:22"},
		{"team/reviewer", "docker.io/team/reviewer:latest"},
		{"ghcr.io/adversarylabs/reviewer:v1.2.3", "ghcr.io/adversarylabs/reviewer:v1.2.3"},
		{"registry.example:5000/team/reviewer:release-1", "registry.example:5000/team/reviewer:release-1"},
		{"[2001:db8::1]:5000/team/reviewer:v1", "[2001:db8::1]:5000/team/reviewer:v1"},
		{"[2001:DB8::A]:5000/team/reviewer:v1", "[2001:DB8::A]:5000/team/reviewer:v1"},
		{"team/reviewer@" + digest, "docker.io/team/reviewer@" + digest},
		{"team/reviewer:v1@" + digest, "docker.io/team/reviewer:v1@" + digest},
		{"team/reviewer@sha384:" + strings.Repeat("a", 96), "docker.io/team/reviewer@sha384:" + strings.Repeat("a", 96)},
		{"team/reviewer@sha512:" + strings.Repeat("b", 128), "docker.io/team/reviewer@sha512:" + strings.Repeat("b", 128)},
	} {
		t.Run("valid/"+tc.input, func(t *testing.T) {
			m, err := Parse([]byte(imageManifest(tc.input)))
			if err != nil {
				t.Fatal(err)
			}
			if m.Runtime.Image != tc.canonical {
				t.Fatalf("canonical runtime.image=%q want %q", m.Runtime.Image, tc.canonical)
			}
			if _, err := distref.Parse(m.Runtime.Image); err != nil {
				t.Fatalf("canonical image rejected by distribution/reference: %v", err)
			}
			// Image commands are image-internal; neither the command nor a host
			// package descriptor needs to exist in the project checkout.
			if err := m.ValidateProject(t.TempDir()); err != nil {
				t.Fatalf("ValidateProject: %v", err)
			}
		})
	}

	for name, image := range map[string]string{
		"whitespace":        "node:2 2",
		"scheme":            "https://registry.example/team/reviewer:1",
		"credentials":       "user:password@registry.example/team/reviewer:1",
		"uppercase repo":    "registry.example/Team/reviewer:1",
		"empty component":   "registry.example/team//reviewer:1",
		"malformed tag":     "team/reviewer:-latest",
		"short digest":      "team/reviewer@sha256:abcd",
		"missing algorithm": "team/reviewer@0123456789abcdef0123456789abcdef",
		"invalid IPv6":      "[2001:::1]/team/reviewer:v1",
		"invalid port":      "registry.example:99999/team/reviewer:v1",
	} {
		t.Run("invalid/"+name, func(t *testing.T) {
			if _, err := Parse([]byte(imageManifest(image))); err == nil {
				t.Fatalf("Parse accepted runtime.image %q", image)
			}
		})
	}

	t.Run("both", func(t *testing.T) {
		input := strings.Replace(valid, "  name: node", "  name: node\n  image: node:22", 1)
		if _, err := Parse([]byte(input)); err == nil {
			t.Fatal("Parse accepted both runtime identities")
		}
	})
	t.Run("neither", func(t *testing.T) {
		input := strings.Replace(valid, "  name: node\n  version: \"22\"", "", 1)
		if _, err := Parse([]byte(input)); err == nil {
			t.Fatal("Parse accepted no runtime identity")
		}
	})
}

func TestRuntimeImageSchemaParserAndDownstreamBoundaries(t *testing.T) {
	schemaData, err := os.ReadFile(filepath.Join("..", "..", "schema", "adversary.manifest.v1.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schemaDocument any
	if err := json.Unmarshal(schemaData, &schemaDocument); err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	const schemaURL = "https://adversary.dev/schemas/adversary.manifest.v1.schema.json"
	if err := compiler.AddResource(schemaURL, schemaDocument); err != nil {
		t.Fatal(err)
	}
	compiled, err := compiler.Compile(schemaURL)
	if err != nil {
		t.Fatal(err)
	}

	imageManifest := func(image string) string {
		return strings.Replace(valid, "  name: node\n  version: \"22\"\n  command: [dist/index.js]", fmt.Sprintf("  image: %q\n  command: [/bin/review]", image), 1)
	}
	path247 := strings.Repeat("a", 247) // "library/" + 247 is the normalized 255-byte path.
	path255 := strings.Repeat("a", 255)
	for name, tc := range map[string]struct {
		image                               string
		schemaValid, parserValid, distValid bool
	}{
		"port lower bound":           {"registry.example:1/team/reviewer:v1", true, true, true},
		"port upper bound":           {"registry.example:65535/team/reviewer:v1", true, true, true},
		"zero padded zero port":      {"registry.example:00000/team/reviewer:v1", true, false, true},
		"port above upper bound":     {"registry.example:99999/team/reviewer:v1", true, false, true},
		"empty DNS label":            {"a..b/team/reviewer:v1", false, false, false},
		"malformed IPv6 literal":     {"[::::]/team/reviewer:v1", true, false, true},
		"empty IPv6 port":            {"[::1]:/team/reviewer:v1", false, false, false},
		"uppercase IPv6 hex":         {"[2001:DB8::A]:5000/team/reviewer:v1", true, true, true},
		"familiar normalized 255":    {path247 + ":v1", true, true, true},
		"familiar normalized 256":    {path247 + "a:v1", true, false, false},
		"explicit repository 256":    {"registry.example/" + path255 + "a:v1", true, false, false},
		"registry excluded from max": {"registry.example/" + path255 + ":v1", true, true, true},
	} {
		t.Run(name, func(t *testing.T) {
			input := imageManifest(tc.image)
			var document any
			if err := yaml.Unmarshal([]byte(input), &document); err != nil {
				t.Fatal(err)
			}
			if got := compiled.Validate(document) == nil; got != tc.schemaValid {
				t.Errorf("schema valid=%v want %v", got, tc.schemaValid)
			}
			if _, err := Parse([]byte(input)); (err == nil) != tc.parserValid {
				t.Errorf("parser valid=%v want %v: %v", err == nil, tc.parserValid, err)
			}
			if _, err := distref.ParseNormalizedNamed(tc.image); (err == nil) != tc.distValid {
				t.Errorf("distribution/reference valid=%v want %v: %v", err == nil, tc.distValid, err)
			}
		})
	}
}

func TestRuntimeImageDirectValidateUsesNormalizedRepositoryBoundary(t *testing.T) {
	base := Manifest{Name: "adversarylabs/example", Runtime: Runtime{Command: []string{"/bin/review"}}}
	for name, tc := range map[string]struct {
		image string
		valid bool
	}{
		"familiar normalized 255":  {strings.Repeat("a", 247) + ":v1", true},
		"familiar normalized 256":  {strings.Repeat("a", 248) + ":v1", false},
		"qualified repository 255": {"registry.example/" + strings.Repeat("a", 255) + ":v1", true},
		"qualified repository 256": {"registry.example/" + strings.Repeat("a", 256) + ":v1", false},
	} {
		t.Run(name, func(t *testing.T) {
			m := base
			m.Runtime.Image = tc.image
			if err := m.Validate(); (err == nil) != tc.valid {
				t.Fatalf("Validate valid=%v want %v: %v", err == nil, tc.valid, err)
			}
		})
	}
}

func TestOptionalFieldsRejectPresentEmptyValues(t *testing.T) {
	for name, input := range map[string]string{
		"version":         strings.Replace(valid, "version: 1.2.3", `version: ""`, 1),
		"findings format": strings.Replace(valid, "format: adversary.review.v1", `format: ""`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(input)); err == nil {
				t.Fatal("Parse succeeded")
			}
		})
	}
}

func TestPublishedFixtures(t *testing.T) {
	validFixture, err := os.ReadFile(filepath.Join("..", "..", "schema", "fixtures", "adversary.manifest.v1.valid.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(validFixture); err != nil {
		t.Fatalf("valid fixture: %v", err)
	}
	invalidFixture, err := os.ReadFile(filepath.Join("..", "..", "schema", "fixtures", "adversary.manifest.v1.invalid.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(invalidFixture); err == nil {
		t.Fatal("invalid fixture parsed successfully")
	}
}

func TestPublishedDraft2020SchemaMatchesCanonicalFixtures(t *testing.T) {
	schemaData, err := os.ReadFile(filepath.Join("..", "..", "schema", "adversary.manifest.v1.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schemaDocument any
	if err := json.Unmarshal(schemaData, &schemaDocument); err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	const schemaURL = "https://adversary.dev/schemas/adversary.manifest.v1.schema.json"
	if err := compiler.AddResource(schemaURL, schemaDocument); err != nil {
		t.Fatal(err)
	}
	compiled, err := compiler.Compile(schemaURL)
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string]struct {
		input string
		valid bool
	}{
		"valid":                {valid, true},
		"unknown":              {valid + "unknown: true\n", false},
		"bad semver":           {strings.Replace(valid, "1.2.3", "1.2.3-01", 1), false},
		"unsupported runtime":  {strings.Replace(valid, "name: node", "name: shell", 1), false},
		"empty command":        {strings.Replace(valid, "command: [dist/index.js]", "command: []", 1), false},
		"whitespace path":      {strings.Replace(valid, `read: ["."]`, `read: [" ."]`, 1), false},
		"absolute path":        {strings.Replace(valid, `read: ["."]`, `read: ["/etc"]`, 1), false},
		"traversal path":       {strings.Replace(valid, `read: ["."]`, `read: ["a/../secret"]`, 1), false},
		"backslash path":       {strings.Replace(valid, `read: ["."]`, `read: ["a\\\\secret"]`, 1), false},
		"drive path":           {strings.Replace(valid, `read: ["."]`, `read: ["C:/secret"]`, 1), false},
		"runtime both":         {strings.Replace(valid, "  name: node", "  name: node\n  image: node:22", 1), false},
		"runtime neither":      {strings.Replace(valid, "  name: node\n  version: \"22\"", "", 1), false},
		"image familiar":       {strings.Replace(valid, "  name: node\n  version: \"22\"\n  command: [dist/index.js]", "  image: node:22\n  command: [/bin/review]", 1), true},
		"image qualified":      {strings.Replace(valid, "  name: node\n  version: \"22\"\n  command: [dist/index.js]", "  image: ghcr.io/adversarylabs/reviewer:v1\n  command: [/bin/review]", 1), true},
		"image IPv6 registry":  {strings.Replace(valid, "  name: node\n  version: \"22\"\n  command: [dist/index.js]", "  image: '[2001:db8::1]:5000/adversarylabs/reviewer:v1'\n  command: [/bin/review]", 1), true},
		"image digest":         {strings.Replace(valid, "  name: node\n  version: \"22\"\n  command: [dist/index.js]", "  image: adversarylabs/reviewer@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n  command: [/bin/review]", 1), true},
		"image uppercase repo": {strings.Replace(valid, "  name: node\n  version: \"22\"", "  image: ghcr.io/Team/reviewer:v1", 1), false},
		"image scheme":         {strings.Replace(valid, "  name: node\n  version: \"22\"", "  image: https://registry.example/reviewer:v1", 1), false},
		"image credentials":    {strings.Replace(valid, "  name: node\n  version: \"22\"", "  image: user:password@registry.example/reviewer:v1", 1), false},
		"image malformed tag":  {strings.Replace(valid, "  name: node\n  version: \"22\"", "  image: adversarylabs/reviewer:-latest", 1), false},
		"image short digest":   {strings.Replace(valid, "  name: node\n  version: \"22\"", "  image: adversarylabs/reviewer@sha256:abcd", 1), false},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			var document any
			if err := yaml.Unmarshal([]byte(tc.input), &document); err != nil {
				t.Fatal(err)
			}
			schemaErr := compiled.Validate(document)
			_, parseErr := Parse([]byte(tc.input))
			if tc.valid && (schemaErr != nil || parseErr != nil) {
				t.Fatalf("validity mismatch: schema=%v parser=%v", schemaErr, parseErr)
			}
			if !tc.valid && (schemaErr == nil || parseErr == nil) {
				t.Fatalf("invalid input accepted: schema=%v parser=%v", schemaErr, parseErr)
			}
		})
	}
}

func TestParserOnlySemanticRules(t *testing.T) {
	// These rules intentionally exceed JSON Schema's structural/syntactic
	// layer and are normative in Parse/Validate.
	for name, input := range map[string]string{
		"cross-array conflict":   strings.Replace(valid, `write: [.adversary/results]`, `write: ["."]`, 1),
		"full semver constraint": strings.Replace(valid, `version: "22"`, `version: "definitely-not-semver"`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(input)); err == nil {
				t.Fatal("Parse succeeded")
			}
		})
	}
}

func FuzzParse(f *testing.F) {
	f.Add([]byte(valid))
	f.Add([]byte("x: &x [*x]"))
	f.Add([]byte("name: a\nname: b"))
	f.Fuzz(func(t *testing.T, data []byte) { _, _ = Parse(data) })
}
