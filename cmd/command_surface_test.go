package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/adversarylabs/adversary/internal/application"
	"github.com/adversarylabs/adversary/pkg/repository"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

func TestVersionHelpGolden(t *testing.T) {
	var out bytes.Buffer
	root := NewRootCommand(&out, &bytes.Buffer{})
	root.SetArgs([]string{"version", "--help"})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("testdata/version-help.golden")
	if err != nil {
		t.Fatal(err)
	}
	if out.String() != string(want) {
		t.Fatalf("version help changed\n--- want\n%s--- got\n%s", want, out.String())
	}
}

func TestRootHelpGolden(t *testing.T) {
	var out bytes.Buffer
	root := NewRootCommand(&out, &bytes.Buffer{})
	root.SetArgs([]string{"--help"})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("testdata/root-help.golden")
	if err != nil {
		t.Fatal(err)
	}
	if out.String() != string(want) {
		t.Fatalf("root help changed\n--- want\n%s--- got\n%s", want, out.String())
	}
}

func TestListIsCanonicalAndLSIsAlias(t *testing.T) {
	root := NewRootCommand(&bytes.Buffer{}, &bytes.Buffer{})
	list, _, err := root.Find([]string{"list"})
	if err != nil {
		t.Fatal(err)
	}
	ls, _, err := root.Find([]string{"ls"})
	if err != nil {
		t.Fatal(err)
	}
	if list != ls || list.Name() != "list" {
		t.Fatalf("list=%p ls=%p name=%q", list, ls, list.Name())
	}
}

func TestVersionedJSONIsPureAndConflictsAreUsageErrors(t *testing.T) {
	var out, errOut bytes.Buffer
	root := NewRootCommand(&out, &errOut)
	root.SetArgs([]string{"version", "--format", "json"})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		SchemaVersion int        `json:"schemaVersion"`
		Command       string     `json:"command"`
		Data          versionDTO `json:"data"`
	}
	if err := json.Unmarshal(out.Bytes(), &envelope); err != nil {
		t.Fatalf("stdout is not exactly JSON: %v: %q", err, out.String())
	}
	if envelope.SchemaVersion != 1 || envelope.Command != "version" || envelope.Data.ReviewProtocolVersion != 1 {
		t.Fatalf("envelope=%+v", envelope)
	}

	out.Reset()
	errOut.Reset()
	root = NewRootCommand(&out, &errOut)
	root.SetArgs([]string{"version", "--json", "--format", "json"})
	if err := root.Execute(); err == nil || !strings.Contains(err.Error(), "cannot be combined") {
		t.Fatalf("err=%v", err)
	}
	if out.Len() != 0 {
		t.Fatalf("work/output happened before validation: %q", out.String())
	}
}

func TestDeprecatedJSONWarnsOnlyOnStderr(t *testing.T) {
	var out, errOut bytes.Buffer
	root := NewRootCommand(&out, &errOut)
	root.SetArgs([]string{"version", "--json"})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	if !json.Valid(out.Bytes()) {
		t.Fatalf("stdout polluted: %q", out.String())
	}
	if !strings.Contains(errOut.String(), "deprecated") {
		t.Fatalf("warning missing: %q", errOut.String())
	}
}

func TestRootVersionContainsBuildAndProtocolMetadata(t *testing.T) {
	var out bytes.Buffer
	root := NewRootCommand(&out, &bytes.Buffer{})
	root.SetArgs([]string{"--version"})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"commit unknown", "built unknown", "go", "review protocol 1"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("version %q missing %q", out.String(), want)
		}
	}
}

func TestCompletion(t *testing.T) {
	var out bytes.Buffer
	root := NewRootCommand(&out, &bytes.Buffer{})
	root.SetArgs([]string{"completion", "bash"})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "__start_adversary") {
		t.Fatalf("unexpected completion output")
	}
}

func TestSanitizeCell(t *testing.T) {
	if got := sanitizeCell("safe\nrow\t\x1b[31m"); strings.ContainsAny(got, "\n\t\x1b") {
		t.Fatalf("unsafe cell %q", got)
	}
}

func TestPublishedCLIOutputFixturesMatchSchema(t *testing.T) {
	root := filepath.Join("..", "docs")
	schemaBytes, err := os.ReadFile(filepath.Join(root, "schemas", "cli-output-v1.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schemaDocument any
	if err := json.Unmarshal(schemaBytes, &schemaDocument); err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	const schemaURL = "https://adversarylabs.dev/schemas/cli-output-v1.schema.json"
	if err := compiler.AddResource(schemaURL, schemaDocument); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile(schemaURL)
	if err != nil {
		t.Fatal(err)
	}
	fixtures, err := filepath.Glob(filepath.Join(root, "fixtures", "cli-*-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(fixtures) != 8 {
		t.Fatalf("got %d CLI fixtures, want 8", len(fixtures))
	}
	for _, path := range fixtures {
		t.Run(filepath.Base(path), func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var value any
			if err := json.Unmarshal(data, &value); err != nil {
				t.Fatal(err)
			}
			if err := schema.Validate(value); err != nil {
				t.Fatal(err)
			}
		})
	}
}

type countingRuntime struct {
	inner application.Runtime
	calls int
}

func (r *countingRuntime) BindingIdentity() string {
	return r.inner.(application.BindingIdentity).BindingIdentity()
}
func (r *countingRuntime) Run(ctx context.Context, o application.AdversaryRunOptions) error {
	r.calls++
	return r.inner.Run(ctx, o)
}
func (r *countingRuntime) Inspect(ctx context.Context, o application.AdversaryRunOptions) error {
	r.calls++
	return r.inner.Inspect(ctx, o)
}

func TestInvalidRunFlagsDoNoRuntimeWorkOrOutput(t *testing.T) {
	for name, args := range map[string][]string{
		"unpaired refs": {"run", "example", "--base", "main"},
		"builder":       {"run", "example", "--builder", "remote"},
		"shell json":    {"run", "example", "--shell", "--format", "json"},
		"debug verbose": {"run", "example", "--debug", "--verbose"},
	} {
		t.Run(name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			base := lifecycleTestApp(t, repository.Repository{Root: t.TempDir()}, &out, &errOut)
			deps := base.Dependencies()
			spy := &countingRuntime{inner: deps.Runtime}
			deps.Runtime = spy
			app, err := application.New(deps)
			if err != nil {
				t.Fatal(err)
			}
			cmd := NewRootCommandWithApp(app)
			cmd.SetArgs(args)
			if err := cmd.Execute(); err == nil {
				t.Fatal("invalid flags succeeded")
			}
			if spy.calls != 0 || out.Len() != 0 || errOut.Len() != 0 {
				t.Fatalf("calls=%d stdout=%q stderr=%q", spy.calls, out.String(), errOut.String())
			}
		})
	}
}

func TestInvalidPackBuilderHasNoProgressOrResolverWork(t *testing.T) {
	var out, errOut bytes.Buffer
	app := lifecycleTestApp(t, repository.Repository{Root: t.TempDir()}, &out, &errOut)
	cmd := NewRootCommandWithApp(app)
	cmd.SetArgs([]string{"pack", t.TempDir(), "--builder", "remote"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("invalid builder succeeded")
	}
	if out.Len() != 0 || errOut.Len() != 0 {
		t.Fatalf("stdout=%q stderr=%q", out.String(), errOut.String())
	}
}
