package cmd

import (
	"bytes"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/adversarylabs/adversary/pkg/repository"
)

func TestRootCommandRemainsThinComposition(t *testing.T) {
	data, err := os.ReadFile("root.go")
	if err != nil {
		t.Fatal(err)
	}
	if lines := bytes.Count(data, []byte("\n")); lines > 140 {
		t.Fatalf("root.go has %d lines; composition root must remain at most 140", lines)
	}
	for _, forbidden := range []string{"func newRunCommand", "func newPackCommand", "func newLoginCommand", "func newPullCommand"} {
		if bytes.Contains(data, []byte(forbidden)) {
			t.Fatalf("root.go contains command implementation %q", forbidden)
		}
	}
}

func TestCommandConstructorsDoNotCaptureStreams(t *testing.T) {
	fset := token.NewFileSet()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") || path == "app.go" || path == "root.go" {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{"deps.Stdout", "deps.Stderr", "deps.Stdin", "os.Stdout", "os.Stderr", "os.Stdin"} {
			if bytes.Contains(data, []byte(forbidden)) {
				t.Errorf("%s accesses %s instead of the executing command stream", path, forbidden)
			}
		}
		file, err := parser.ParseFile(fset, path, data, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			fn, ok := node.(*ast.FuncDecl)
			if !ok || !strings.HasPrefix(fn.Name.Name, "new") || !strings.HasSuffix(fn.Name.Name, "Command") {
				return true
			}
			for _, field := range fn.Type.Params.List {
				for _, name := range field.Names {
					switch name.Name {
					case "stdin", "stdout", "stderr":
						t.Errorf("%s: constructor %s accepts captured stream %s", path, fn.Name.Name, name.Name)
					}
				}
			}
			return false
		})
	}
}

func TestCommandHandlersDoNotBypassApplicationPorts(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") || path == "app.go" || path == "root.go" || strings.HasPrefix(path, "signals_") {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, data, 0)
		if err != nil {
			t.Fatal(err)
		}
		imports := map[string]string{}
		for _, spec := range file.Imports {
			name := ""
			if spec.Name != nil {
				name = spec.Name.Name
			}
			value := strings.Trim(spec.Path.Value, `"`)
			if name == "." {
				t.Errorf("%s uses forbidden dot import %s", path, value)
				continue
			}
			if name == "" {
				name = filepath.Base(value)
			}
			imports[name] = value
		}
		ast.Inspect(file, func(node ast.Node) bool {
			sel, ok := node.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			ident, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			qualified := imports[ident.Name] + "." + sel.Sel.Name
			for _, forbidden := range []string{
				"os.Getenv", "os.LookupEnv", "os.Environ", "os.UserHomeDir", "os.TempDir", "os.Stat", "os.Open", "os.ReadFile", "os.WriteFile", "os.Mkdir", "os.MkdirAll", "os.Remove", "os.RemoveAll",
				"os/exec.Command", "os/exec.CommandContext",
				"github.com/adversarylabs/adversary/internal/initproject.Create", "github.com/adversarylabs/adversary/internal/initproject.RenderSuccess",
				"github.com/adversarylabs/adversary/pkg/manifest.Load", "github.com/adversarylabs/adversary/pkg/pack.Create", "github.com/adversarylabs/adversary/pkg/pack.Check", "github.com/adversarylabs/adversary/pkg/oci.ParseReference",
			} {
				if qualified == forbidden {
					t.Errorf("%s bypasses App port with %s", path, qualified)
				}
			}
			return true
		})
	}
}

func TestAmbientGuardAdversarialSourceForms(t *testing.T) {
	for name, source := range map[string]string{
		"aliased import": `package fixture; import ambient "os"; var f = ambient.Stat`,
		"function alias": `package fixture; import "os"; func x() { stat := os.Stat; _, _ = stat("x") }`,
		"dot import":     `package fixture; import . "os"; var _ = Stat`,
	} {
		t.Run(name, func(t *testing.T) {
			file, err := parser.ParseFile(token.NewFileSet(), "fixture.go", source, 0)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			imports := map[string]string{}
			for _, spec := range file.Imports {
				value := strings.Trim(spec.Path.Value, `"`)
				alias := filepath.Base(value)
				if spec.Name != nil {
					alias = spec.Name.Name
				}
				if alias == "." {
					found = true
				} else {
					imports[alias] = value
				}
			}
			ast.Inspect(file, func(node ast.Node) bool {
				sel, ok := node.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				id, ok := sel.X.(*ast.Ident)
				if ok && imports[id.Name] == "os" && sel.Sel.Name == "Stat" {
					found = true
				}
				return true
			})
			if !found {
				t.Fatal("adversarial ambient access escaped guard")
			}
		})
	}
}

func TestArtifactCommandsHaveNoByteLayerCompatibilityFallback(t *testing.T) {
	for _, path := range []string{"artifact_pack.go", "artifact_pull.go", "artifact_push.go", "app.go"} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{"does not support streaming", "oci.Blob", "PulledArtifact", ".Payload("} {
			if bytes.Contains(data, []byte(forbidden)) {
				t.Errorf("%s retains compatibility path %q", path, forbidden)
			}
		}
	}
}

func TestSubcommandStreamOverridesAreHonored(t *testing.T) {
	var appOut, appErr bytes.Buffer
	app := lifecycleTestApp(t, repository.Repository{Root: t.TempDir()}, &appOut, &appErr)

	root := NewRootCommandWithApp(app)
	version, _, err := root.Find([]string{"version"})
	if err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	version.SetOut(&out)
	version.SetErr(&errOut)
	root.SetArgs([]string{"version", "--json"})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"command":"version"`) || !strings.Contains(errOut.String(), "deprecated") {
		t.Fatalf("subcommand stdout=%q stderr=%q", out.String(), errOut.String())
	}
	if appOut.Len() != 0 || appErr.Len() != 0 {
		t.Fatalf("constructor streams received subcommand output: stdout=%q stderr=%q", appOut.String(), appErr.String())
	}

	root = NewRootCommandWithApp(app)
	completion, _, err := root.Find([]string{"completion"})
	if err != nil {
		t.Fatal(err)
	}
	out.Reset()
	completion.SetOut(&out)
	root.SetArgs([]string{"completion", "bash"})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "__start_adversary") {
		t.Fatalf("completion subcommand output=%q", out.String())
	}
}

func TestSubcommandInputOverrideIsHonored(t *testing.T) {
	var password string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
		}
		password = request.Password
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"token":"test-token"}`))
	}))
	defer server.Close()

	var out, errOut bytes.Buffer
	app := lifecycleTestApp(t, repository.Repository{Root: t.TempDir()}, &out, &errOut)
	root := NewRootCommandWithApp(app)
	login, _, err := root.Find([]string{"login"})
	if err != nil {
		t.Fatal(err)
	}
	login.SetIn(strings.NewReader("stream override secret\n"))
	root.SetArgs([]string{"--api-url", server.URL, "login", "--email-address", "user@example.test", "--password-stdin"})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	if password != "stream override secret" {
		t.Fatalf("password=%q", password)
	}
}
