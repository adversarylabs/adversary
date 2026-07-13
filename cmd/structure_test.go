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
		if forbidden := forbiddenHandlerDependency(file); forbidden != "" {
			t.Errorf("%s bypasses App port with %s", path, forbidden)
		}
	}
}

func TestAmbientGuardAdversarialSourceForms(t *testing.T) {
	for name, source := range map[string]string{
		"aliased filesystem":  `package fixture; import ambient "os"; var f = ambient.Stat`,
		"function alias":      `package fixture; import "net"; func x() { listen := net.Listen; _, _ = listen("tcp", "127.0.0.1:0") }`,
		"entropy alias":       `package fixture; import entropy "crypto/rand"; var _ = entropy.Reader`,
		"HTTP server":         `package fixture; import web "net/http"; var _ = web.Server{}`,
		"background shutdown": `package fixture; import lifecycle "context"; var _ = lifecycle.Background`,
		"dot import":          `package fixture; import . "net/http"; var _ = NewServeMux`,
	} {
		t.Run(name, func(t *testing.T) {
			file, err := parser.ParseFile(token.NewFileSet(), "fixture.go", source, 0)
			if err != nil {
				t.Fatal(err)
			}
			if forbiddenHandlerDependency(file) == "" {
				t.Fatal("adversarial ambient access escaped guard")
			}
		})
	}
}

var forbiddenHandlerSelectors = map[string]struct{}{
	"os.Getenv": {}, "os.LookupEnv": {}, "os.Environ": {}, "os.UserHomeDir": {}, "os.TempDir": {}, "os.Stat": {}, "os.Open": {}, "os.ReadFile": {}, "os.WriteFile": {}, "os.Mkdir": {}, "os.MkdirAll": {}, "os.Remove": {}, "os.RemoveAll": {},
	"os/exec.Command": {}, "os/exec.CommandContext": {},
	"crypto/rand.Reader": {}, "crypto/rand.Read": {}, "net.Listen": {}, "net.ListenConfig": {},
	"net/http.Server": {}, "net/http.NewServeMux": {}, "net/http.Serve": {}, "net/http.ServeTLS": {}, "net/http.ListenAndServe": {}, "net/http.ListenAndServeTLS": {}, "context.Background": {},
	"github.com/adversarylabs/adversary/internal/initproject.Create": {}, "github.com/adversarylabs/adversary/internal/initproject.RenderSuccess": {},
	"github.com/adversarylabs/adversary/pkg/manifest.Load": {}, "github.com/adversarylabs/adversary/pkg/pack.Create": {}, "github.com/adversarylabs/adversary/pkg/pack.Check": {}, "github.com/adversarylabs/adversary/pkg/oci.ParseReference": {},
}

var forbiddenHandlerImports = map[string]struct{}{"crypto/rand": {}, "net": {}}

func forbiddenHandlerDependency(file *ast.File) string {
	imports := map[string]string{}
	for _, spec := range file.Imports {
		value := strings.Trim(spec.Path.Value, `"`)
		if _, forbidden := forbiddenHandlerImports[value]; forbidden {
			return "import " + value
		}
		name := filepath.Base(value)
		if spec.Name != nil {
			name = spec.Name.Name
		}
		if name == "." {
			return "dot import " + value
		}
		imports[name] = value
	}
	found := ""
	ast.Inspect(file, func(node ast.Node) bool {
		selector, ok := node.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		identifier, ok := selector.X.(*ast.Ident)
		if !ok {
			return true
		}
		qualified := imports[identifier.Name] + "." + selector.Sel.Name
		if _, forbidden := forbiddenHandlerSelectors[qualified]; forbidden && found == "" {
			found = qualified
		}
		return true
	})
	return found
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
