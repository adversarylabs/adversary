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
