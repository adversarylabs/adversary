package adversary

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Runtime policy must stay deterministic under injection. Only the named
// concrete adapters may import ambient process/filesystem packages.
func TestRuntimePolicyHasNoAmbientProcessDependencies(t *testing.T) {
	business := map[string]bool{
		"runner.go":              true,
		"manifest.go":            true,
		"resolver.go":            true,
		"docker.go":              true,
		"git.go":                 true,
		"process_environment.go": true,
	}
	adapters := map[string]bool{
		"process_adapter.go":  true,
		"process_unix.go":     true,
		"process_windows.go":  true,
		"runtime_files.go":    true,
		"executable_path.go":  true,
		"resolver_default.go": true,
		"manifest_default.go": true,
	}
	ambientImports := map[string]bool{"os": true, "os/exec": true}
	ambientCalls := map[string]map[string]bool{
		"time": {
			"Now": true, "Since": true, "Until": true, "NewTimer": true,
			"NewTicker": true, "After": true, "Tick": true, "AfterFunc": true, "Sleep": true,
		},
	}
	productionFiles, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range productionFiles {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		tree, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		aliases := map[string]string{}
		for _, spec := range tree.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatal(err)
			}
			if spec.Name != nil && spec.Name.Name == "." && (ambientImports[importPath] || importPath == "time") {
				t.Errorf("%s dot-imports ambient package %q", file, importPath)
			}
			if ambientImports[importPath] && !adapters[file] {
				t.Errorf("%s imports ambient package %q but is not a declared concrete adapter", file, importPath)
			}
			name := path.Base(importPath)
			if spec.Name != nil && spec.Name.Name != "_" && spec.Name.Name != "." {
				name = spec.Name.Name
			}
			aliases[name] = importPath
		}
		if !adapters[file] {
			ast.Inspect(tree, func(node ast.Node) bool {
				selector, ok := node.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				identifier, ok := selector.X.(*ast.Ident)
				if ok && ambientCalls[aliases[identifier.Name]][selector.Sel.Name] {
					t.Errorf("%s calls ambient %s.%s", file, aliases[identifier.Name], selector.Sel.Name)
				}
				return true
			})
		}
	}

	for file := range business {
		tree, err := parser.ParseFile(token.NewFileSet(), file, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, spec := range tree.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatal(err)
			}
			if ambientImports[importPath] {
				t.Errorf("%s imports ambient package %q; move the operation to a named adapter", file, importPath)
			}
		}
	}

	for file := range adapters {
		if _, err := parser.ParseFile(token.NewFileSet(), file, nil, parser.ImportsOnly); err != nil {
			t.Fatalf("declared runtime adapter %s is missing or malformed: %v", file, err)
		}
	}

}
