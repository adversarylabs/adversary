package pack

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSDKImportScannerAdversarialSyntax(t *testing.T) {
	tests := []struct {
		name   string
		source string
		want   bool
	}{
		{"esm named", `import { Adversary as A } from "@adversarylabs/sdk"`, true},
		{"esm side effect whitespace", "import /*a*/\n '@adversarylabs/sdk'", true},
		{"esm dynamic", `await import ( "@adversarylabs/sdk" )`, true},
		{"esm reexport", `export { Adversary as A } from "@adversarylabs/sdk"`, true},
		{"cjs direct", `const A = require ( "@adversarylabs/sdk" )`, true},
		{"cjs legacy alias", `const A = require("@adversary/sdk")`, true},
		{"cjs module require", `const A = module.require("@adversarylabs/sdk")`, true},
		{"cjs optional require", `const A = require?.("@adversarylabs/sdk")`, true},
		{"cjs loader alias", `const load = require; const A = load("@adversarylabs/sdk")`, true},
		{"createRequire loader", `import { createRequire } from "node:module"; const load = createRequire(import.meta.url); load("@adversarylabs/sdk")`, true},
		{"escaped at sign", `import "\x40adversarylabs/sdk"`, true},
		{"escaped loader identifier", `const A = requ\u0069re("@adversarylabs/sdk")`, true},
		{"postfix division containing load", `let x=1; const y = x++ / require("@adversarylabs/sdk").value / 2`, true},
		{"comment", `// import "@adversarylabs/sdk"`, false},
		{"block comment", `/* require("@adversarylabs/sdk") */`, false},
		{"ordinary string", `const s = "import '@adversarylabs/sdk'"`, false},
		{"template text", "const s = `require(\"@adversarylabs/sdk\")`", false},
		{"template execution", "const s = `${require(\"@adversarylabs/sdk\")}`", true},
		{"regex", `const r = /require\("@adversarylabs\/sdk"\)/`, false},
		{"hashbang comment", "#!/usr/bin/env node\nconsole.log('require(\\\"@adversarylabs/sdk\\\")')", false},
		{"object require method", `object.require("@adversarylabs/sdk")`, false},
		{"object import method", `object.import("@adversarylabs/sdk")`, false},
		{"unterminated comment", `/* import "@adversarylabs/sdk"`, true},
		{"unterminated string", `const s = "@adversarylabs/sdk`, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokens, ambiguous := lexJSTokens([]byte(tt.source))
			if got := ambiguous || tokensLoadSDK(tokens); got != tt.want {
				t.Fatalf("needs closure = %v, want %v; ambiguous=%v tokens=%#v", got, tt.want, ambiguous, tokens)
			}
		})
	}
}

func TestSDKImportScannerLongStaticImport(t *testing.T) {
	names := make([]string, 80)
	for i := range names {
		names[i] = fmt.Sprintf("name%d", i)
	}
	source := "import { " + strings.Join(names, ", ") + ` } from "@adversarylabs/sdk"`
	tokens, ambiguous := lexJSTokens([]byte(source))
	if !ambiguous && !tokensLoadSDK(tokens) {
		t.Fatal("long valid static SDK import was excluded")
	}
}

func TestPackRetainsSDKForReachableLocalModule(t *testing.T) {
	dir := testProject(t)
	writeFile(t, dir, "dist/index.js", `import "./runtime.js"`+"\n")
	writeFile(t, dir, "dist/runtime.js", `import "@adversarylabs/sdk"`+"\n")
	writeFile(t, dir, "node_modules/@adversarylabs/sdk/package.json", `{"name":"@adversarylabs/sdk","version":"1.0.0","main":"index.js"}`)
	writeFile(t, dir, "node_modules/@adversarylabs/sdk/index.js", "export const ok = true\n")
	artifact, err := Create(context.Background(), Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer artifact.Close()
	for _, file := range artifact.Files {
		if file.Path == "node_modules/@adversarylabs/sdk/package.json" {
			return
		}
	}
	t.Fatal("reachable local module imports SDK but closure was excluded")
}

func TestPackSelfContainedBundleInventoryIsDeterministic(t *testing.T) {
	dir := testProject(t)
	writeFile(t, dir, "dist/index.js", "#!/usr/bin/env node\nconst text = 'node_modules/@adversarylabs/sdk'; console.log('ok', text.length)\n")
	writeFile(t, dir, "node_modules/@adversarylabs/sdk/package.json", `{"name":"@adversarylabs/sdk","version":"1.0.0","main":"index.js"}`)
	writeFile(t, dir, "node_modules/@adversarylabs/sdk/index.js", "should not ship\n")
	first, err := Create(context.Background(), Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := Create(context.Background(), Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if first.LayerDigest != second.LayerDigest {
		t.Fatalf("digest mismatch: %s != %s", first.LayerDigest, second.LayerDigest)
	}
	for _, file := range first.Files {
		if strings.HasPrefix(file.Path, "node_modules/") {
			t.Fatalf("unexpected dependency %s", file.Path)
		}
	}
	extracted := extractArtifactLayer(t, first)
	node := "/nix/store/s0qzknz77k3lzikgywx2piilfp8w0581-nodejs-22.23.2/bin/node"
	if _, err := os.Stat(node); err != nil {
		node = "/Users/marc/.nvm/versions/node/v22.22.0/bin/node"
	}
	output, err := os.ReadFile(filepath.Join(extracted, "dist/index.js"))
	if err != nil || !strings.Contains(string(output), "console.log") {
		t.Fatalf("standalone entrypoint missing: %v (node %s)", err, node)
	}
}
