package pack

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/adversarylabs/adversary/pkg/manifest"
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

func TestSDKImportScannerScopeAndComputedLoads(t *testing.T) {
	tests := []struct {
		name   string
		source string
		want   bool
	}{
		{"outer alias restored after inner shadow", `const load = require; { const load = replacement; load("unrelated") } load("@adversarylabs/sdk")`, true},
		{"conditional alias reassignment leaves loader path", `let load = require; if (flag) load = replacement; load("@adversarylabs/sdk")`, true},
		{"require parameter is not builtin loader", `function run(require) { return require("@adversarylabs/sdk") }`, false},
		{"imported require is not builtin loader", `import require from "./shim.js"; require("@adversarylabs/sdk")`, false},
		{"reassigned createRequire is not trusted", `import { createRequire as cr } from "node:module"; cr = replacement; const load = cr(import.meta.url); load("@adversarylabs/sdk")`, false},
		{"shadowed createRequire parameter is not trusted", `import { createRequire as cr } from "node:module"; function run(cr) { const load = cr(import.meta.url); load("@adversarylabs/sdk") }`, false},
		{"arrow require parameter is not builtin loader", `const run = (require) => { return require("@adversarylabs/sdk") }`, false},
		{"method require parameter is not builtin loader", `const object = { run(require) { return require("@adversarylabs/sdk") } }`, false},
		{"uninitialized local require shadows builtin", `function run() { let require; return require("@adversarylabs/sdk") }`, false},
		{"later declarator loader stays function local", `function run() { const value = 1, load = require; load("@adversarylabs/sdk") } const load = replacement; load("unrelated")`, true},
		{"later declarator loader does not leak from function", `function run() { const value = 1, load = require } load("@adversarylabs/sdk")`, false},
		{"uninvoked function assignment does not destroy outer loader", `let load = require; function reset() { load = replacement } load("@adversarylabs/sdk")`, true},
		{"concatenated sdk dynamic import fails closed", `import("@adversarylabs/" + "sdk")`, true},
		{"concatenated sdk require fails closed", `require("@adversarylabs/" + "sdk")`, true},
		{"computed local dynamic import fails closed", `import("./" + target)`, true},
		{"computed local require fails closed", `require("./" + target)`, true},
		{"escaped template sdk specifier", "import(`\\x40adversarylabs/sdk`)", true},
		{"commonjs destructured createRequire", `const { createRequire } = require("node:module"); const load = createRequire(import.meta.url); load("@adversarylabs/sdk")`, true},
		{"direct iife establishes loader alias", `let load = replacement; (() => { load = require })(); load("@adversarylabs/sdk")`, true},
		{"called helper establishes loader alias", `let load = replacement; function set() { load = require } set(); load("@adversarylabs/sdk")`, true},
		{"conditional helper replacement preserves loader path", `let load = require; function reset() { load = replacement } flag && reset(); load("@adversarylabs/sdk")`, true},
		{"conditional iife replacement preserves loader path", `let load = require; flag && (() => { load = replacement })(); load("@adversarylabs/sdk")`, true},
		{"unconditional iife replacement clears loader", `let load = require; (() => { load = replacement })(); load("@adversarylabs/sdk")`, false},
		{"ternary replacement preserves possible loader", `let load = require; flag ? load = replacement : observe(); load("@adversarylabs/sdk")`, true},
		{"short circuit replacement preserves possible loader", `let load = require; flag && (load = replacement); load("@adversarylabs/sdk")`, true},
		{"destructured require parameter shadows builtin", `function run({ require }) { require("@adversarylabs/sdk") }`, false},
		{"destructured local require shadows builtin", `const { require } = replacement; require("@adversarylabs/sdk")`, false},
		{"called arrow establishes loader", `let load = replacement; const set = () => { load = require }; set(); load("@adversarylabs/sdk")`, true},
		{"called function expression establishes loader", `let load = replacement; const set = function () { load = require }; set(); load("@adversarylabs/sdk")`, true},
		{"conditional named helper establishes possible loader", `let load = replacement; function set() { if (flag) load = require } set(); load("@adversarylabs/sdk")`, true},
		{"conditional iife establishes possible loader", `let load = replacement; (() => { if (flag) load = require })(); load("@adversarylabs/sdk")`, true},
		{"named helper establishes module require", `let load = replacement; function set() { load = module.require } set(); load("@adversarylabs/sdk")`, true},
		{"named helper establishes createRequire loader", `import { createRequire as cr } from "node:module"; let load = replacement; function set() { load = cr(import.meta.url) } set(); load("@adversarylabs/sdk")`, true},
		{"shadowed helper call does not invoke outer helper", `let load = replacement; function set() { load = require } { const set = replacement; set() } load("@adversarylabs/sdk")`, false},
		{"inaccessible nested helper does not bind top level call", `let load = replacement; function outer() { function set() { load = require } } set(); load("@adversarylabs/sdk")`, false},
		{"later duplicate function declaration wins nonloader", `let load = replacement; function set() { load = require } function set() { load = replacement } set(); load("@adversarylabs/sdk")`, false},
		{"later duplicate function declaration wins loader", `let load = replacement; function set() { load = replacement } function set() { load = require } set(); load("@adversarylabs/sdk")`, true},
		{"hoisted helper establishes loader before declaration", `let load = replacement; set(); function set() { load = require } load("@adversarylabs/sdk")`, true},
		{"hoisted last duplicate wins before declarations", `let load = replacement; set(); function set() { load = require } function set() { load = replacement } load("@adversarylabs/sdk")`, false},
		{"called helper alias establishes loader", `let load = replacement; function set() { load = require } const invoke = set; invoke(); load("@adversarylabs/sdk")`, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokens, ambiguous := lexJSTokens([]byte(tt.source))
			got := ambiguous || tokensLoadSDK(tokens)
			if got != tt.want {
				t.Fatalf("needs closure=%v want=%v ambiguous=%v tokens=%#v", got, tt.want, ambiguous, tokens)
			}
		})
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

func TestPackFollowsCommonJSDirectoryPackageMain(t *testing.T) {
	dir := testProject(t)
	writeFile(t, dir, "adversary.yaml", `name: local/security-reviewer
version: 0.1.0
runtime:
  name: node
  version: "22"
  command:
    - dist/index.cjs
permissions:
  network: false
`)
	writeFile(t, dir, "dist/index.cjs", `require("./runtime")`+"\n")
	writeFile(t, dir, "dist/runtime/package.json", `{"main":"loader.cjs"}`)
	writeFile(t, dir, "dist/runtime/loader.cjs", `const sdk = require("@adversarylabs/sdk"); console.log(sdk.value)`+"\n")
	writeFile(t, dir, "node_modules/@adversarylabs/sdk/package.json", `{"name":"@adversarylabs/sdk","version":"1.0.0","main":"index.js"}`)
	writeFile(t, dir, "node_modules/@adversarylabs/sdk/index.js", `module.exports = { value: "sdk-ok" }`+"\n")

	artifact, err := Create(context.Background(), Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer artifact.Close()
	assertArtifactHasPath(t, artifact, "node_modules/@adversarylabs/sdk/package.json")
	extracted := extractArtifactLayer(t, artifact)
	node, err := exec.LookPath("node")
	if err != nil {
		t.Fatal("node is required for the CommonJS directory-main offline contract")
	}
	cmd := exec.Command(node, "dist/index.cjs")
	cmd.Dir = extracted
	cmd.Env = append(os.Environ(), "npm_config_offline=true", "NODE_PATH=")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("packed CommonJS directory-main entrypoint failed offline: %v\n%s", err, output)
	}
	if strings.TrimSpace(string(output)) != "sdk-ok" {
		t.Fatalf("packed CommonJS directory-main output = %q", output)
	}
}

func TestPackFollowsCommonJSDirectoryValuedPackageMain(t *testing.T) {
	dir := testProject(t)
	writeFile(t, dir, "adversary.yaml", `name: local/security-reviewer
version: 0.1.0
runtime:
  name: node
  version: "22"
  command:
    - dist/index.cjs
permissions:
  network: false
`)
	writeFile(t, dir, "dist/index.cjs", `require("./runtime")`+"\n")
	writeFile(t, dir, "dist/runtime/package.json", `{"main":"lib"}`)
	writeFile(t, dir, "dist/runtime/lib/index.cjs", `require("@adversarylabs/sdk")`+"\n")
	writeFile(t, dir, "node_modules/@adversarylabs/sdk/package.json", `{"name":"@adversarylabs/sdk","version":"1.0.0","main":"index.js"}`)
	writeFile(t, dir, "node_modules/@adversarylabs/sdk/index.js", `module.exports = {}`+"\n")

	manifestData, err := os.ReadFile(filepath.Join(dir, "adversary.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	m, err := manifest.Parse(manifestData)
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	got, err := declaredEntrypointsNeedSDKClosure(root, m)
	if err != nil {
		t.Fatal(err)
	}
	if !got {
		t.Fatal("directory-valued package main imports SDK but closure was excluded")
	}
}

func TestPackFollowsQueryQualifiedLocalModule(t *testing.T) {
	dir := testProject(t)
	writeFile(t, dir, "dist/index.js", `import "./runtime.js?variant=review"`+"\n")
	writeFile(t, dir, "dist/runtime.js", `import "@adversarylabs/sdk"`+"\n")
	writeFile(t, dir, "node_modules/@adversarylabs/sdk/package.json", `{"name":"@adversarylabs/sdk","version":"1.0.0","main":"index.js"}`)
	writeFile(t, dir, "node_modules/@adversarylabs/sdk/index.js", "export const ok = true\n")

	manifestData, err := os.ReadFile(filepath.Join(dir, "adversary.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	m, err := manifest.Parse(manifestData)
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	got, err := declaredEntrypointsNeedSDKClosure(root, m)
	if err != nil {
		t.Fatal(err)
	}
	if !got {
		t.Fatal("query-qualified reachable local module imports SDK but closure was excluded")
	}
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
