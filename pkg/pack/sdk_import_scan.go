package pack

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"

	"github.com/adversarylabs/adversary/pkg/manifest"
)

const maxJSEntrypointScanBytes = 16 << 20
const maxJSEntrypointTokens = 1 << 20
const maxJSModuleGraphFiles = 4096

type jsTokenKind uint8

const (
	jsIdentifier jsTokenKind = iota
	jsNumber
	jsRegex
	jsString
	jsTemplate
	jsPunctuation
)

type jsToken struct {
	kind      jsTokenKind
	text      string
	escaped   bool
	ambiguous bool
}

// declaredEntrypointsNeedSDKClosure reports whether the package still has a
// runtime dependency on the published JavaScript SDK. The packer deliberately
// makes the conservative choice (include the closure) for oversized or
// lexically ambiguous entrypoints, but it does not mistake generated source
// comments, ordinary strings, or template text for module loads.
func declaredEntrypointsNeedSDKClosure(root *os.Root, m manifest.Manifest) (bool, error) {
	if runtimeName(m) != "node" || m.Runtime.Image != "" {
		return false, nil
	}

	entrypoints := make([]string, 0, 2)
	entrypoint, required, err := checkedPackageEntrypoint(m)
	if err != nil {
		return false, err
	}
	if required && isJSEntrypoint(entrypoint) {
		entrypoints = append(entrypoints, entrypoint)
	}
	if detection := filepath.ToSlash(filepath.Clean(m.Detection.Entrypoint)); m.Detection.Entrypoint != "" && isJSEntrypoint(detection) && detection != entrypoint {
		entrypoints = append(entrypoints, detection)
	}

	queue := append([]string(nil), entrypoints...)
	visited := make(map[string]struct{}, len(queue))
	for len(queue) > 0 {
		module := queue[0]
		queue = queue[1:]
		module = path.Clean(filepath.ToSlash(module))
		if _, ok := visited[module]; ok {
			continue
		}
		visited[module] = struct{}{}
		if len(visited) > maxJSModuleGraphFiles {
			return true, nil
		}

		needs, localModules, err := jsModuleNeedsSDKClosure(root, module)
		if err != nil {
			return false, fmt.Errorf("inspect JavaScript module %q for SDK imports: %w", module, err)
		}
		if needs {
			return true, nil
		}
		for _, specifier := range localModules {
			resolved, err := resolveLocalJSModules(root, module, specifier)
			if err != nil {
				return false, err
			}
			queue = append(queue, resolved...)
		}
	}
	return false, nil
}

func isJSEntrypoint(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".js", ".mjs", ".cjs":
		return true
	default:
		return false
	}
}

func jsModuleNeedsSDKClosure(root *os.Root, module string) (bool, []string, error) {
	f, err := root.Open(filepath.FromSlash(module))
	if err != nil {
		// Entrypoint validation reports missing build output with its established
		// error. There is no source to classify in that case.
		if os.IsNotExist(err) {
			return false, nil, nil
		}
		return false, nil, err
	}
	defer f.Close()

	source, err := io.ReadAll(io.LimitReader(f, maxJSEntrypointScanBytes+1))
	if err != nil {
		return false, nil, err
	}
	if len(source) > maxJSEntrypointScanBytes {
		return true, nil, nil
	}
	tokens, ambiguous := lexJSTokens(source)
	if ambiguous {
		return true, nil, nil
	}
	loads := tokensModuleLoads(tokens)
	return loads.sdk, loads.local, nil
}

func resolveLocalJSModules(root *os.Root, importer, specifier string) ([]string, error) {
	if !strings.HasPrefix(specifier, "./") && !strings.HasPrefix(specifier, "../") {
		return nil, nil
	}
	if suffix := strings.IndexAny(specifier, "?#"); suffix >= 0 {
		specifier = specifier[:suffix]
	}
	clean := path.Clean(path.Join(path.Dir(importer), specifier))
	if clean == ".." || strings.HasPrefix(clean, "../") || path.IsAbs(clean) {
		return nil, fmt.Errorf("local JavaScript import %q from %q escapes package root", specifier, importer)
	}
	candidates := []string{clean}
	if !isJSEntrypoint(clean) {
		candidates = append(candidates, clean+".js", clean+".mjs", clean+".cjs")
		packageJSON := path.Join(clean, "package.json")
		if data, err := root.ReadFile(filepath.FromSlash(packageJSON)); err == nil {
			var packageMetadata struct {
				Main string `json:"main"`
			}
			if err := json.Unmarshal(data, &packageMetadata); err != nil {
				return nil, fmt.Errorf("parse local JavaScript package %q: %w", packageJSON, err)
			}
			if packageMetadata.Main != "" {
				main := path.Clean(path.Join(clean, packageMetadata.Main))
				if main == ".." || strings.HasPrefix(main, "../") || path.IsAbs(main) {
					return nil, fmt.Errorf("local JavaScript package main %q escapes package root", packageMetadata.Main)
				}
				candidates = append(candidates, main)
				if !isJSEntrypoint(main) {
					candidates = append(candidates,
						main+".js", main+".mjs", main+".cjs",
						path.Join(main, "index.js"), path.Join(main, "index.mjs"), path.Join(main, "index.cjs"),
					)
				}
			}
		} else if !os.IsNotExist(err) {
			return nil, fmt.Errorf("read local JavaScript package %q: %w", packageJSON, err)
		}
		candidates = append(candidates,
			path.Join(clean, "index.js"), path.Join(clean, "index.mjs"), path.Join(clean, "index.cjs"),
		)
	}
	resolved := make([]string, 0, 1)
	for _, candidate := range candidates {
		info, err := root.Stat(filepath.FromSlash(candidate))
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("resolve local JavaScript import %q from %q: %w", specifier, importer, err)
		}
		if !info.IsDir() && isJSEntrypoint(candidate) {
			resolved = append(resolved, candidate)
		}
	}
	return resolved, nil
}

type jsModuleLoads struct {
	sdk   bool
	local []string
}

type jsBinding uint8

const (
	jsNonLoader jsBinding = 1 << iota
	jsLoader
	jsLoaderFactory
	jsModuleObject
)

type jsBindingScope struct {
	bindings    map[string]jsBinding
	conditional bool
	inherited   map[string]struct{}
	propagate   bool
}

type jsBindingTracker struct {
	scopes []jsBindingScope
}

type jsBindingEffect struct {
	name        string
	binding     jsBinding
	conditional bool
}

type jsInvokedEffects struct {
	effects     []jsBindingEffect
	conditional bool
}

type jsFunctionValue struct {
	effects []jsBindingEffect
}

type jsFunctionTracker struct {
	scopes []map[string]*jsFunctionValue
}

func newJSFunctionTracker(initial map[string]*jsFunctionValue) *jsFunctionTracker {
	return &jsFunctionTracker{scopes: []map[string]*jsFunctionValue{copyJSFunctionValues(initial)}}
}

func (tracker *jsFunctionTracker) push(initial map[string]*jsFunctionValue) {
	tracker.scopes = append(tracker.scopes, copyJSFunctionValues(initial))
}

func (tracker *jsFunctionTracker) pop() {
	if len(tracker.scopes) > 1 {
		tracker.scopes = tracker.scopes[:len(tracker.scopes)-1]
	}
}

func (tracker *jsFunctionTracker) lookup(name string) (*jsFunctionValue, bool) {
	for i := len(tracker.scopes) - 1; i >= 0; i-- {
		if value, ok := tracker.scopes[i][name]; ok {
			return value, true
		}
	}
	return nil, false
}

func (tracker *jsFunctionTracker) declare(name string, value *jsFunctionValue) {
	tracker.scopes[len(tracker.scopes)-1][name] = value
}

func (tracker *jsFunctionTracker) assign(name string, value *jsFunctionValue, conditional bool) {
	target := 0
	for i := len(tracker.scopes) - 1; i >= 0; i-- {
		if _, ok := tracker.scopes[i][name]; ok {
			target = i
			break
		}
	}
	if conditional {
		if existing := tracker.scopes[target][name]; existing != nil {
			if value == nil {
				return
			}
			value = &jsFunctionValue{effects: append(append([]jsBindingEffect(nil), existing.effects...), value.effects...)}
		}
	}
	tracker.scopes[target][name] = value
}

func copyJSFunctionValues(values map[string]*jsFunctionValue) map[string]*jsFunctionValue {
	result := make(map[string]*jsFunctionValue, len(values))
	for name, value := range values {
		result[name] = value
	}
	return result
}

type jsFunctionDeclaration struct {
	name  string
	value *jsFunctionValue
}

func newJSBindingTracker(tokens []jsToken) *jsBindingTracker {
	root := map[string]jsBinding{
		"require": jsLoader,
		"module":  jsModuleObject,
	}
	for name, binding := range importedJSBindings(tokens) {
		root[name] = binding
	}
	return &jsBindingTracker{scopes: []jsBindingScope{{bindings: root}}}
}

func (tracker *jsBindingTracker) push(conditional bool, initial map[string]jsBinding, propagate bool) {
	bindings := make(map[string]jsBinding, len(initial))
	inherited := make(map[string]struct{}, len(initial))
	for name, binding := range initial {
		bindings[name] = binding
		inherited[name] = struct{}{}
	}
	tracker.scopes = append(tracker.scopes, jsBindingScope{bindings: bindings, conditional: conditional, inherited: inherited, propagate: propagate})
}

func (tracker *jsBindingTracker) pop() {
	if len(tracker.scopes) <= 1 {
		return
	}
	scope := tracker.scopes[len(tracker.scopes)-1]
	tracker.scopes = tracker.scopes[:len(tracker.scopes)-1]
	if scope.propagate {
		for name := range scope.inherited {
			tracker.assign(name, scope.bindings[name], scope.conditional)
		}
	}
}

func (tracker *jsBindingTracker) lookup(name string) jsBinding {
	for i := len(tracker.scopes) - 1; i >= 0; i-- {
		if binding, ok := tracker.scopes[i].bindings[name]; ok {
			return binding
		}
	}
	return jsNonLoader
}

func (tracker *jsBindingTracker) snapshot() map[string]jsBinding {
	bindings := make(map[string]jsBinding)
	for _, scope := range tracker.scopes {
		for name, binding := range scope.bindings {
			bindings[name] = binding
		}
	}
	return bindings
}

func (tracker *jsBindingTracker) declare(name string, binding jsBinding) {
	tracker.scopes[len(tracker.scopes)-1].bindings[name] = binding
}

func (tracker *jsBindingTracker) assign(name string, binding jsBinding, conditional bool) {
	target := 0
	for i := len(tracker.scopes) - 1; i >= 0; i-- {
		if _, ok := tracker.scopes[i].bindings[name]; ok {
			target = i
			break
		}
	}
	for i := target + 1; i < len(tracker.scopes); i++ {
		conditional = conditional || tracker.scopes[i].conditional
	}
	if conditional {
		tracker.scopes[target].bindings[name] |= binding
		return
	}
	tracker.scopes[target].bindings[name] = binding
}

func tokensLoadSDK(tokens []jsToken) bool {
	return tokensModuleLoads(tokens).sdk
}

func tokensModuleLoads(tokens []jsToken) jsModuleLoads {
	loads := jsModuleLoads{}
	bindings := newJSBindingTracker(tokens)
	declarations := simpleJSDeclarationIndexes(tokens)
	destructuredDeclarations := destructuredJSDeclarations(tokens)
	functionParameters := jsFunctionBodyParameters(tokens)
	functionDeclarations, functionAssignments, directIIFEEffects := jsFunctionMetadata(tokens, functionParameters)
	functionDeclarationsByScope := jsFunctionDeclarationsByScope(tokens, functionDeclarations)
	functions := newJSFunctionTracker(functionDeclarationsByScope[-1])
	addSpecifier := func(token jsToken) {
		specifier, exact := staticModuleSpecifier(token)
		if !exact {
			if token.ambiguous {
				loads.sdk = true
			}
			return
		}
		if isSDKModule(specifier) {
			loads.sdk = true
		}
		if token.escaped && (strings.Contains(specifier, "@adversarylabs") || strings.Contains(specifier, "@adversary/sdk")) {
			// Escaped namespace text that does not decode to an exact known SDK
			// name is still too close to distinguish safely from a deliberately
			// obfuscated SDK load. Prefer the offline-safe closure.
			loads.sdk = true
		}
		if strings.HasPrefix(specifier, "./") || strings.HasPrefix(specifier, "../") {
			loads.local = append(loads.local, specifier)
		}
	}

	for i, token := range tokens {
		if isPunctuation(token, "{") {
			initial := make(map[string]jsBinding)
			if parameters, functionBody := functionParameters[i]; functionBody {
				initial = bindings.snapshot()
				for _, name := range parameters {
					initial[name] = jsNonLoader
				}
			}
			bindings.push(jsBlockIsConditional(tokens, i), initial, false)
			functions.push(functionDeclarationsByScope[i])
			continue
		}
		if isPunctuation(token, "}") {
			bindings.pop()
			functions.pop()
			for _, effect := range directIIFEEffects[i].effects {
				bindings.assign(effect.name, effect.binding, directIIFEEffects[i].conditional || effect.conditional)
			}
			continue
		}
		if token.kind != jsIdentifier {
			continue
		}
		if declared := destructuredDeclarations[i]; declared != nil {
			for name, binding := range declared {
				bindings.declare(name, binding)
				functions.declare(name, nil)
			}
		}
		if declarations[i] && (i+1 >= len(tokens) || !isPunctuation(tokens[i+1], "=")) {
			bindings.declare(token.text, jsNonLoader)
			functions.declare(token.text, nil)
			continue
		}
		if i+2 < len(tokens) && isPunctuation(tokens[i+1], "=") {
			binding := jsAssignmentBinding(tokens, i+2, bindings)
			functionValue := functionAssignments[i]
			if functionValue == nil && tokens[i+2].kind == jsIdentifier && !identifierIsProperty(tokens, i+2) {
				functionValue, _ = functions.lookup(tokens[i+2].text)
			}
			if declarations[i] {
				bindings.declare(token.text, binding)
				functions.declare(token.text, functionValue)
			} else {
				conditional := jsAssignmentIsConditional(tokens, i)
				bindings.assign(token.text, binding, conditional)
				functions.assign(token.text, functionValue, conditional)
			}
			continue
		}
		switch token.text {
		case "import":
			if identifierIsProperty(tokens, i) || i+1 >= len(tokens) || isPunctuation(tokens[i+1], ".") { // object.import / import.meta
				continue
			}
			if isStaticModuleToken(tokens[i+1]) { // import "@adversarylabs/sdk"
				addSpecifier(tokens[i+1])
				continue
			}
			if isPunctuation(tokens[i+1], "(") { // import("@adversarylabs/sdk")
				if argument, ok := loaderCallArgument(tokens, i); ok {
					addSpecifier(argument)
				}
				continue
			}
			if specifier, ok := staticFromSpecifier(tokens, i+1); ok {
				addSpecifier(specifier)
			}
		case "export":
			// Re-exporting the SDK is also an unresolved static module load.
			if identifierIsProperty(tokens, i) {
				continue
			}
			if specifier, ok := staticFromSpecifier(tokens, i+1); ok {
				addSpecifier(specifier)
			}
		default:
			if i+1 < len(tokens) && isPunctuation(tokens[i+1], "(") &&
				(i == 0 || tokens[i-1].kind != jsIdentifier || tokens[i-1].text != "function") && !identifierIsProperty(tokens, i) {
				if functionValue, ok := functions.lookup(token.text); ok && functionValue != nil {
					for _, effect := range functionValue.effects {
						bindings.assign(effect.name, effect.binding, jsOperationIsConditional(tokens, i) || effect.conditional)
					}
				}
			}
			binding := bindings.lookup(token.text)
			if identifierIsProperty(tokens, i) {
				if !isModuleRequire(tokens, i) || bindings.lookup("module")&jsModuleObject == 0 {
					continue
				}
				binding = jsLoader
			}
			if binding&jsLoader == 0 {
				continue
			}
			if argument, ok := loaderCallArgument(tokens, i); ok {
				addSpecifier(argument)
			}
		}
	}
	return loads
}

func importedJSBindings(tokens []jsToken) map[string]jsBinding {
	bindings := make(map[string]jsBinding)
	for i, token := range tokens {
		if token.kind != jsIdentifier || token.text != "import" || identifierIsProperty(tokens, i) ||
			i+1 >= len(tokens) || isPunctuation(tokens[i+1], "(") || isStaticModuleToken(tokens[i+1]) {
			continue
		}
		specifier, ok := staticFromSpecifier(tokens, i+1)
		if !ok {
			continue
		}
		module, exact := staticModuleSpecifier(specifier)
		if !exact {
			continue
		}
		factoryModule := module == "node:module" || module == "module"
		for j := i + 1; j < len(tokens); j++ {
			if tokens[j].kind == jsIdentifier && tokens[j].text == "from" {
				break
			}
			if tokens[j].kind != jsIdentifier || tokens[j].text == "as" {
				continue
			}
			name := tokens[j].text
			imported := name
			if j+2 < len(tokens) && tokens[j+1].kind == jsIdentifier && tokens[j+1].text == "as" && tokens[j+2].kind == jsIdentifier {
				name = tokens[j+2].text
				j += 2
			}
			binding := jsNonLoader
			if factoryModule && imported == "createRequire" {
				binding = jsLoaderFactory
			}
			bindings[name] = binding
		}
	}
	return bindings
}

func simpleJSDeclarationIndexes(tokens []jsToken) map[int]bool {
	declarations := make(map[int]bool)
	for i, token := range tokens {
		if token.kind != jsIdentifier || token.text != "const" && token.text != "let" && token.text != "var" {
			continue
		}
		depth := 0
		expectName := true
		for j := i + 1; j < len(tokens); j++ {
			if depth == 0 && isPunctuation(tokens[j], ";") {
				break
			}
			if isPunctuation(tokens[j], "(") || isPunctuation(tokens[j], "[") || isPunctuation(tokens[j], "{") {
				depth++
				continue
			}
			if isPunctuation(tokens[j], ")") || isPunctuation(tokens[j], "]") || isPunctuation(tokens[j], "}") {
				if depth > 0 {
					depth--
				}
				continue
			}
			if depth == 0 && isPunctuation(tokens[j], ",") {
				expectName = true
				continue
			}
			if depth == 0 && expectName && tokens[j].kind == jsIdentifier {
				declarations[j] = true
				expectName = false
			}
		}
	}
	return declarations
}

func destructuredJSDeclarations(tokens []jsToken) map[int]map[string]jsBinding {
	declarations := make(map[int]map[string]jsBinding)
	for i, token := range tokens {
		if token.kind != jsIdentifier || token.text != "const" && token.text != "let" && token.text != "var" ||
			i+1 >= len(tokens) || !isPunctuation(tokens[i+1], "{") {
			continue
		}
		close := matchingJSPunctuation(tokens, i+1, "{", "}")
		if close < 0 {
			continue
		}
		bindings := destructuredObjectBindings(tokens[i+2:close], "")
		if close+2 < len(tokens) && isPunctuation(tokens[close+1], "=") {
			if module, exact := staticLoaderModule(tokens, close+2); exact && (module == "node:module" || module == "module") {
				bindings = destructuredObjectBindings(tokens[i+2:close], module)
			}
		}
		declarations[i] = bindings
	}
	return declarations
}

func destructuredObjectBindings(tokens []jsToken, module string) map[string]jsBinding {
	bindings := make(map[string]jsBinding)
	depth := 0
	for i := 0; i < len(tokens); i++ {
		if isPunctuation(tokens[i], "{") || isPunctuation(tokens[i], "[") || isPunctuation(tokens[i], "(") {
			depth++
			continue
		}
		if isPunctuation(tokens[i], "}") || isPunctuation(tokens[i], "]") || isPunctuation(tokens[i], ")") {
			if depth > 0 {
				depth--
			}
			continue
		}
		if depth != 0 || tokens[i].kind != jsIdentifier {
			continue
		}
		property := tokens[i].text
		local := property
		if i+2 < len(tokens) && isPunctuation(tokens[i+1], ":") && tokens[i+2].kind == jsIdentifier {
			local = tokens[i+2].text
			i += 2
		}
		binding := jsNonLoader
		if (module == "node:module" || module == "module") && property == "createRequire" {
			binding = jsLoaderFactory
		}
		bindings[local] = binding
		for i+1 < len(tokens) && !isPunctuation(tokens[i+1], ",") {
			i++
		}
	}
	return bindings
}

func staticLoaderModule(tokens []jsToken, start int) (string, bool) {
	if start >= len(tokens) || tokens[start].kind != jsIdentifier || tokens[start].text != "require" ||
		identifierIsProperty(tokens, start) {
		return "", false
	}
	argument, ok := loaderCallArgument(tokens, start)
	if !ok {
		return "", false
	}
	return staticModuleSpecifier(argument)
}

func jsFunctionMetadata(tokens []jsToken, parameters map[int][]string) (map[int]jsFunctionDeclaration, map[int]*jsFunctionValue, map[int]jsInvokedEffects) {
	declarations := make(map[int]jsFunctionDeclaration)
	assignments := make(map[int]*jsFunctionValue)
	direct := make(map[int]jsInvokedEffects)
	for body := 0; body < len(tokens); body++ {
		params, ok := parameters[body]
		if !ok {
			continue
		}
		close := matchingJSPunctuation(tokens, body, "{", "}")
		if close < 0 {
			continue
		}
		effects := jsFunctionBindingEffects(tokens, body, close, params, parameters)
		value := &jsFunctionValue{effects: effects}
		if keyword, name, named := namedJSFunctionAtBody(tokens, body); named {
			declarations[keyword] = jsFunctionDeclaration{name: name, value: value}
		} else if target, assigned := assignedJSFunctionAtBody(tokens, body); assigned {
			assignments[target] = value
		}
		if len(effects) > 0 && jsFunctionBodyIsDirectlyInvoked(tokens, close) {
			direct[close] = jsInvokedEffects{effects: effects, conditional: jsOperationIsConditional(tokens, body)}
		}
	}
	return declarations, assignments, direct
}

func jsFunctionDeclarationsByScope(tokens []jsToken, declarations map[int]jsFunctionDeclaration) map[int]map[string]*jsFunctionValue {
	byScope := make(map[int]map[string]*jsFunctionValue)
	stack := []int{-1}
	for index, token := range tokens {
		if declaration, ok := declarations[index]; ok {
			scope := stack[len(stack)-1]
			if byScope[scope] == nil {
				byScope[scope] = make(map[string]*jsFunctionValue)
			}
			// Function declarations are hoisted, and when a scope contains duplicate
			// declarations JavaScript selects the lexically last declaration.
			byScope[scope][declaration.name] = declaration.value
		}
		if isPunctuation(token, "{") {
			stack = append(stack, index)
		} else if isPunctuation(token, "}") && len(stack) > 1 {
			stack = stack[:len(stack)-1]
		}
	}
	return byScope
}

func namedJSFunctionAtBody(tokens []jsToken, body int) (int, string, bool) {
	if body == 0 || !isPunctuation(tokens[body-1], ")") {
		return 0, "", false
	}
	open := matchingJSPunctuationBackward(tokens, body-1, "(", ")")
	if open < 2 || tokens[open-1].kind != jsIdentifier || tokens[open-2].kind != jsIdentifier || tokens[open-2].text != "function" {
		return 0, "", false
	}
	return open - 2, tokens[open-1].text, true
}

func assignedJSFunctionAtBody(tokens []jsToken, body int) (int, bool) {
	if body >= 3 && isPunctuation(tokens[body-1], ">") && isPunctuation(tokens[body-2], "=") {
		parameterStart := body - 3
		if isPunctuation(tokens[parameterStart], ")") {
			parameterStart = matchingJSPunctuationBackward(tokens, parameterStart, "(", ")")
		}
		if parameterStart >= 2 && isPunctuation(tokens[parameterStart-1], "=") && tokens[parameterStart-2].kind == jsIdentifier {
			return parameterStart - 2, true
		}
	}
	if body > 0 && isPunctuation(tokens[body-1], ")") {
		open := matchingJSPunctuationBackward(tokens, body-1, "(", ")")
		if open >= 3 && tokens[open-1].kind == jsIdentifier && tokens[open-1].text == "function" &&
			isPunctuation(tokens[open-2], "=") && tokens[open-3].kind == jsIdentifier {
			return open - 3, true
		}
	}
	return 0, false
}

func jsFunctionBodyIsDirectlyInvoked(tokens []jsToken, close int) bool {
	i := close + 1
	for i < len(tokens) && isPunctuation(tokens[i], ")") {
		i++
	}
	return i+1 < len(tokens) && isPunctuation(tokens[i], "(") && isPunctuation(tokens[i+1], ")")
}

func jsFunctionBindingEffects(tokens []jsToken, body, close int, parameters []string, functionBodies map[int][]string) []jsBindingEffect {
	locals := make(map[string]bool)
	for _, parameter := range parameters {
		locals[parameter] = true
	}
	declarationIndexes := simpleJSDeclarationIndexes(tokens)
	for index := body + 1; index < close; index++ {
		if declarationIndexes[index] && tokens[index].kind == jsIdentifier {
			locals[tokens[index].text] = true
		}
	}
	for keyword, bindings := range destructuredJSDeclarations(tokens) {
		if keyword <= body || keyword >= close {
			continue
		}
		for name := range bindings {
			locals[name] = true
		}
	}
	imported := importedJSBindings(tokens)
	conditionalStack := make([]bool, 0)
	conditionalDepth := 0
	effects := make([]jsBindingEffect, 0)
	for i := body + 1; i < close; i++ {
		if nestedParameters, nested := functionBodies[i]; nested {
			_ = nestedParameters
			nestedClose := matchingJSPunctuation(tokens, i, "{", "}")
			if nestedClose > i {
				i = nestedClose
			}
			continue
		}
		if isPunctuation(tokens[i], "{") {
			conditional := jsBlockIsConditional(tokens, i)
			conditionalStack = append(conditionalStack, conditional)
			if conditional {
				conditionalDepth++
			}
			continue
		}
		if isPunctuation(tokens[i], "}") {
			if len(conditionalStack) > 0 {
				if conditionalStack[len(conditionalStack)-1] {
					conditionalDepth--
				}
				conditionalStack = conditionalStack[:len(conditionalStack)-1]
			}
			continue
		}
		if tokens[i].kind != jsIdentifier || i+2 >= len(tokens) || !isPunctuation(tokens[i+1], "=") {
			continue
		}
		if locals[tokens[i].text] || declarationIndexes[i] {
			continue
		}
		binding := staticJSFunctionEffectBinding(tokens, i+2, locals, imported)
		effects = append(effects, jsBindingEffect{
			name:        tokens[i].text,
			binding:     binding,
			conditional: conditionalDepth > 0 || jsOperationIsConditional(tokens, i),
		})
	}
	return effects
}

func staticJSFunctionEffectBinding(tokens []jsToken, right int, locals map[string]bool, imported map[string]jsBinding) jsBinding {
	if right >= len(tokens) || tokens[right].kind != jsIdentifier {
		return jsNonLoader
	}
	if tokens[right].text == "require" && !locals["require"] && !identifierIsProperty(tokens, right) {
		return jsLoader
	}
	if isModuleRequire(tokens, right+2) && tokens[right].text == "module" && !locals["module"] {
		return jsLoader
	}
	if imported[tokens[right].text]&jsLoaderFactory != 0 && !locals[tokens[right].text] &&
		right+1 < len(tokens) && isPunctuation(tokens[right+1], "(") {
		return jsLoader
	}
	return jsNonLoader
}

func jsFunctionBodyParameters(tokens []jsToken) map[int][]string {
	parameters := make(map[int][]string)
	for i, token := range tokens {
		if token.kind != jsIdentifier || token.text != "function" {
			continue
		}
		open := i + 1
		if open < len(tokens) && tokens[open].kind == jsIdentifier {
			open++
		}
		if open >= len(tokens) || !isPunctuation(tokens[open], "(") {
			continue
		}
		close := matchingJSPunctuation(tokens, open, "(", ")")
		if close < 0 || close+1 >= len(tokens) || !isPunctuation(tokens[close+1], "{") {
			continue
		}
		parameters[close+1] = jsParameterNames(tokens[open+1 : close])
	}
	for body := range tokens {
		if !isPunctuation(tokens[body], "{") || parameters[body] != nil {
			continue
		}
		if body >= 3 && isPunctuation(tokens[body-1], ">") && isPunctuation(tokens[body-2], "=") {
			parameterEnd := body - 2
			if isPunctuation(tokens[parameterEnd-1], ")") {
				open := matchingJSPunctuationBackward(tokens, parameterEnd-1, "(", ")")
				if open >= 0 {
					parameters[body] = jsParameterNames(tokens[open+1 : parameterEnd-1])
				}
			} else if tokens[parameterEnd-1].kind == jsIdentifier {
				parameters[body] = []string{tokens[parameterEnd-1].text}
			}
			continue
		}
		if body == 0 || !isPunctuation(tokens[body-1], ")") {
			continue
		}
		open := matchingJSPunctuationBackward(tokens, body-1, "(", ")")
		if open <= 0 || tokens[open-1].kind != jsIdentifier {
			continue
		}
		switch tokens[open-1].text {
		case "if", "for", "while", "switch", "with":
			continue
		}
		// Method declarations have the same parameter/body boundary as function
		// declarations but omit the `function` keyword.
		parameters[body] = jsParameterNames(tokens[open+1 : body-1])
	}
	return parameters
}

func jsParameterNames(tokens []jsToken) []string {
	names := make([]string, 0)
	for i := 0; i < len(tokens); {
		if isPunctuation(tokens[i], "{") {
			close := matchingJSPunctuation(tokens, i, "{", "}")
			if close < 0 {
				break
			}
			for name := range destructuredObjectBindings(tokens[i+1:close], "") {
				names = append(names, name)
			}
			i = close + 1
			continue
		}
		if isPunctuation(tokens[i], "[") {
			close := matchingJSPunctuation(tokens, i, "[", "]")
			if close < 0 {
				break
			}
			for _, token := range tokens[i+1 : close] {
				if token.kind == jsIdentifier {
					names = append(names, token.text)
				}
			}
			i = close + 1
			continue
		}
		if tokens[i].kind == jsIdentifier {
			names = append(names, tokens[i].text)
			for i < len(tokens) && !isPunctuation(tokens[i], ",") {
				i++
			}
			continue
		}
		i++
	}
	return names
}

func jsBlockIsConditional(tokens []jsToken, open int) bool {
	if open == 0 {
		return false
	}
	if tokens[open-1].kind == jsIdentifier && tokens[open-1].text == "else" {
		return true
	}
	if !isPunctuation(tokens[open-1], ")") {
		return false
	}
	conditionOpen := matchingJSPunctuationBackward(tokens, open-1, "(", ")")
	if conditionOpen <= 0 || tokens[conditionOpen-1].kind != jsIdentifier {
		return false
	}
	switch tokens[conditionOpen-1].text {
	case "if", "for", "while", "switch", "catch", "with":
		return true
	default:
		return false
	}
}

func jsAssignmentIsConditional(tokens []jsToken, assignment int) bool {
	return jsOperationIsConditional(tokens, assignment)
}

func jsOperationIsConditional(tokens []jsToken, position int) bool {
	if position == 0 {
		return false
	}
	if isPunctuation(tokens[position-1], ")") {
		conditionOpen := matchingJSPunctuationBackward(tokens, position-1, "(", ")")
		if conditionOpen > 0 && tokens[conditionOpen-1].kind == jsIdentifier &&
			(tokens[conditionOpen-1].text == "if" || tokens[conditionOpen-1].text == "while" || tokens[conditionOpen-1].text == "for") {
			return true
		}
	}
	for i := position - 1; i >= 0 && !isPunctuation(tokens[i], ";") && !isPunctuation(tokens[i], "{") && !isPunctuation(tokens[i], "}"); i-- {
		if isPunctuation(tokens[i], "?") ||
			i > 0 && isPunctuation(tokens[i], "&") && isPunctuation(tokens[i-1], "&") ||
			i > 0 && isPunctuation(tokens[i], "|") && isPunctuation(tokens[i-1], "|") {
			return true
		}
	}
	return false
}

func jsAssignmentBinding(tokens []jsToken, right int, bindings *jsBindingTracker) jsBinding {
	if right >= len(tokens) || tokens[right].kind != jsIdentifier {
		return jsNonLoader
	}
	if isModuleRequire(tokens, right) && bindings.lookup("module")&jsModuleObject != 0 {
		return jsLoader
	}
	binding := bindings.lookup(tokens[right].text)
	if binding&jsLoaderFactory != 0 && right+1 < len(tokens) && isPunctuation(tokens[right+1], "(") {
		return jsLoader
	}
	return binding
}

func matchingJSPunctuation(tokens []jsToken, open int, left, right string) int {
	depth := 0
	for i := open; i < len(tokens); i++ {
		if isPunctuation(tokens[i], left) {
			depth++
		} else if isPunctuation(tokens[i], right) {
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func matchingJSPunctuationBackward(tokens []jsToken, close int, left, right string) int {
	depth := 0
	for i := close; i >= 0; i-- {
		if isPunctuation(tokens[i], right) {
			depth++
		} else if isPunctuation(tokens[i], left) {
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func staticFromSpecifier(tokens []jsToken, start int) (jsToken, bool) {
	depth := 0
	for i := start; i < len(tokens); i++ {
		if depth == 0 && isPunctuation(tokens[i], ";") {
			return jsToken{}, false
		}
		if isPunctuation(tokens[i], "{") || isPunctuation(tokens[i], "[") || isPunctuation(tokens[i], "(") {
			depth++
			continue
		}
		if isPunctuation(tokens[i], "}") || isPunctuation(tokens[i], "]") || isPunctuation(tokens[i], ")") {
			if depth > 0 {
				depth--
			}
			continue
		}
		if depth == 0 && tokens[i].kind == jsIdentifier && tokens[i].text == "from" && i+1 < len(tokens) && isStaticModuleToken(tokens[i+1]) {
			return tokens[i+1], true
		}
	}
	return jsToken{}, false
}

func loaderCallArgument(tokens []jsToken, identifier int) (jsToken, bool) {
	open := identifier + 1
	if open+2 < len(tokens) && isPunctuation(tokens[open], "?") && isPunctuation(tokens[open+1], ".") {
		open += 2
	}
	if open >= len(tokens) || !isPunctuation(tokens[open], "(") {
		return jsToken{}, false
	}
	close := matchingJSPunctuation(tokens, open, "(", ")")
	if close < 0 || close == open+1 {
		return jsToken{}, false
	}
	end := close
	depth := 0
	for i := open + 1; i < close; i++ {
		if isPunctuation(tokens[i], "(") || isPunctuation(tokens[i], "[") || isPunctuation(tokens[i], "{") {
			depth++
		} else if isPunctuation(tokens[i], ")") || isPunctuation(tokens[i], "]") || isPunctuation(tokens[i], "}") {
			if depth > 0 {
				depth--
			}
		} else if depth == 0 && isPunctuation(tokens[i], ",") {
			end = i
			break
		}
	}
	return staticJSModuleExpression(tokens[open+1 : end]), true
}

func staticJSModuleExpression(tokens []jsToken) jsToken {
	if len(tokens) == 0 {
		return jsToken{kind: jsString, ambiguous: true}
	}
	var value strings.Builder
	escaped := false
	for i := 0; i < len(tokens); i++ {
		if i%2 == 1 {
			if !isPunctuation(tokens[i], "+") {
				return jsToken{kind: jsString, text: value.String(), escaped: escaped, ambiguous: true}
			}
			continue
		}
		if !isStaticModuleToken(tokens[i]) || tokens[i].ambiguous {
			return jsToken{kind: jsString, text: value.String(), escaped: escaped, ambiguous: true}
		}
		value.WriteString(tokens[i].text)
		escaped = escaped || tokens[i].escaped
	}
	if len(tokens)%2 == 0 {
		return jsToken{kind: jsString, text: value.String(), escaped: escaped, ambiguous: true}
	}
	return jsToken{kind: jsString, text: value.String(), escaped: escaped}
}

func isModuleRequire(tokens []jsToken, i int) bool {
	return i >= 2 && tokens[i].kind == jsIdentifier && tokens[i].text == "require" &&
		isPunctuation(tokens[i-1], ".") && tokens[i-2].kind == jsIdentifier && tokens[i-2].text == "module" &&
		!identifierIsProperty(tokens, i-2)
}

func identifierIsProperty(tokens []jsToken, i int) bool {
	return i > 0 && isPunctuation(tokens[i-1], ".")
}

func isStaticModuleToken(token jsToken) bool {
	return token.kind == jsString || token.kind == jsTemplate
}

func staticModuleSpecifier(token jsToken) (string, bool) {
	if !isStaticModuleToken(token) || token.ambiguous {
		return "", false
	}
	return token.text, true
}

func isSDKModule(specifier string) bool {
	return specifier == "@adversarylabs/sdk" || specifier == "@adversary/sdk"
}

func isPunctuation(token jsToken, value string) bool {
	return token.kind == jsPunctuation && token.text == value
}

type jsLexer struct {
	source    []byte
	position  int
	tokens    []jsToken
	ambiguous bool
}

func lexJSTokens(source []byte) ([]jsToken, bool) {
	lexer := &jsLexer{source: source, tokens: make([]jsToken, 0, len(source)/8)}
	lexer.scanCode(false)
	if len(lexer.tokens) > maxJSEntrypointTokens {
		lexer.ambiguous = true
	}
	return lexer.tokens, lexer.ambiguous
}

func (lexer *jsLexer) scanCode(stopAtTemplateBrace bool) {
	braceDepth := 0
	if lexer.position == 0 && len(lexer.source) >= 2 && lexer.source[0] == '#' && lexer.source[1] == '!' {
		for lexer.position < len(lexer.source) && lexer.source[lexer.position] != '\n' && lexer.source[lexer.position] != '\r' {
			lexer.position++
		}
	}
	for lexer.position < len(lexer.source) && !lexer.ambiguous {
		c := lexer.source[lexer.position]
		if isJSSpace(c) {
			lexer.position++
			continue
		}
		if c == '/' && lexer.position+1 < len(lexer.source) {
			next := lexer.source[lexer.position+1]
			switch next {
			case '/':
				lexer.position += 2
				for lexer.position < len(lexer.source) && lexer.source[lexer.position] != '\n' && lexer.source[lexer.position] != '\r' {
					lexer.position++
				}
				continue
			case '*':
				lexer.position += 2
				closed := false
				for lexer.position+1 < len(lexer.source) {
					if lexer.source[lexer.position] == '*' && lexer.source[lexer.position+1] == '/' {
						lexer.position += 2
						closed = true
						break
					}
					lexer.position++
				}
				if !closed {
					lexer.ambiguous = true
				}
				continue
			}
			if canStartJSRegex(lexer.tokens) {
				if lexer.scanRegex() {
					continue
				}
			}
		}
		if c == '\'' || c == '"' {
			lexer.tokens = append(lexer.tokens, lexer.scanString(c))
			continue
		}
		if c == '`' {
			lexer.scanTemplate()
			continue
		}
		if isJSIdentifierStart(c) || c == '\\' {
			token, ok := lexer.scanIdentifier()
			if !ok {
				lexer.ambiguous = true
				continue
			}
			lexer.tokens = append(lexer.tokens, token)
			continue
		}
		if c >= '0' && c <= '9' || c == '.' && lexer.position+1 < len(lexer.source) && lexer.source[lexer.position+1] >= '0' && lexer.source[lexer.position+1] <= '9' {
			lexer.scanNumber()
			continue
		}
		if c == '{' {
			braceDepth++
		} else if c == '}' && stopAtTemplateBrace {
			if braceDepth == 0 {
				lexer.position++
				return
			}
			braceDepth--
		}
		lexer.tokens = append(lexer.tokens, jsToken{kind: jsPunctuation, text: string(c)})
		lexer.position++
	}
	if stopAtTemplateBrace && !lexer.ambiguous {
		lexer.ambiguous = true
	}
}

func (lexer *jsLexer) scanIdentifier() (jsToken, bool) {
	var value strings.Builder
	escaped := false
	first := true
	for lexer.position < len(lexer.source) {
		c := lexer.source[lexer.position]
		if c == '\\' {
			r, next, ok := scanJSUnicodeEscape(lexer.source, lexer.position)
			if !ok || first && !isJSIdentifierStartRune(r) || !first && !isJSIdentifierPartRune(r) {
				return jsToken{}, false
			}
			value.WriteRune(r)
			lexer.position = next
			escaped = true
			first = false
			continue
		}
		if first && isJSIdentifierStart(c) || !first && isJSIdentifierPart(c) {
			value.WriteByte(c)
			lexer.position++
			first = false
			continue
		}
		break
	}
	if first {
		return jsToken{}, false
	}
	return jsToken{kind: jsIdentifier, text: value.String(), escaped: escaped}, true
}

func scanJSUnicodeEscape(source []byte, start int) (rune, int, bool) {
	if start+2 >= len(source) || source[start] != '\\' || source[start+1] != 'u' {
		return 0, start, false
	}
	if source[start+2] == '{' {
		end := start + 3
		for end < len(source) && source[end] != '}' && end-start <= 9 {
			end++
		}
		if end >= len(source) || source[end] != '}' || end == start+3 {
			return 0, start, false
		}
		value, err := strconv.ParseUint(string(source[start+3:end]), 16, 32)
		if err != nil || value > unicode.MaxRune {
			return 0, start, false
		}
		return rune(value), end + 1, true
	}
	if start+6 > len(source) {
		return 0, start, false
	}
	value, err := strconv.ParseUint(string(source[start+2:start+6]), 16, 16)
	if err != nil {
		return 0, start, false
	}
	return rune(value), start + 6, true
}

func isJSIdentifierStartRune(r rune) bool {
	return r == '_' || r == '$' || unicode.IsLetter(r)
}

func isJSIdentifierPartRune(r rune) bool {
	return isJSIdentifierStartRune(r) || unicode.IsDigit(r)
}

func (lexer *jsLexer) scanNumber() {
	start := lexer.position
	lexer.position++
	for lexer.position < len(lexer.source) {
		c := lexer.source[lexer.position]
		if isJSIdentifierPart(c) || c == '.' {
			lexer.position++
			continue
		}
		if (c == '+' || c == '-') && lexer.position > start && (lexer.source[lexer.position-1] == 'e' || lexer.source[lexer.position-1] == 'E') {
			lexer.position++
			continue
		}
		break
	}
	lexer.tokens = append(lexer.tokens, jsToken{kind: jsNumber, text: string(lexer.source[start:lexer.position])})
}

func canStartJSRegex(tokens []jsToken) bool {
	if len(tokens) == 0 {
		return true
	}
	previous := tokens[len(tokens)-1]
	if previous.kind == jsPunctuation {
		switch previous.text {
		case ")":
			return followsJSControlCondition(tokens)
		case "]", "}", ".":
			return false
		default:
			return true
		}
	}
	if previous.kind == jsIdentifier {
		switch previous.text {
		case "return", "throw", "case", "delete", "void", "typeof", "new", "in", "instanceof", "yield", "await", "else", "do":
			return true
		}
	}
	return false
}

func followsJSControlCondition(tokens []jsToken) bool {
	depth := 0
	for i := len(tokens) - 1; i >= 0; i-- {
		if isPunctuation(tokens[i], ")") {
			depth++
			continue
		}
		if !isPunctuation(tokens[i], "(") {
			continue
		}
		depth--
		if depth != 0 {
			continue
		}
		if i == 0 || tokens[i-1].kind != jsIdentifier {
			return false
		}
		switch tokens[i-1].text {
		case "if", "while", "for", "with", "switch", "catch":
			return true
		default:
			return false
		}
	}
	return false
}

func (lexer *jsLexer) scanRegex() bool {
	start := lexer.position
	lexer.position++
	inCharacterClass := false
	for lexer.position < len(lexer.source) {
		c := lexer.source[lexer.position]
		if c == '\n' || c == '\r' {
			lexer.position = start
			return false
		}
		if c == '\\' {
			lexer.position += 2
			continue
		}
		if c == '[' {
			inCharacterClass = true
		} else if c == ']' {
			inCharacterClass = false
		} else if c == '/' && !inCharacterClass {
			lexer.position++
			for lexer.position < len(lexer.source) && isJSIdentifierPart(lexer.source[lexer.position]) {
				lexer.position++
			}
			lexer.tokens = append(lexer.tokens, jsToken{kind: jsRegex})
			return true
		}
		lexer.position++
	}
	lexer.position = start
	return false
}

func (lexer *jsLexer) scanString(quote byte) jsToken {
	lexer.position++
	start := lexer.position
	escaped := false
	var value strings.Builder
	for lexer.position < len(lexer.source) {
		c := lexer.source[lexer.position]
		if c == quote {
			value.Write(lexer.source[start:lexer.position])
			lexer.position++
			return jsToken{kind: jsString, text: value.String(), escaped: escaped}
		}
		if c == '\n' || c == '\r' {
			lexer.ambiguous = true
			return jsToken{kind: jsString, ambiguous: true}
		}
		if c == '\\' {
			value.Write(lexer.source[start:lexer.position])
			escaped = true
			decoded, next, ok := scanJSStringEscape(lexer.source, lexer.position)
			if !ok {
				lexer.ambiguous = true
				return jsToken{kind: jsString, text: value.String(), escaped: true, ambiguous: true}
			}
			value.WriteString(decoded)
			lexer.position = next
			start = lexer.position
			continue
		}
		lexer.position++
	}
	lexer.ambiguous = true
	return jsToken{kind: jsString, ambiguous: true}
}

func scanJSStringEscape(source []byte, slash int) (string, int, bool) {
	if slash+1 >= len(source) || source[slash] != '\\' {
		return "", slash, false
	}
	c := source[slash+1]
	switch c {
	case 'x':
		if slash+4 > len(source) {
			return "", slash, false
		}
		value, err := strconv.ParseUint(string(source[slash+2:slash+4]), 16, 8)
		if err != nil {
			return "", slash, false
		}
		return string(rune(value)), slash + 4, true
	case 'u':
		r, next, ok := scanJSUnicodeEscape(source, slash)
		return string(r), next, ok
	case '\n':
		return "", slash + 2, true
	case '\r':
		if slash+2 < len(source) && source[slash+2] == '\n' {
			return "", slash + 3, true
		}
		return "", slash + 2, true
	case 'n':
		return "\n", slash + 2, true
	case 'r':
		return "\r", slash + 2, true
	case 't':
		return "\t", slash + 2, true
	case 'b':
		return "\b", slash + 2, true
	case 'f':
		return "\f", slash + 2, true
	case 'v':
		return "\v", slash + 2, true
	case '0':
		return "\x00", slash + 2, true
	default:
		return string(c), slash + 2, true
	}
}

func (lexer *jsLexer) scanTemplate() {
	lexer.position++
	start := lexer.position
	tokenIndex := len(lexer.tokens)
	lexer.tokens = append(lexer.tokens, jsToken{kind: jsTemplate})
	var value strings.Builder
	escaped := false
	ambiguous := false
	for lexer.position < len(lexer.source) {
		c := lexer.source[lexer.position]
		switch c {
		case '`':
			value.Write(lexer.source[start:lexer.position])
			lexer.position++
			lexer.tokens[tokenIndex] = jsToken{kind: jsTemplate, text: value.String(), escaped: escaped, ambiguous: ambiguous}
			return
		case '\\':
			value.Write(lexer.source[start:lexer.position])
			escaped = true
			decoded, next, ok := scanJSStringEscape(lexer.source, lexer.position)
			if !ok {
				lexer.ambiguous = true
				return
			}
			value.WriteString(decoded)
			lexer.position = next
			start = lexer.position
		case '$':
			if lexer.position+1 < len(lexer.source) && lexer.source[lexer.position+1] == '{' {
				value.Write(lexer.source[start:lexer.position])
				ambiguous = true
				lexer.position += 2
				lexer.scanCode(true)
				start = lexer.position
				continue
			}
			lexer.position++
		default:
			lexer.position++
		}
	}
	lexer.ambiguous = true
}

func isJSSpace(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\r', '\f', '\v':
		return true
	default:
		return false
	}
}

func isJSIdentifierStart(c byte) bool {
	return c == '_' || c == '$' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func isJSIdentifierPart(c byte) bool {
	return isJSIdentifierStart(c) || c >= '0' && c <= '9'
}
