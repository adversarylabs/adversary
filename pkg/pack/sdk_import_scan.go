package pack

import (
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
	clean := path.Clean(path.Join(path.Dir(importer), specifier))
	if clean == ".." || strings.HasPrefix(clean, "../") || path.IsAbs(clean) {
		return nil, fmt.Errorf("local JavaScript import %q from %q escapes package root", specifier, importer)
	}
	candidates := []string{clean}
	if !isJSEntrypoint(clean) {
		candidates = append(candidates,
			clean+".js", clean+".mjs", clean+".cjs",
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

func tokensLoadSDK(tokens []jsToken) bool {
	return tokensModuleLoads(tokens).sdk
}

func tokensModuleLoads(tokens []jsToken) jsModuleLoads {
	loads := jsModuleLoads{}
	loaderNames := map[string]bool{"require": true}
	createRequireNames := importedCreateRequireNames(tokens)
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
		if token.kind != jsIdentifier {
			continue
		}
		if i+2 < len(tokens) && isPunctuation(tokens[i+1], "=") {
			right := i + 2
			isLoader := tokens[right].kind == jsIdentifier && loaderNames[tokens[right].text] && !identifierIsProperty(tokens, right)
			if !isLoader && isModuleRequire(tokens, right) {
				isLoader = true
			}
			if !isLoader && tokens[right].kind == jsIdentifier && createRequireNames[tokens[right].text] &&
				right+1 < len(tokens) && isPunctuation(tokens[right+1], "(") {
				isLoader = true
			}
			if isLoader {
				loaderNames[token.text] = true
			} else {
				delete(loaderNames, token.text)
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
				if i+2 < len(tokens) && isStaticModuleToken(tokens[i+2]) {
					addSpecifier(tokens[i+2])
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
			if !loaderNames[token.text] || identifierIsProperty(tokens, i) && !isModuleRequire(tokens, i) {
				continue
			}
			if argument, ok := loaderCallArgument(tokens, i); ok {
				addSpecifier(argument)
			}
		}
	}
	return loads
}

func importedCreateRequireNames(tokens []jsToken) map[string]bool {
	names := make(map[string]bool)
	for i, token := range tokens {
		if token.kind != jsIdentifier || token.text != "import" || identifierIsProperty(tokens, i) {
			continue
		}
		specifier, ok := staticFromSpecifier(tokens, i+1)
		if !ok {
			continue
		}
		module, exact := staticModuleSpecifier(specifier)
		if !exact || module != "node:module" && module != "module" {
			continue
		}
		for j := i + 1; j+1 < len(tokens); j++ {
			if tokens[j].kind == jsIdentifier && tokens[j].text == "from" {
				break
			}
			if tokens[j].kind != jsIdentifier || tokens[j].text != "createRequire" {
				continue
			}
			name := "createRequire"
			if j+2 < len(tokens) && tokens[j+1].kind == jsIdentifier && tokens[j+1].text == "as" && tokens[j+2].kind == jsIdentifier {
				name = tokens[j+2].text
			}
			names[name] = true
		}
	}
	return names
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
	if open >= len(tokens) || !isPunctuation(tokens[open], "(") || open+1 >= len(tokens) || !isStaticModuleToken(tokens[open+1]) {
		return jsToken{}, false
	}
	return tokens[open+1], true
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
			value.WriteByte(c)
			lexer.position++
			if lexer.position >= len(lexer.source) {
				lexer.ambiguous = true
				return
			}
			value.WriteByte(lexer.source[lexer.position])
			lexer.position++
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
