package pack

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/adversarylabs/adversary/pkg/manifest"
)

const maxJSEntrypointScanBytes = 16 << 20
const maxJSEntrypointTokens = 1 << 20

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

	for _, entrypoint := range entrypoints {
		needs, err := jsEntrypointNeedsSDKClosure(root, entrypoint)
		if err != nil {
			return false, fmt.Errorf("inspect JavaScript entrypoint %q for SDK imports: %w", entrypoint, err)
		}
		if needs {
			return true, nil
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

func jsEntrypointNeedsSDKClosure(root *os.Root, entrypoint string) (bool, error) {
	f, err := root.Open(filepath.FromSlash(entrypoint))
	if err != nil {
		// Entrypoint validation reports missing build output with its established
		// error. There is no source to classify in that case.
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	defer f.Close()

	source, err := io.ReadAll(io.LimitReader(f, maxJSEntrypointScanBytes+1))
	if err != nil {
		return false, err
	}
	if len(source) > maxJSEntrypointScanBytes {
		return true, nil
	}
	tokens, ambiguous := lexJSTokens(source)
	if ambiguous {
		return true, nil
	}
	return tokensLoadSDK(tokens), nil
}

func tokensLoadSDK(tokens []jsToken) bool {
	for i, token := range tokens {
		if token.kind != jsIdentifier {
			continue
		}
		switch token.text {
		case "require":
			if i > 0 && tokens[i-1].kind == jsPunctuation && tokens[i-1].text == "." {
				continue
			}
			if i+2 < len(tokens) && isPunctuation(tokens[i+1], "(") && sdkModuleToken(tokens[i+2]) {
				return true
			}
		case "import":
			if i+1 >= len(tokens) || isPunctuation(tokens[i+1], ".") { // import.meta
				continue
			}
			if sdkModuleToken(tokens[i+1]) { // import "@adversarylabs/sdk"
				return true
			}
			if isPunctuation(tokens[i+1], "(") { // import("@adversarylabs/sdk")
				if i+2 < len(tokens) && sdkModuleToken(tokens[i+2]) {
					return true
				}
				continue
			}
			// Static import clauses are bounded both by token count and their
			// statement terminator. This accepts multiline import clauses without
			// scanning arbitrary later source for a coincidental `from` string.
			limit := i + 64
			if limit > len(tokens) {
				limit = len(tokens)
			}
			for j := i + 1; j < limit; j++ {
				if isPunctuation(tokens[j], ";") {
					break
				}
				if tokens[j].kind == jsIdentifier && tokens[j].text == "from" && j+1 < limit && sdkModuleToken(tokens[j+1]) {
					return true
				}
			}
		case "export":
			// Re-exporting the SDK is also an unresolved static module load.
			limit := i + 64
			if limit > len(tokens) {
				limit = len(tokens)
			}
			for j := i + 1; j < limit; j++ {
				if isPunctuation(tokens[j], ";") {
					break
				}
				if tokens[j].kind == jsIdentifier && tokens[j].text == "from" && j+1 < limit && sdkModuleToken(tokens[j+1]) {
					return true
				}
			}
		}
	}
	return false
}

func isPunctuation(token jsToken, value string) bool {
	return token.kind == jsPunctuation && token.text == value
}

func sdkModuleToken(token jsToken) bool {
	if token.kind != jsString && token.kind != jsTemplate {
		return false
	}
	if !token.escaped && !token.ambiguous {
		return token.text == "@adversarylabs/sdk" || token.text == "@adversary/sdk"
	}
	// Escapes and template substitutions make exact static resolution harder.
	// If this is syntactically in a module-load position, include the closure
	// rather than risk producing an artifact that cannot execute offline.
	return token.ambiguous || strings.Contains(token.text, "@adversarylabs") || strings.Contains(token.text, "@adversary/sdk")
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
		if isJSIdentifierStart(c) {
			start := lexer.position
			lexer.position++
			for lexer.position < len(lexer.source) && isJSIdentifierPart(lexer.source[lexer.position]) {
				lexer.position++
			}
			lexer.tokens = append(lexer.tokens, jsToken{kind: jsIdentifier, text: string(lexer.source[start:lexer.position])})
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
			value.WriteByte(c)
			lexer.position++
			if lexer.position >= len(lexer.source) {
				lexer.ambiguous = true
				return jsToken{kind: jsString, text: value.String(), escaped: true, ambiguous: true}
			}
			value.WriteByte(lexer.source[lexer.position])
			lexer.position++
			start = lexer.position
			continue
		}
		lexer.position++
	}
	lexer.ambiguous = true
	return jsToken{kind: jsString, ambiguous: true}
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
