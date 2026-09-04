package repoindex

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const v2SchemaSQL = `
PRAGMA journal_mode=DELETE;
PRAGMA synchronous=FULL;
PRAGMA foreign_keys=ON;
CREATE TABLE files (
  id INTEGER PRIMARY KEY, path TEXT NOT NULL UNIQUE, language TEXT NOT NULL,
  size INTEGER NOT NULL, hash TEXT NOT NULL, module TEXT NOT NULL DEFAULT ''
);
CREATE TABLE symbols (
  id INTEGER PRIMARY KEY, file_id INTEGER NOT NULL REFERENCES files(id),
  name TEXT NOT NULL, kind TEXT NOT NULL, start_line INTEGER NOT NULL,
  start_col INTEGER NOT NULL, end_line INTEGER NOT NULL, end_col INTEGER NOT NULL,
  container_id INTEGER REFERENCES symbols(id), exported INTEGER NOT NULL,
  adapter_data TEXT NOT NULL DEFAULT ''
);
CREATE TABLE edges (
  id INTEGER PRIMARY KEY, from_file_id INTEGER NOT NULL REFERENCES files(id),
  from_symbol_id INTEGER REFERENCES symbols(id), to_file_id INTEGER REFERENCES files(id),
  to_symbol_id INTEGER REFERENCES symbols(id), unresolved_target TEXT,
  kind TEXT NOT NULL, line INTEGER NOT NULL, column INTEGER NOT NULL,
  confidence REAL NOT NULL, adapter TEXT NOT NULL
);
CREATE TABLE test_links (
  id INTEGER PRIMARY KEY, source_file_id INTEGER NOT NULL REFERENCES files(id),
  source_symbol_id INTEGER REFERENCES symbols(id), test_file_id INTEGER NOT NULL REFERENCES files(id),
  test_symbol_id INTEGER REFERENCES symbols(id), confidence REAL NOT NULL, reason TEXT NOT NULL
);
CREATE INDEX files_language_path ON files(language,path);
CREATE INDEX symbols_file_name_kind ON symbols(file_id,name,kind);
CREATE INDEX symbols_name_kind ON symbols(name,kind);
CREATE INDEX edges_kind_source ON edges(kind,from_symbol_id,from_file_id);
CREATE INDEX edges_kind_target ON edges(kind,to_symbol_id,to_file_id);
CREATE INDEX test_links_source ON test_links(source_file_id,source_symbol_id);
`

type v2FileRecord struct {
	id       int64
	path     string
	language string
	module   string
	body     []byte
	goFile   *ast.File
	fset     *token.FileSet
}

type v2SymbolDraft struct {
	id          int64
	fileID      int64
	filePath    string
	module      string
	name        string
	kind        string
	startLine   int
	startColumn int
	endLine     int
	endColumn   int
	exported    bool
	metadata    string
}

type v2BuildState struct {
	db           *sql.DB
	files        []v2FileRecord
	fileByPath   map[string]*v2FileRecord
	symbols      []v2SymbolDraft
	byName       map[string][]*v2SymbolDraft
	byFileName   map[string][]*v2SymbolDraft
	byModuleName map[string][]*v2SymbolDraft
	edges        int
	testLinks    int
	diagnostics  []V2Diagnostic
}

func V2Fingerprint(absRepo string) (string, error) {
	v1, err := Fingerprint(absRepo)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte(V2SchemaVersion + "\n" + V2AdapterRevision + "\n" + v1))
	return hex.EncodeToString(digest[:]), nil
}

func EnsureV2(absRepo string, mode Mode, stderr io.Writer) (*V2Handle, error) {
	if mode == ModeOff {
		return nil, nil
	}
	absRepo, err := filepath.Abs(absRepo)
	if err != nil {
		return nil, err
	}
	absRepo = filepath.Clean(absRepo)
	fingerprint, err := V2Fingerprint(absRepo)
	if err != nil {
		return nil, err
	}
	root, err := CacheRoot()
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(root, V2SchemaVersion, FingerprintKey(fingerprint))
	unlock := lockEnsure("v2:" + dir)
	defer unlock()
	if err := recoverV2Publication(dir); err != nil {
		return nil, err
	}
	if mode != ModeForce && mode != ModeGraphForce {
		if meta, ok := loadV2Meta(filepath.Join(dir, v2MetaFile)); ok && meta.SchemaVersion == V2SchemaVersion && meta.AdapterRevision == V2AdapterRevision && meta.Fingerprint == fingerprint {
			if _, err := os.Stat(filepath.Join(dir, v2DatabaseFile)); err == nil {
				return &V2Handle{Dir: dir, Meta: meta}, nil
			}
		}
	}
	if stderr != nil {
		fmt.Fprintf(stderr, "repo-graph: building %s\n", absRepo)
	}
	meta, err := BuildV2(absRepo, dir, fingerprint)
	if err != nil {
		return nil, err
	}
	meta.Rebuilt = true
	if stderr != nil {
		fmt.Fprintf(stderr, "repo-graph: wrote %d files, %d symbols, %d edges, %d test links -> %s\n", meta.FileCount, meta.SymbolCount, meta.EdgeCount, meta.TestLinkCount, dir)
	}
	return &V2Handle{Dir: dir, Meta: meta}, nil
}

func BuildV2(absRepo, dir, fingerprint string) (V2Meta, error) {
	started := time.Now()
	temporary := fmt.Sprintf("%s.tmp-%d", dir, os.Getpid())
	if err := os.RemoveAll(temporary); err != nil {
		return V2Meta{}, err
	}
	if err := os.MkdirAll(temporary, 0o700); err != nil {
		return V2Meta{}, err
	}
	complete := false
	defer func() {
		if !complete {
			_ = os.RemoveAll(temporary)
		}
	}()

	databasePath := filepath.Join(temporary, v2DatabaseFile)
	db, err := sql.Open("sqlite", databasePath)
	if err != nil {
		return V2Meta{}, err
	}
	if _, err := db.Exec(v2SchemaSQL); err != nil {
		_ = db.Close()
		return V2Meta{}, err
	}
	state := &v2BuildState{db: db, fileByPath: map[string]*v2FileRecord{}, byName: map[string][]*v2SymbolDraft{}, byFileName: map[string][]*v2SymbolDraft{}, byModuleName: map[string][]*v2SymbolDraft{}}
	if err := state.index(absRepo); err != nil {
		_ = db.Close()
		return V2Meta{}, err
	}
	if _, err := db.Exec("PRAGMA optimize"); err != nil {
		_ = db.Close()
		return V2Meta{}, err
	}
	if err := db.Close(); err != nil {
		return V2Meta{}, err
	}
	if err := os.Chmod(databasePath, 0o600); err != nil {
		return V2Meta{}, err
	}
	meta := V2Meta{
		SchemaVersion: V2SchemaVersion, AdapterRevision: V2AdapterRevision,
		Fingerprint: fingerprint, RepoPath: absRepo, BuiltAt: time.Now().UTC(),
		DurationMS: time.Since(started).Milliseconds(), FileCount: len(state.files),
		SymbolCount: len(state.symbols), EdgeCount: state.edges, TestLinkCount: state.testLinks,
		ParseFailures: state.diagnostics,
	}
	raw, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return V2Meta{}, err
	}
	if err := os.WriteFile(filepath.Join(temporary, v2MetaFile), append(raw, '\n'), 0o600); err != nil {
		return V2Meta{}, err
	}
	for _, path := range []string{databasePath, filepath.Join(temporary, v2MetaFile)} {
		file, err := os.Open(path)
		if err != nil {
			return V2Meta{}, err
		}
		err = file.Sync()
		_ = file.Close()
		if err != nil {
			return V2Meta{}, err
		}
	}
	if err := publishV2Directory(temporary, dir); err != nil {
		return V2Meta{}, err
	}
	complete = true
	return meta, nil
}

func (state *v2BuildState) index(absRepo string) error {
	paths, err := listIndexableFiles(absRepo)
	if err != nil {
		return err
	}
	goModRoot, goModule := readGoMod(absRepo)
	_ = goModRoot
	transaction, err := state.db.Begin()
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	insertFile, err := transaction.Prepare("INSERT INTO files(path,language,size,hash,module) VALUES(?,?,?,?,?)")
	if err != nil {
		return err
	}
	defer insertFile.Close()
	for _, relative := range paths {
		fullPath := filepath.Join(absRepo, relative)
		info, err := os.Lstat(fullPath)
		if err != nil {
			state.diagnostics = append(state.diagnostics, V2Diagnostic{Path: filepath.ToSlash(relative), Adapter: "inventory", Message: err.Error()})
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 {
			state.diagnostics = append(state.diagnostics, V2Diagnostic{Path: filepath.ToSlash(relative), Adapter: "inventory", Message: "symlink excluded from repository graph"})
			continue
		}
		body, err := os.ReadFile(fullPath)
		if err != nil {
			state.diagnostics = append(state.diagnostics, V2Diagnostic{Path: filepath.ToSlash(relative), Adapter: "inventory", Message: err.Error()})
			continue
		}
		path := filepath.ToSlash(relative)
		language := languageOf(path)
		module := moduleForPath(path, language, goModule)
		digest := sha256.Sum256(body)
		result, err := insertFile.Exec(path, language, len(body), hex.EncodeToString(digest[:]), module)
		if err != nil {
			return err
		}
		id, err := result.LastInsertId()
		if err != nil {
			return err
		}
		record := v2FileRecord{id: id, path: path, language: language, module: module, body: body}
		state.files = append(state.files, record)
		state.fileByPath[path] = &state.files[len(state.files)-1]
	}
	if err := transaction.Commit(); err != nil {
		return err
	}
	for index := range state.files {
		record := &state.files[index]
		state.fileByPath[record.path] = record
		switch record.language {
		case "go":
			state.parseGo(record)
		case "typescript", "javascript":
			state.parseTypeScript(record)
		}
	}
	if err := state.insertSymbols(); err != nil {
		return err
	}
	if err := state.insertRelations(absRepo, goModule); err != nil {
		return err
	}
	return state.insertTestLinks()
}

func moduleForPath(path, language, goModule string) string {
	dir := filepath.ToSlash(filepath.Dir(path))
	if dir == "." {
		dir = ""
	}
	if language == "go" && goModule != "" {
		if dir == "" {
			return goModule
		}
		return goModule + "/" + dir
	}
	return dir
}

func (state *v2BuildState) parseGo(record *v2FileRecord) {
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, record.path, record.body, parser.SkipObjectResolution)
	if err != nil {
		state.diagnostics = append(state.diagnostics, V2Diagnostic{Path: record.path, Adapter: "go", Message: err.Error()})
		return
	}
	record.goFile, record.fset = parsed, fset
	for _, declaration := range parsed.Decls {
		switch typed := declaration.(type) {
		case *ast.FuncDecl:
			kind, metadata := "function", ""
			if typed.Recv != nil {
				kind = "method"
				metadata = goReceiver(typed.Recv)
			}
			state.addSymbol(record, typed.Name.Name, kind, typed.Pos(), typed.End(), ast.IsExported(typed.Name.Name), metadata)
		case *ast.GenDecl:
			for _, specification := range typed.Specs {
				switch value := specification.(type) {
				case *ast.TypeSpec:
					kind := "type"
					switch value.Type.(type) {
					case *ast.InterfaceType:
						kind = "interface"
					case *ast.StructType:
						kind = "struct"
					}
					state.addSymbol(record, value.Name.Name, kind, value.Pos(), value.End(), ast.IsExported(value.Name.Name), "")
				case *ast.ValueSpec:
					kind := "variable"
					if typed.Tok == token.CONST {
						kind = "constant"
					}
					for _, name := range value.Names {
						state.addSymbol(record, name.Name, kind, name.Pos(), name.End(), ast.IsExported(name.Name), "")
					}
				}
			}
		}
	}
}

func (state *v2BuildState) addSymbol(record *v2FileRecord, name, kind string, start, end token.Pos, exported bool, metadata string) {
	startPosition, endPosition := record.fset.Position(start), record.fset.Position(end)
	state.symbols = append(state.symbols, v2SymbolDraft{fileID: record.id, filePath: record.path, module: record.module, name: name, kind: kind, startLine: startPosition.Line, startColumn: startPosition.Column, endLine: endPosition.Line, endColumn: endPosition.Column, exported: exported, metadata: metadata})
}

var tsDeclaration = regexp.MustCompile(`(?m)(?:^|[;{}]\s*)(?:export\s+)?(?:default\s+)?(?:async\s+)?(function|class|interface|type|enum|const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)`)

func (state *v2BuildState) parseTypeScript(record *v2FileRecord) {
	for _, match := range tsDeclaration.FindAllSubmatchIndex(record.body, -1) {
		kind := string(record.body[match[2]:match[3]])
		name := string(record.body[match[4]:match[5]])
		line, column := byteLineColumn(record.body, match[4])
		state.symbols = append(state.symbols, v2SymbolDraft{fileID: record.id, filePath: record.path, module: record.module, name: name, kind: kind, startLine: line, startColumn: column, endLine: line, endColumn: column + len(name), exported: ast.IsExported(name) || bytesBeforeContainsExport(record.body, match[0], match[4])})
	}
}

func (state *v2BuildState) insertSymbols() error {
	transaction, err := state.db.Begin()
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	statement, err := transaction.Prepare("INSERT INTO symbols(file_id,name,kind,start_line,start_col,end_line,end_col,exported,adapter_data) VALUES(?,?,?,?,?,?,?,?,?)")
	if err != nil {
		return err
	}
	defer statement.Close()
	for index := range state.symbols {
		symbol := &state.symbols[index]
		result, err := statement.Exec(symbol.fileID, symbol.name, symbol.kind, symbol.startLine, symbol.startColumn, symbol.endLine, symbol.endColumn, boolInt(symbol.exported), symbol.metadata)
		if err != nil {
			return err
		}
		symbol.id, err = result.LastInsertId()
		if err != nil {
			return err
		}
		state.byName[symbol.name] = append(state.byName[symbol.name], symbol)
		state.byFileName[symbol.filePath+"\x00"+symbol.name] = append(state.byFileName[symbol.filePath+"\x00"+symbol.name], symbol)
		state.byModuleName[symbol.module+"\x00"+symbol.name] = append(state.byModuleName[symbol.module+"\x00"+symbol.name], symbol)
	}
	return transaction.Commit()
}

func (state *v2BuildState) insertRelations(absRepo, goModule string) error {
	transaction, err := state.db.Begin()
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	statement, err := transaction.Prepare("INSERT INTO edges(from_file_id,from_symbol_id,to_file_id,to_symbol_id,unresolved_target,kind,line,column,confidence,adapter) VALUES(?,?,?,?,?,?,?,?,?,?)")
	if err != nil {
		return err
	}
	defer statement.Close()
	for index := range state.symbols {
		symbol := &state.symbols[index]
		if err := state.insertEdge(statement, symbol.fileID, nil, symbol.fileID, &symbol.id, "", "defines", symbol.startLine, symbol.startColumn, 1, "index"); err != nil {
			return err
		}
	}
	allPaths := make([]string, 0, len(state.files))
	packageFiles := map[string][]string{}
	for _, file := range state.files {
		allPaths = append(allPaths, file.path)
		if file.language == "go" {
			packageFiles[file.module] = append(packageFiles[file.module], file.path)
			dir := filepath.ToSlash(filepath.Dir(file.path))
			if dir == "." {
				dir = ""
			}
			packageFiles[dir] = append(packageFiles[dir], file.path)
		}
	}
	for index := range state.files {
		record := &state.files[index]
		var imports []string
		switch record.language {
		case "go":
			imports = extractGoImports(string(record.body))
		case "typescript", "javascript":
			imports = extractTSImports(string(record.body))
		}
		for _, imported := range imports {
			targets := resolveImport(absRepo, record.path, record.language, imported, goModule, absRepo, packageFiles, allPaths)
			if len(targets) == 0 {
				if err := state.insertEdge(statement, record.id, nil, 0, nil, imported, "imports", 1, 1, .25, record.language); err != nil {
					return err
				}
				continue
			}
			for _, target := range targets {
				targetFile := state.fileByPath[target]
				if targetFile == nil {
					for _, candidate := range state.files {
						if filepath.ToSlash(filepath.Dir(candidate.path)) == target {
							targetFile = state.fileByPath[candidate.path]
							break
						}
					}
				}
				if targetFile != nil {
					if err := state.insertEdge(statement, record.id, nil, targetFile.id, nil, "", "imports", 1, 1, .9, record.language); err != nil {
						return err
					}
				}
			}
		}
		if record.goFile != nil {
			if err := state.insertGoRelations(statement, record); err != nil {
				return err
			}
		} else if record.language == "typescript" || record.language == "javascript" {
			if err := state.insertTSRelations(statement, record); err != nil {
				return err
			}
		}
	}
	return transaction.Commit()
}

func (state *v2BuildState) insertGoRelations(statement *sql.Stmt, record *v2FileRecord) error {
	var relationErr error
	ast.Inspect(record.goFile, func(node ast.Node) bool {
		if node == nil || relationErr != nil {
			return true
		}
		position := record.fset.Position(node.Pos())
		from := state.enclosingSymbol(record.path, position.Line, position.Column)
		switch typed := node.(type) {
		case *ast.CallExpr:
			name := goExpressionName(typed.Fun)
			if name == "" {
				return true
			}
			target := state.resolveSymbol(record, name)
			relationErr = state.insertResolvedEdge(statement, record, from, target, name, "calls", position.Line, position.Column, "go")
		case *ast.Ident:
			if isGoDeclarationIdentifier(record.goFile, typed) {
				return true
			}
			target := state.resolveSymbol(record, typed.Name)
			if target != nil {
				relationErr = state.insertResolvedEdge(statement, record, from, target, typed.Name, "references", position.Line, position.Column, "go")
			}
		}
		return true
	})
	return relationErr
}

var tsCall = regexp.MustCompile(`\b([A-Za-z_$][A-Za-z0-9_$]*)\s*\(`)
var tsIdentifier = regexp.MustCompile(`\b[A-Za-z_$][A-Za-z0-9_$]*\b`)

func (state *v2BuildState) insertTSRelations(statement *sql.Stmt, record *v2FileRecord) error {
	for _, match := range tsCall.FindAllSubmatchIndex(record.body, -1) {
		name := string(record.body[match[2]:match[3]])
		line, column := byteLineColumn(record.body, match[2])
		from := state.enclosingSymbol(record.path, line, column)
		target := state.resolveSymbol(record, name)
		if err := state.insertResolvedEdge(statement, record, from, target, name, "calls", line, column, "typescript"); err != nil {
			return err
		}
	}
	for _, match := range tsIdentifier.FindAllIndex(record.body, -1) {
		name := string(record.body[match[0]:match[1]])
		target := state.resolveSymbol(record, name)
		if target == nil || target.filePath == record.path && target.startColumn == match[0] {
			continue
		}
		line, column := byteLineColumn(record.body, match[0])
		from := state.enclosingSymbol(record.path, line, column)
		if err := state.insertResolvedEdge(statement, record, from, target, name, "references", line, column, "typescript"); err != nil {
			return err
		}
	}
	return nil
}

func (state *v2BuildState) insertResolvedEdge(statement *sql.Stmt, record *v2FileRecord, from, target *v2SymbolDraft, unresolved, kind string, line, column int, adapter string) error {
	var fromID, toID *int64
	toFileID := int64(0)
	confidence := .45
	if from != nil {
		fromID = &from.id
	}
	if target != nil {
		toID, toFileID, unresolved, confidence = &target.id, target.fileID, "", .8
	}
	return state.insertEdge(statement, record.id, fromID, toFileID, toID, unresolved, kind, line, column, confidence, adapter)
}

func (state *v2BuildState) insertEdge(statement *sql.Stmt, fromFile int64, fromSymbol *int64, toFile int64, toSymbol *int64, unresolved, kind string, line, column int, confidence float64, adapter string) error {
	var toFileValue any
	if toFile > 0 {
		toFileValue = toFile
	}
	if unresolved == "" {
		unresolved = ""
	}
	if _, err := statement.Exec(fromFile, fromSymbol, toFileValue, toSymbol, nullableString(unresolved), kind, line, column, confidence, adapter); err != nil {
		return err
	}
	state.edges++
	return nil
}

func (state *v2BuildState) insertTestLinks() error {
	transaction, err := state.db.Begin()
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	statement, err := transaction.Prepare("INSERT INTO test_links(source_file_id,test_file_id,confidence,reason) VALUES(?,?,?,?)")
	if err != nil {
		return err
	}
	defer statement.Close()
	for index := range state.files {
		test := &state.files[index]
		candidates := productionCandidates(test.path)
		for _, candidate := range candidates {
			source := state.fileByPath[candidate]
			if source == nil {
				continue
			}
			if _, err := statement.Exec(source.id, test.id, .9, "filename convention"); err != nil {
				return err
			}
			state.testLinks++
			break
		}
	}
	return transaction.Commit()
}

func (state *v2BuildState) resolveSymbol(record *v2FileRecord, name string) *v2SymbolDraft {
	if symbols := state.byFileName[record.path+"\x00"+name]; len(symbols) == 1 {
		return symbols[0]
	}
	if symbols := state.byModuleName[record.module+"\x00"+name]; len(symbols) == 1 {
		return symbols[0]
	}
	if symbols := state.byName[name]; len(symbols) == 1 {
		return symbols[0]
	}
	return nil
}

func (state *v2BuildState) enclosingSymbol(path string, line, column int) *v2SymbolDraft {
	var best *v2SymbolDraft
	for _, symbol := range state.symbols {
		if symbol.filePath != path || line < symbol.startLine || line > symbol.endLine {
			continue
		}
		if line == symbol.startLine && column < symbol.startColumn || line == symbol.endLine && column > symbol.endColumn {
			continue
		}
		if best == nil || symbol.endLine-symbol.startLine < best.endLine-best.startLine {
			copy := symbol
			best = &copy
		}
	}
	return best
}

func publishV2Directory(temporary, dir string) error {
	previous := dir + ".previous"
	_ = os.RemoveAll(previous)
	if _, err := os.Stat(dir); err == nil {
		if err := os.Rename(dir, previous); err != nil {
			return err
		}
	}
	if err := os.Rename(temporary, dir); err != nil {
		_ = os.Rename(previous, dir)
		return err
	}
	if err := os.RemoveAll(previous); err != nil {
		return err
	}
	parent, err := os.Open(filepath.Dir(dir))
	if err != nil {
		return err
	}
	err = parent.Sync()
	_ = parent.Close()
	return err
}

func recoverV2Publication(dir string) error {
	previous := dir + ".previous"
	if _, err := os.Stat(dir); err == nil {
		return os.RemoveAll(previous)
	}
	if _, err := os.Stat(previous); err == nil {
		return os.Rename(previous, dir)
	}
	return nil
}

func goReceiver(fields *ast.FieldList) string {
	if fields == nil || len(fields.List) == 0 {
		return ""
	}
	return goExpressionName(fields.List[0].Type)
}

func goExpressionName(expression ast.Expr) string {
	switch value := expression.(type) {
	case *ast.Ident:
		return value.Name
	case *ast.SelectorExpr:
		return value.Sel.Name
	case *ast.StarExpr:
		return goExpressionName(value.X)
	case *ast.IndexExpr:
		return goExpressionName(value.X)
	case *ast.IndexListExpr:
		return goExpressionName(value.X)
	default:
		return ""
	}
}

func isGoDeclarationIdentifier(file *ast.File, identifier *ast.Ident) bool {
	for _, declaration := range file.Decls {
		switch value := declaration.(type) {
		case *ast.FuncDecl:
			if value.Name == identifier {
				return true
			}
		case *ast.GenDecl:
			for _, specification := range value.Specs {
				switch typed := specification.(type) {
				case *ast.TypeSpec:
					if typed.Name == identifier {
						return true
					}
				case *ast.ValueSpec:
					for _, name := range typed.Names {
						if name == identifier {
							return true
						}
					}
				}
			}
		}
	}
	return false
}

func byteLineColumn(body []byte, offset int) (line, column int) {
	line, column = 1, 1
	for index, char := range body {
		if index >= offset {
			break
		}
		if char == '\n' {
			line, column = line+1, 1
		} else {
			column++
		}
	}
	return line, column
}

func bytesBeforeContainsExport(body []byte, start, end int) bool {
	if start < 0 || end > len(body) || start > end {
		return false
	}
	return strings.Contains(string(body[start:end]), "export")
}

func productionCandidates(path string) []string {
	extension := filepath.Ext(path)
	base := strings.TrimSuffix(path, extension)
	switch {
	case extension == ".go" && strings.HasSuffix(base, "_test"):
		return []string{strings.TrimSuffix(base, "_test") + extension}
	case strings.HasSuffix(base, ".test"):
		return []string{strings.TrimSuffix(base, ".test") + extension}
	case strings.HasSuffix(base, ".spec"):
		return []string{strings.TrimSuffix(base, ".spec") + extension}
	default:
		return nil
	}
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}
