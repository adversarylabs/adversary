package repoindex

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const (
	V2SchemaVersion   = "v2"
	V2AdapterRevision = "go-ast-v1+ts-syntax-v1"
	EnvRepoGraph      = "ADVERSARY_REPO_GRAPH"
	v2DatabaseFile    = "graph.sqlite"
	v2MetaFile        = "meta.json"
)

type V2Meta struct {
	SchemaVersion   string         `json:"schemaVersion"`
	AdapterRevision string         `json:"adapterRevision"`
	Fingerprint     string         `json:"fingerprint"`
	RepoPath        string         `json:"repoPath"`
	BuiltAt         time.Time      `json:"builtAt"`
	DurationMS      int64          `json:"durationMs"`
	FileCount       int            `json:"fileCount"`
	SymbolCount     int            `json:"symbolCount"`
	EdgeCount       int            `json:"edgeCount"`
	TestLinkCount   int            `json:"testLinkCount"`
	ParseFailures   []V2Diagnostic `json:"parseFailures,omitempty"`
	Rebuilt         bool           `json:"-"`
}

type V2Diagnostic struct {
	Path    string `json:"path"`
	Adapter string `json:"adapter"`
	Message string `json:"message"`
}

type V2Handle struct {
	Dir  string
	Meta V2Meta
}

type V2File struct {
	ID       int64  `json:"id"`
	Path     string `json:"path"`
	Language string `json:"language"`
	Size     int64  `json:"size"`
	Hash     string `json:"hash"`
	Module   string `json:"module,omitempty"`
}

type V2Symbol struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	Path        string `json:"path"`
	StartLine   int    `json:"startLine"`
	StartColumn int    `json:"startColumn"`
	EndLine     int    `json:"endLine"`
	EndColumn   int    `json:"endColumn"`
	ContainerID *int64 `json:"containerId,omitempty"`
	Exported    bool   `json:"exported"`
	Language    string `json:"language"`
	Metadata    string `json:"metadata,omitempty"`
}

type V2Edge struct {
	ID               int64   `json:"id"`
	FromPath         string  `json:"fromPath"`
	FromSymbolID     *int64  `json:"fromSymbolId,omitempty"`
	ToPath           string  `json:"toPath,omitempty"`
	ToSymbolID       *int64  `json:"toSymbolId,omitempty"`
	UnresolvedTarget string  `json:"unresolvedTarget,omitempty"`
	Kind             string  `json:"kind"`
	Line             int     `json:"line"`
	Column           int     `json:"column"`
	Confidence       float64 `json:"confidence"`
	Adapter          string  `json:"adapter"`
}

type V2TestLink struct {
	SourcePath     string  `json:"sourcePath"`
	SourceSymbolID *int64  `json:"sourceSymbolId,omitempty"`
	TestPath       string  `json:"testPath"`
	TestSymbolID   *int64  `json:"testSymbolId,omitempty"`
	Confidence     float64 `json:"confidence"`
	Reason         string  `json:"reason"`
}

type V2Page[T any] struct {
	Items      []T    `json:"items"`
	NextCursor string `json:"nextCursor,omitempty"`
}

type V2FileQuery struct {
	Language string
	Glob     string
	Cursor   string
	Limit    int
}

type V2SymbolQuery struct {
	Path   string
	Name   string
	Kind   string
	Cursor string
	Limit  int
}

type V2RelationQuery struct {
	SymbolID int64
	Cursor   string
	Limit    int
}

type V2Graph struct {
	dir  string
	db   *sql.DB
	meta V2Meta
}

func OpenV2(dir string) (*V2Graph, error) {
	meta, ok := loadV2Meta(filepath.Join(dir, v2MetaFile))
	if !ok || meta.SchemaVersion != V2SchemaVersion || meta.AdapterRevision != V2AdapterRevision {
		return nil, fmt.Errorf("repo-graph: missing or unsupported metadata in %s", dir)
	}
	databasePath := filepath.Join(dir, v2DatabaseFile)
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(databasePath)+"?mode=ro&immutable=1")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &V2Graph{dir: dir, db: db, meta: meta}, nil
}

func (g *V2Graph) Close() error { return g.db.Close() }
func (g *V2Graph) Meta() V2Meta { return g.meta }

func (g *V2Graph) Files(query V2FileQuery) (V2Page[V2File], error) {
	limit, cursor, err := v2Bounds(query.Limit, query.Cursor)
	if err != nil {
		return V2Page[V2File]{}, err
	}
	pattern := ""
	if query.Glob != "" {
		if err := validV2PathPattern(query.Glob); err != nil {
			return V2Page[V2File]{}, err
		}
		pattern = globToLike(query.Glob)
	}
	rows, err := g.db.Query(`SELECT id,path,language,size,hash,module FROM files
WHERE id > ? AND (? = '' OR language = ?) AND (? = '' OR path LIKE ? ESCAPE '\')
ORDER BY id LIMIT ?`, cursor, query.Language, query.Language, pattern, pattern, limit+1)
	if err != nil {
		return V2Page[V2File]{}, err
	}
	defer rows.Close()
	var items []V2File
	for rows.Next() {
		var item V2File
		if err := rows.Scan(&item.ID, &item.Path, &item.Language, &item.Size, &item.Hash, &item.Module); err != nil {
			return V2Page[V2File]{}, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return V2Page[V2File]{}, err
	}
	return v2Page(items, limit, func(item V2File) int64 { return item.ID }), nil
}

func (g *V2Graph) SymbolAt(path string, line, column int) (*V2Symbol, error) {
	if err := validV2Path(path); err != nil {
		return nil, err
	}
	if line < 1 || column < 0 {
		return nil, errors.New("line must be positive and column non-negative")
	}
	row := g.db.QueryRow(`SELECT s.id,s.name,s.kind,f.path,s.start_line,s.start_col,s.end_line,s.end_col,s.container_id,s.exported,f.language,s.adapter_data
FROM symbols s JOIN files f ON f.id=s.file_id
WHERE f.path=? AND (s.start_line < ? OR (s.start_line=? AND s.start_col<=?))
AND (s.end_line > ? OR (s.end_line=? AND s.end_col>=?))
ORDER BY (s.end_line-s.start_line) ASC, s.id ASC LIMIT 1`, filepath.ToSlash(path), line, line, column, line, line, column)
	item, err := scanV2Symbol(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return item, err
}

func (g *V2Graph) Symbols(query V2SymbolQuery) (V2Page[V2Symbol], error) {
	limit, cursor, err := v2Bounds(query.Limit, query.Cursor)
	if err != nil {
		return V2Page[V2Symbol]{}, err
	}
	if query.Path != "" {
		if err := validV2Path(query.Path); err != nil {
			return V2Page[V2Symbol]{}, err
		}
	}
	rows, err := g.db.Query(`SELECT s.id,s.name,s.kind,f.path,s.start_line,s.start_col,s.end_line,s.end_col,s.container_id,s.exported,f.language,s.adapter_data
FROM symbols s JOIN files f ON f.id=s.file_id
WHERE s.id>? AND (?='' OR f.path=?) AND (?='' OR s.name=?) AND (?='' OR s.kind=?)
ORDER BY s.id LIMIT ?`, cursor, query.Path, filepath.ToSlash(query.Path), query.Name, query.Name, query.Kind, query.Kind, limit+1)
	if err != nil {
		return V2Page[V2Symbol]{}, err
	}
	defer rows.Close()
	var items []V2Symbol
	for rows.Next() {
		item, err := scanV2Symbol(rows)
		if err != nil {
			return V2Page[V2Symbol]{}, err
		}
		items = append(items, *item)
	}
	if err := rows.Err(); err != nil {
		return V2Page[V2Symbol]{}, err
	}
	return v2Page(items, limit, func(item V2Symbol) int64 { return item.ID }), nil
}

func (g *V2Graph) Definitions(name, path, cursor string, limit int) (V2Page[V2Symbol], error) {
	return g.Symbols(V2SymbolQuery{Name: name, Path: path, Cursor: cursor, Limit: limit})
}

func (g *V2Graph) References(query V2RelationQuery) (V2Page[V2Edge], error) {
	return g.relations(query, "references", false)
}

func (g *V2Graph) Callers(query V2RelationQuery) (V2Page[V2Edge], error) {
	return g.relations(query, "calls", false)
}

func (g *V2Graph) Callees(query V2RelationQuery) (V2Page[V2Edge], error) {
	return g.relations(query, "calls", true)
}

func (g *V2Graph) Implementations(query V2RelationQuery) (V2Page[V2Edge], error) {
	return g.relations(query, "implements", false)
}

func (g *V2Graph) relations(query V2RelationQuery, kind string, outgoing bool) (V2Page[V2Edge], error) {
	if query.SymbolID < 1 {
		return V2Page[V2Edge]{}, errors.New("symbol id must be positive")
	}
	limit, cursor, err := v2Bounds(query.Limit, query.Cursor)
	if err != nil {
		return V2Page[V2Edge]{}, err
	}
	column, argument := "to_symbol_id", query.SymbolID
	if outgoing {
		column = "from_symbol_id"
	}
	statement := fmt.Sprintf(`SELECT e.id,ff.path,e.from_symbol_id,COALESCE(tf.path,''),e.to_symbol_id,COALESCE(e.unresolved_target,''),e.kind,e.line,e.column,e.confidence,e.adapter
FROM edges e JOIN files ff ON ff.id=e.from_file_id LEFT JOIN files tf ON tf.id=e.to_file_id
WHERE e.id>? AND e.kind=? AND e.%s=? ORDER BY e.id LIMIT ?`, column)
	rows, err := g.db.Query(statement, cursor, kind, argument, limit+1)
	if err != nil {
		return V2Page[V2Edge]{}, err
	}
	defer rows.Close()
	var items []V2Edge
	for rows.Next() {
		var item V2Edge
		if err := rows.Scan(&item.ID, &item.FromPath, &item.FromSymbolID, &item.ToPath, &item.ToSymbolID, &item.UnresolvedTarget, &item.Kind, &item.Line, &item.Column, &item.Confidence, &item.Adapter); err != nil {
			return V2Page[V2Edge]{}, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return V2Page[V2Edge]{}, err
	}
	return v2Page(items, limit, func(item V2Edge) int64 { return item.ID }), nil
}

func (g *V2Graph) ImportsOf(path string, cursor string, limit int) (V2Page[V2Edge], error) {
	return g.fileRelations(path, cursor, limit, true)
}

func (g *V2Graph) ImportersOf(path string, cursor string, limit int) (V2Page[V2Edge], error) {
	return g.fileRelations(path, cursor, limit, false)
}

func (g *V2Graph) fileRelations(path, cursor string, limit int, outgoing bool) (V2Page[V2Edge], error) {
	if err := validV2Path(path); err != nil {
		return V2Page[V2Edge]{}, err
	}
	limit, cursorID, err := v2Bounds(limit, cursor)
	if err != nil {
		return V2Page[V2Edge]{}, err
	}
	condition := "ff.path=?"
	if !outgoing {
		condition = "tf.module=(SELECT module FROM files WHERE path=?)"
	}
	statement := fmt.Sprintf(`SELECT e.id,ff.path,e.from_symbol_id,COALESCE(tf.path,''),e.to_symbol_id,COALESCE(e.unresolved_target,''),e.kind,e.line,e.column,e.confidence,e.adapter
FROM edges e JOIN files ff ON ff.id=e.from_file_id LEFT JOIN files tf ON tf.id=e.to_file_id
WHERE e.id>? AND e.kind='imports' AND %s ORDER BY e.id LIMIT ?`, condition)
	rows, err := g.db.Query(statement, cursorID, filepath.ToSlash(path), limit+1)
	if err != nil {
		return V2Page[V2Edge]{}, err
	}
	defer rows.Close()
	var items []V2Edge
	for rows.Next() {
		var item V2Edge
		if err := rows.Scan(&item.ID, &item.FromPath, &item.FromSymbolID, &item.ToPath, &item.ToSymbolID, &item.UnresolvedTarget, &item.Kind, &item.Line, &item.Column, &item.Confidence, &item.Adapter); err != nil {
			return V2Page[V2Edge]{}, err
		}
		items = append(items, item)
	}
	return v2Page(items, limit, func(item V2Edge) int64 { return item.ID }), rows.Err()
}

func (g *V2Graph) RelatedTests(path string, symbolID int64, cursor string, limit int) (V2Page[V2TestLink], error) {
	if path != "" {
		if err := validV2Path(path); err != nil {
			return V2Page[V2TestLink]{}, err
		}
	}
	limit, cursorID, err := v2Bounds(limit, cursor)
	if err != nil {
		return V2Page[V2TestLink]{}, err
	}
	rows, err := g.db.Query(`SELECT tl.id,sf.path,tl.source_symbol_id,tf.path,tl.test_symbol_id,tl.confidence,tl.reason
FROM test_links tl JOIN files sf ON sf.id=tl.source_file_id JOIN files tf ON tf.id=tl.test_file_id
WHERE tl.id>? AND (?='' OR sf.path=?)
AND (?=0 OR tl.source_symbol_id=? OR sf.id=(SELECT file_id FROM symbols WHERE id=?))
ORDER BY tl.id LIMIT ?`, cursorID, path, filepath.ToSlash(path), symbolID, symbolID, symbolID, limit+1)
	if err != nil {
		return V2Page[V2TestLink]{}, err
	}
	defer rows.Close()
	type itemWithID struct {
		id int64
		V2TestLink
	}
	var raw []itemWithID
	for rows.Next() {
		var item itemWithID
		if err := rows.Scan(&item.id, &item.SourcePath, &item.SourceSymbolID, &item.TestPath, &item.TestSymbolID, &item.Confidence, &item.Reason); err != nil {
			return V2Page[V2TestLink]{}, err
		}
		raw = append(raw, item)
	}
	if err := rows.Err(); err != nil {
		return V2Page[V2TestLink]{}, err
	}
	page := V2Page[V2TestLink]{}
	if len(raw) > limit {
		page.NextCursor = strconv.FormatInt(raw[limit-1].id, 10)
		raw = raw[:limit]
	}
	for _, item := range raw {
		page.Items = append(page.Items, item.V2TestLink)
	}
	return page, nil
}

type v2Scanner interface{ Scan(...any) error }

func scanV2Symbol(scanner v2Scanner) (*V2Symbol, error) {
	var item V2Symbol
	var exported int
	if err := scanner.Scan(&item.ID, &item.Name, &item.Kind, &item.Path, &item.StartLine, &item.StartColumn, &item.EndLine, &item.EndColumn, &item.ContainerID, &exported, &item.Language, &item.Metadata); err != nil {
		return nil, err
	}
	item.Exported = exported != 0
	return &item, nil
}

func v2Bounds(limit int, cursor string) (int, int64, error) {
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		return 0, 0, errors.New("limit cannot exceed 500")
	}
	if cursor == "" {
		return limit, 0, nil
	}
	value, err := strconv.ParseInt(cursor, 10, 64)
	if err != nil || value < 0 {
		return 0, 0, errors.New("cursor must be a non-negative integer")
	}
	return limit, value, nil
}

func v2Page[T any](items []T, limit int, id func(T) int64) V2Page[T] {
	page := V2Page[T]{}
	if len(items) > limit {
		page.NextCursor = strconv.FormatInt(id(items[limit-1]), 10)
		items = items[:limit]
	}
	page.Items = items
	return page
}

func validV2Path(path string) error {
	path = filepath.ToSlash(path)
	if path == "" || filepath.IsAbs(path) || filepath.Clean(path) != filepath.FromSlash(path) || path == ".." || strings.HasPrefix(path, "../") || strings.ContainsRune(path, '\x00') {
		return errors.New("path must be normalized and repository-relative")
	}
	return nil
}

func validV2PathPattern(pattern string) error {
	if strings.Contains(pattern, "..") || filepath.IsAbs(pattern) || strings.ContainsRune(pattern, '\x00') {
		return errors.New("glob must be repository-relative")
	}
	return nil
}

func globToLike(pattern string) string {
	var builder strings.Builder
	for _, char := range filepath.ToSlash(pattern) {
		switch char {
		case '%', '_', '\\':
			builder.WriteRune('\\')
			builder.WriteRune(char)
		case '*':
			builder.WriteRune('%')
		case '?':
			builder.WriteRune('_')
		default:
			builder.WriteRune(char)
		}
	}
	return builder.String()
}

func loadV2Meta(path string) (V2Meta, bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return V2Meta{}, false
	}
	var meta V2Meta
	if err := jsonUnmarshalStrict(raw, &meta); err != nil {
		return V2Meta{}, false
	}
	return meta, true
}

func jsonUnmarshalStrict(raw []byte, target any) error {
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("multiple JSON values are not allowed")
	}
	return nil
}
