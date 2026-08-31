// Package repoindex builds and loads a local filesystem index of a target
// repository for adversary navigation (file inventory + import edges).
package repoindex

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	internalpaths "github.com/adversarylabs/adversary/internal/paths"
)

const (
	// SchemaVersion is the on-disk format version.
	SchemaVersion = "v1"
	// EnvRepoIndex is injected into adversary child processes.
	EnvRepoIndex = "ADVERSARY_REPO_INDEX"
	metaFile     = "meta.json"
	filesFile    = "files.jsonl"
	edgesFile    = "edges.jsonl"
)

// Mode controls ensure behavior.
type Mode string

const (
	ModeAuto       Mode = "auto"
	ModeOff        Mode = "off"
	ModeForce      Mode = "force"
	ModeGraph      Mode = "graph"
	ModeGraphForce Mode = "graph-force"
)

// ParseMode parses CLI mode strings.
func ParseMode(s string) (Mode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "auto":
		return ModeAuto, nil
	case "off", "false", "0":
		return ModeOff, nil
	case "force", "rebuild":
		return ModeForce, nil
	case "graph", "v2":
		return ModeGraph, nil
	case "graph-force", "v2-force":
		return ModeGraphForce, nil
	default:
		return "", fmt.Errorf("repo-index mode must be auto, off, force, graph, or graph-force (got %q)", s)
	}
}

// Meta is persisted as meta.json.
type Meta struct {
	SchemaVersion string    `json:"schemaVersion"`
	Fingerprint   string    `json:"fingerprint"`
	RepoPath      string    `json:"repoPath"`
	BuiltAt       time.Time `json:"builtAt"`
	FileCount     int       `json:"fileCount"`
	EdgeCount     int       `json:"edgeCount"`
	Rebuilt       bool      `json:"-"` // not persisted; set on Ensure result
}

// FileEntry is one line of files.jsonl.
type FileEntry struct {
	Path     string `json:"path"`
	Language string `json:"language"`
	Size     int64  `json:"size"`
	Hash     string `json:"hash"`
}

// Edge is one line of edges.jsonl: from file path → to file or package path.
type Edge struct {
	From string `json:"from"`
	To   string `json:"to"`
	Kind string `json:"kind"` // "import"
}

// Handle is a loaded index directory.
type Handle struct {
	Dir  string
	Meta Meta
}

// CacheRoot returns the default root for repo indexes.
func CacheRoot() (string, error) {
	if override := strings.TrimSpace(os.Getenv("ADVERSARY_REPO_INDEX_DIR")); override != "" {
		abs, err := filepath.Abs(override)
		if err != nil {
			return "", err
		}
		return filepath.Clean(abs), nil
	}
	base, err := internalpaths.CacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "repo-index"), nil
}

// RepoKey hashes the absolute repo path into a stable directory name.
func RepoKey(absRepo string) string {
	sum := sha256.Sum256([]byte(filepath.Clean(absRepo)))
	return hex.EncodeToString(sum[:16])
}

// Fingerprint computes the invalidation key for a worktree.
//
// For git repos: HEAD + staged tree identity + porcelain status, plus the
// **content hash** of every dirty or untracked indexable path (so two different
// edits to the same path do not collide). For non-git: content hash of all
// indexable files.
func Fingerprint(absRepo string) (string, error) {
	absRepo = filepath.Clean(absRepo)
	h := sha256.New()
	_, _ = io.WriteString(h, SchemaVersion+"\n")
	_, _ = io.WriteString(h, absRepo+"\n")

	if isGitRepo(absRepo) {
		head, err := gitOutput(absRepo, "rev-parse", "HEAD")
		if err != nil {
			// unborn or corrupt — still fingerprint dirtiness
			head = "NOHEAD"
		}
		_, _ = io.WriteString(h, strings.TrimSpace(head)+"\n")
		// Tracked tree as indexed in the object store (clean commit identity)
		ls, err := gitOutput(absRepo, "ls-files", "-z", "--stage")
		if err == nil {
			_, _ = io.WriteString(h, ls)
		}
		status, err := gitOutput(absRepo, "status", "--porcelain=v1", "-uall", "--", ".")
		if err != nil {
			return "", fmt.Errorf("git status: %w", err)
		}
		_, _ = io.WriteString(h, status)
		// Content identity of dirty/untracked paths — porcelain alone is not enough
		// (two different edits to the same path share the same status line).
		for _, rel := range dirtyIndexablePaths(status) {
			if err := writeFileContentFingerprint(h, absRepo, rel); err != nil {
				// Missing path (deleted) still contributes a stable marker.
				fmt.Fprintf(h, "missing\t%s\n", rel)
			}
		}
	} else {
		entries, err := listIndexableFiles(absRepo)
		if err != nil {
			return "", err
		}
		for _, rel := range entries {
			if err := writeFileContentFingerprint(h, absRepo, rel); err != nil {
				continue
			}
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func writeFileContentFingerprint(h io.Writer, absRepo, rel string) error {
	body, err := os.ReadFile(filepath.Join(absRepo, rel))
	if err != nil {
		return err
	}
	sum := sha256.Sum256(body)
	_, err = fmt.Fprintf(h, "%s\t%s\n", filepath.ToSlash(rel), hex.EncodeToString(sum[:]))
	return err
}

// dirtyIndexablePaths extracts worktree paths from git status --porcelain=v1
// that may have content not represented by ls-files --stage alone.
func dirtyIndexablePaths(porcelain string) []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(p string) {
		p = strings.TrimSpace(p)
		p = strings.Trim(p, "\"")
		p = filepath.ToSlash(p)
		if p == "" || languageOf(p) == "" {
			return
		}
		if _, ok := seen[p]; ok {
			return
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	for _, line := range strings.Split(porcelain, "\n") {
		if len(line) < 4 {
			continue
		}
		// XY<space>path  or  XY<space>orig -> path (rename)
		rest := line[3:]
		if i := strings.Index(rest, " -> "); i >= 0 {
			add(rest[:i])
			add(rest[i+4:])
			continue
		}
		add(rest)
	}
	sort.Strings(out)
	return out
}

// Ensure builds or loads the index for absRepo according to mode.
// When mode is Off, returns nil handle and nil error.
func Ensure(absRepo string, mode Mode, stderr io.Writer) (*Handle, error) {
	if mode == ModeOff {
		return nil, nil
	}
	absRepo, err := filepath.Abs(absRepo)
	if err != nil {
		return nil, err
	}
	absRepo = filepath.Clean(absRepo)
	info, err := os.Stat(absRepo)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("repo path is not a directory: %s", absRepo)
	}

	fp, err := Fingerprint(absRepo)
	if err != nil {
		return nil, fmt.Errorf("fingerprint: %w", err)
	}

	root, err := CacheRoot()
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(root, SchemaVersion, RepoKey(absRepo))
	metaPath := filepath.Join(dir, metaFile)

	if mode != ModeForce {
		if meta, ok := loadMeta(metaPath); ok && meta.SchemaVersion == SchemaVersion && meta.Fingerprint == fp {
			if filesExist(dir) {
				if stderr != nil {
					fmt.Fprintf(stderr, "repo-index: cache hit %s\n", dir)
				}
				return &Handle{Dir: dir, Meta: meta}, nil
			}
		}
	}

	if stderr != nil {
		fmt.Fprintf(stderr, "repo-index: building %s\n", absRepo)
	}
	meta, err := Build(absRepo, dir, fp)
	if err != nil {
		return nil, err
	}
	meta.Rebuilt = true
	if stderr != nil {
		fmt.Fprintf(stderr, "repo-index: wrote %d files, %d edges → %s\n", meta.FileCount, meta.EdgeCount, dir)
	}
	return &Handle{Dir: dir, Meta: meta}, nil
}

func filesExist(dir string) bool {
	for _, name := range []string{metaFile, filesFile, edgesFile} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			return false
		}
	}
	return true
}

func loadMeta(path string) (Meta, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Meta{}, false
	}
	var m Meta
	if err := json.Unmarshal(data, &m); err != nil {
		return Meta{}, false
	}
	return m, true
}

// Build walks absRepo and writes a complete index under dir.
func Build(absRepo, dir, fingerprint string) (Meta, error) {
	if err := os.RemoveAll(dir); err != nil {
		return Meta{}, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return Meta{}, err
	}

	rels, err := listIndexableFiles(absRepo)
	if err != nil {
		return Meta{}, err
	}

	filesPath := filepath.Join(dir, filesFile)
	edgesPath := filepath.Join(dir, edgesFile)
	ff, err := os.OpenFile(filesPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return Meta{}, err
	}
	defer ff.Close()
	ef, err := os.OpenFile(edgesPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return Meta{}, err
	}
	defer ef.Close()

	// Map package directories for Go resolution
	goModRoot, modulePath := readGoMod(absRepo)
	packageFiles := map[string][]string{} // package import path or dir -> files

	var fileCount, edgeCount int
	encF := json.NewEncoder(ff)
	encE := json.NewEncoder(ef)

	// First pass: file inventory
	type fileRec struct {
		rel  string
		lang string
		body string
	}
	var records []fileRec
	for _, rel := range rels {
		full := filepath.Join(absRepo, rel)
		body, err := os.ReadFile(full)
		if err != nil {
			continue
		}
		lang := languageOf(rel)
		sum := sha256.Sum256(body)
		entry := FileEntry{
			Path:     filepath.ToSlash(rel),
			Language: lang,
			Size:     int64(len(body)),
			Hash:     hex.EncodeToString(sum[:]),
		}
		if err := encF.Encode(entry); err != nil {
			return Meta{}, err
		}
		fileCount++
		records = append(records, fileRec{rel: entry.Path, lang: lang, body: string(body)})
		if lang == "go" {
			dirSlash := filepath.ToSlash(filepath.Dir(rel))
			if dirSlash == "." {
				dirSlash = ""
			}
			pkgImport := dirSlash
			if modulePath != "" && goModRoot != "" {
				// package path = module + path relative to go.mod dir
				relToMod, err := filepath.Rel(goModRoot, filepath.Join(absRepo, filepath.Dir(rel)))
				if err == nil {
					relToMod = filepath.ToSlash(relToMod)
					if relToMod == "." {
						pkgImport = modulePath
					} else {
						pkgImport = modulePath + "/" + relToMod
					}
				}
			}
			packageFiles[pkgImport] = append(packageFiles[pkgImport], entry.Path)
			packageFiles[dirSlash] = append(packageFiles[dirSlash], entry.Path)
		}
	}

	// Second pass: edges
	for _, rec := range records {
		var imports []string
		switch rec.lang {
		case "go":
			imports = extractGoImports(rec.body)
		case "typescript", "javascript":
			imports = extractTSImports(rec.body)
		default:
			continue
		}
		for _, imp := range imports {
			targets := resolveImport(absRepo, rec.rel, rec.lang, imp, modulePath, goModRoot, packageFiles, rels)
			if len(targets) == 0 {
				// store unresolved as edge to import string for debugging
				if err := encE.Encode(Edge{From: rec.rel, To: imp, Kind: "import-raw"}); err != nil {
					return Meta{}, err
				}
				edgeCount++
				continue
			}
			for _, to := range targets {
				if err := encE.Encode(Edge{From: rec.rel, To: to, Kind: "import"}); err != nil {
					return Meta{}, err
				}
				edgeCount++
			}
		}
	}

	meta := Meta{
		SchemaVersion: SchemaVersion,
		Fingerprint:   fingerprint,
		RepoPath:      absRepo,
		BuiltAt:       time.Now().UTC(),
		FileCount:     fileCount,
		EdgeCount:     edgeCount,
	}
	metaBytes, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return Meta{}, err
	}
	if err := os.WriteFile(filepath.Join(dir, metaFile), append(metaBytes, '\n'), 0o600); err != nil {
		return Meta{}, err
	}
	return meta, nil
}

// Load opens an existing index directory.
func Load(dir string) (*Index, error) {
	meta, ok := loadMeta(filepath.Join(dir, metaFile))
	if !ok {
		return nil, fmt.Errorf("repo-index: missing or invalid meta in %s", dir)
	}
	files, err := readFiles(filepath.Join(dir, filesFile))
	if err != nil {
		return nil, err
	}
	edges, err := readEdges(filepath.Join(dir, edgesFile))
	if err != nil {
		return nil, err
	}
	return &Index{Dir: dir, Meta: meta, Files: files, Edges: edges}, nil
}

// Index is an in-memory query surface (used by tests and optional CLI tooling).
type Index struct {
	Dir   string
	Meta  Meta
	Files []FileEntry
	Edges []Edge
}

// ListFiles returns files, optionally filtered by language prefix or suffix glob-ish.
func (idx *Index) ListFiles(language string, limit int) []FileEntry {
	if limit <= 0 {
		limit = 5000
	}
	var out []FileEntry
	for _, f := range idx.Files {
		if language != "" && f.Language != language {
			continue
		}
		out = append(out, f)
		if len(out) >= limit {
			break
		}
	}
	return out
}

// File returns metadata for a path or false.
func (idx *Index) File(path string) (FileEntry, bool) {
	path = filepath.ToSlash(path)
	for _, f := range idx.Files {
		if f.Path == path {
			return f, true
		}
	}
	return FileEntry{}, false
}

// ImportsOf returns destinations imported by path.
func (idx *Index) ImportsOf(path string) []Edge {
	path = filepath.ToSlash(path)
	var out []Edge
	for _, e := range idx.Edges {
		if e.From == path && e.Kind == "import" {
			out = append(out, e)
		}
	}
	return out
}

// ImportersOf returns edges where to equals path (or a directory prefix of path).
func (idx *Index) ImportersOf(path string) []Edge {
	path = filepath.ToSlash(path)
	dir := filepath.ToSlash(filepath.Dir(path))
	if dir == "." {
		dir = ""
	}
	var out []Edge
	for _, e := range idx.Edges {
		if e.Kind != "import" {
			continue
		}
		if e.To == path || e.To == dir || strings.HasPrefix(path, strings.TrimSuffix(e.To, "/")+"/") {
			// Prefer exact file matches; also package-dir matches for Go
			if e.To == path || e.To == dir {
				out = append(out, e)
			}
		}
	}
	return out
}

func readFiles(path string) ([]FileEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []FileEntry
	sc := bufio.NewScanner(f)
	// large lines
	buf := make([]byte, 0, 64*1024)
	sc.Buffer(buf, 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var e FileEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, sc.Err()
}

func readEdges(path string) ([]Edge, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Edge
	sc := bufio.NewScanner(f)
	buf := make([]byte, 0, 64*1024)
	sc.Buffer(buf, 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var e Edge
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, sc.Err()
}

// --- walk / exclude ---

var excludeDirNames = map[string]struct{}{
	".git": {}, "node_modules": {}, "vendor": {}, "dist": {}, "bin": {},
	".next": {}, "coverage": {}, "__pycache__": {}, ".tox": {}, "target": {},
}

func listIndexableFiles(root string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := d.Name()
		if d.IsDir() {
			if _, skip := excludeDirNames[name]; skip {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasPrefix(name, ".") {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		lang := languageOf(rel)
		if lang == "" {
			return nil
		}
		out = append(out, rel)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(out)
	return out, nil
}

func languageOf(rel string) string {
	ext := strings.ToLower(filepath.Ext(rel))
	switch ext {
	case ".go":
		return "go"
	case ".ts", ".tsx":
		return "typescript"
	case ".js", ".jsx", ".mjs", ".cjs":
		return "javascript"
	default:
		return ""
	}
}

// --- import extraction ---

var (
	goImportSingle = regexp.MustCompile(`(?m)^\s*import\s+(?:\w+\s+)?"([^"]+)"`)
	goImportBlock  = regexp.MustCompile(`(?s)import\s*\((.*?)\)`)
	goImportLine   = regexp.MustCompile(`"([^"]+)"`)
	tsImportFrom   = regexp.MustCompile(`(?m)(?:import|export)\s+(?:type\s+)?(?:[^'"\n]+from\s+)?['"]([^'"]+)['"]`)
	tsRequire      = regexp.MustCompile(`(?m)require\s*\(\s*['"]([^'"]+)['"]\s*\)`)
	tsDynamic      = regexp.MustCompile(`(?m)import\s*\(\s*['"]([^'"]+)['"]\s*\)`)
)

func extractGoImports(src string) []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" {
			return
		}
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	for _, m := range goImportSingle.FindAllStringSubmatch(src, -1) {
		add(m[1])
	}
	for _, block := range goImportBlock.FindAllStringSubmatch(src, -1) {
		for _, m := range goImportLine.FindAllStringSubmatch(block[1], -1) {
			add(m[1])
		}
	}
	return out
}

func extractTSImports(src string) []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" || strings.HasPrefix(s, "node:") {
			return
		}
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	for _, re := range []*regexp.Regexp{tsImportFrom, tsRequire, tsDynamic} {
		for _, m := range re.FindAllStringSubmatch(src, -1) {
			add(m[1])
		}
	}
	return out
}

func resolveImport(
	absRepo, fromRel, lang, imp, modulePath, goModRoot string,
	packageFiles map[string][]string,
	allRels []string,
) []string {
	fromRel = filepath.ToSlash(fromRel)
	switch lang {
	case "go":
		// stdlib / external: skip resolution to files
		if !strings.Contains(imp, ".") && !strings.HasPrefix(imp, modulePath) && modulePath != "" {
			// might still be local if no module — try dir map
		}
		if modulePath != "" && (imp == modulePath || strings.HasPrefix(imp, modulePath+"/")) {
			if files := packageFiles[imp]; len(files) > 0 {
				// edge to package directory (first file's dir) for stable importersOf
				dir := filepath.ToSlash(filepath.Dir(files[0]))
				if dir == "." {
					dir = ""
				}
				return []string{dir}
			}
		}
		// relative not used in Go
		if files := packageFiles[imp]; len(files) > 0 {
			dir := filepath.ToSlash(filepath.Dir(files[0]))
			if dir == "." {
				dir = ""
			}
			return []string{dir}
		}
		return nil
	case "typescript", "javascript":
		if !strings.HasPrefix(imp, ".") && !strings.HasPrefix(imp, "/") {
			// bare specifier — unresolved in v1
			return nil
		}
		baseDir := filepath.Dir(filepath.FromSlash(fromRel))
		joined := filepath.Clean(filepath.Join(baseDir, filepath.FromSlash(imp)))
		joinedSlash := filepath.ToSlash(joined)
		// try exact and with extensions / index
		candidates := []string{
			joinedSlash,
			joinedSlash + ".ts",
			joinedSlash + ".tsx",
			joinedSlash + ".js",
			joinedSlash + ".jsx",
			joinedSlash + ".mjs",
			joinedSlash + "/index.ts",
			joinedSlash + "/index.tsx",
			joinedSlash + "/index.js",
		}
		fileSet := map[string]struct{}{}
		for _, r := range allRels {
			fileSet[filepath.ToSlash(r)] = struct{}{}
		}
		for _, c := range candidates {
			c = strings.TrimPrefix(c, "./")
			if _, ok := fileSet[c]; ok {
				return []string{c}
			}
		}
		return nil
	default:
		return nil
	}
}

func readGoMod(absRepo string) (goModDir, modulePath string) {
	// find go.mod at root or walk up one level only (keep simple: root)
	path := filepath.Join(absRepo, "go.mod")
	data, err := os.ReadFile(path)
	if err != nil {
		return "", ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "module ") {
			return absRepo, strings.TrimSpace(strings.TrimPrefix(line, "module "))
		}
	}
	return absRepo, ""
}

func isGitRepo(dir string) bool {
	info, err := os.Stat(filepath.Join(dir, ".git"))
	return err == nil && (info.IsDir() || info.Mode().IsRegular())
}

func gitOutput(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	// avoid inheriting pager
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	out, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return "", fmt.Errorf("git %v: %w: %s", args, err, string(ee.Stderr))
		}
		return "", err
	}
	return string(out), nil
}

// EnsureForRun is a convenience used by the runner with default cache root.
func EnsureForRun(repoPath string, mode Mode, verbose bool, stderr io.Writer) (indexDir string, err error) {
	if mode == ModeOff {
		return "", nil
	}
	var log io.Writer
	if verbose {
		log = stderr
	}
	v1Mode := mode
	if mode == ModeGraph {
		v1Mode = ModeAuto
	} else if mode == ModeGraphForce {
		v1Mode = ModeForce
	}
	h, err := Ensure(repoPath, v1Mode, log)
	if err != nil {
		return "", err
	}
	if h == nil {
		return "", nil
	}
	return h.Dir, nil
}

// Silence unused on non-unix
var _ = runtime.GOOS
