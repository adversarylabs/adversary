package findingverify

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unicode"

	"github.com/adversarylabs/adversary/pkg/detection"
)

const maxFileBytes = 512 << 10

type fileContent struct{ text, unavailable string }

// Collector pins committed reads and freezes every changed worktree file before
// reviewers run. It never executes repository code, hooks, diff drivers or filters.
type Collector struct {
	root, Base, Head string
	mu               sync.Mutex
	files            map[string]fileContent
	patches          map[string]string
}

func NewCollector(ctx context.Context, change *detection.Context) (*Collector, error) {
	if change == nil || change.RepositoryRoot == "" {
		return nil, fmt.Errorf("resolved change context unavailable")
	}
	c := &Collector{root: change.RepositoryRoot, files: map[string]fileContent{}, patches: map[string]string{}}
	base := change.MergeBase
	if base == "" {
		base = change.BaseRef
	}
	if base == "" {
		base = "HEAD"
	}
	head := change.HeadRef
	if head == "" {
		head = "HEAD"
	}
	var err error
	c.Base, err = c.revision(ctx, base)
	if err != nil {
		return nil, fmt.Errorf("cannot pin review base")
	}
	c.Head, err = c.revision(ctx, head)
	if err != nil {
		return nil, fmt.Errorf("cannot pin review head")
	}
	dirty := change.Mode == detection.ModeDirtyWorktree
	for _, file := range change.ChangedFiles {
		if !validPath(file.Path) {
			continue
		}
		if dirty {
			c.files["head:"+file.Path] = c.worktreeFile(file.Path)
		}
		args := []string{"diff", "--no-ext-diff", "--no-textconv", "--unified=12", c.Base}
		if !dirty {
			args = append(args, c.Head)
		}
		args = append(args, "--", file.Path)
		patch, patchErr := c.git(ctx, 48<<10, args...)
		if patchErr != nil {
			patch = "[Patch unavailable or exceeds 48 KiB; verify from base/head source.]"
		}
		if dirty && file.Status == detection.StatusUntracked {
			patch = "New untracked file; all supplied head lines are additions."
		}
		c.patches[file.Path] = patch
	}
	return c, nil
}
func validPath(p string) bool {
	return len(p) <= 4096 && p != "" && p != "." && !path.IsAbs(p) && path.Clean(p) == p && p != ".." && !strings.HasPrefix(p, "../") && !strings.Contains(p, "\\") && p != ".git" && !strings.HasPrefix(p, ".git/") && strings.IndexFunc(p, unicode.IsControl) < 0
}
func validRequest(r ReadRequest) bool {
	return validPath(r.Path) && (r.Side == "base" || r.Side == "head") && r.StartLine >= 1 && r.EndLine >= r.StartLine && r.EndLine-r.StartLine < 200
}
func (c *Collector) Read(ctx context.Context, r ReadRequest) Source {
	s := Source{Path: r.Path, Side: r.Side, StartLine: r.StartLine}
	if !validRequest(r) {
		s.StartLine = max(1, s.StartLine)
		s.Unavailable = "Invalid or over-budget source request."
		s.ID = sourceID(s)
		return s
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	key := r.Side + ":" + r.Path
	file, ok := c.files[key]
	if !ok {
		ref := c.Head
		if r.Side == "base" {
			ref = c.Base
		}
		file = c.committedFile(ctx, ref, r.Path)
		c.files[key] = file
	}
	if file.unavailable != "" {
		s.Unavailable = file.unavailable
	} else {
		lines := strings.Split(strings.TrimSuffix(file.text, "\n"), "\n")
		if file.text == "" || r.StartLine > len(lines) {
			s.Unavailable = "Requested lines are outside the file."
		} else {
			s.Content = strings.Join(lines[r.StartLine-1:min(r.EndLine, len(lines))], "\n") + "\n"
			s.EndOfFile = r.EndLine >= len(lines)
			if len(s.Content) > 32<<10 {
				s.Content = ""
				s.Unavailable = "Requested source exceeds 32 KiB."
			}
		}
	}
	s.ID = sourceID(s)
	return s
}
func (c *Collector) Prepare(ctx context.Context, candidate *Candidate) {
	paths := map[string]bool{}
	for _, e := range candidate.Finding.Evidence {
		if len(paths) >= 4 {
			break
		}
		if !validPath(e.File) || paths[e.File] {
			continue
		}
		paths[e.File] = true
		line := 1
		if e.Line != nil {
			line = max(1, *e.Line)
		}
		for _, side := range []string{"base", "head"} {
			candidate.Sources = append(candidate.Sources, c.Read(ctx, ReadRequest{Path: e.File, Side: side, StartLine: max(1, line-40), EndLine: line + 60}))
		}
		if patch := c.patches[e.File]; patch != "" {
			candidate.Patch += "\nFile: " + e.File + "\n" + patch
		}
	}
	for _, policy := range []string{"AGENTS.md", "CLAUDE.md"} {
		source := c.Read(ctx, ReadRequest{Path: policy, Side: "head", StartLine: 1, EndLine: 120})
		if source.Unavailable == "" {
			candidate.Sources = append(candidate.Sources, source)
		}
	}
	// A cited unchanged file may be affected by a caller change elsewhere. Supply
	// changed paths as retrieval leads without pretending unseen hunks were read.
	var changed []string
	for p := range c.patches {
		changed = append(changed, p)
	}
	sort.Strings(changed)
	if len(changed) > 100 {
		changed = changed[:100]
	}
	candidate.Patch += "\nOther changed-file leads (read before relying on them): " + strings.Join(changed, ", ")
}
func (c *Collector) revision(ctx context.Context, ref string) (string, error) {
	value, err := c.git(ctx, 1024, "rev-parse", "--verify", "--end-of-options", ref+"^{commit}")
	return strings.TrimSpace(value), err
}
func (c *Collector) committedFile(ctx context.Context, ref, p string) fileContent {
	entry, err := c.git(ctx, 4096, "ls-tree", ref, "--", p)
	if err != nil || !(strings.HasPrefix(entry, "100644 blob ") || strings.HasPrefix(entry, "100755 blob ")) {
		return fileContent{unavailable: "Regular source file unavailable at pinned revision."}
	}
	size, err := c.git(ctx, 64, "cat-file", "-s", ref+":"+p)
	n, parseErr := strconv.Atoi(strings.TrimSpace(size))
	if err != nil || parseErr != nil || n > maxFileBytes {
		return fileContent{unavailable: "Source unavailable or exceeds 512 KiB."}
	}
	content, err := c.git(ctx, maxFileBytes, "show", ref+":"+p)
	if err != nil || strings.ContainsRune(content, 0) {
		return fileContent{unavailable: "Source unavailable or binary."}
	}
	return fileContent{text: content}
}
func (c *Collector) worktreeFile(p string) fileContent {
	root, err := os.OpenRoot(c.root)
	if err != nil {
		return fileContent{unavailable: "Worktree source unavailable."}
	}
	defer root.Close()
	info, err := root.Lstat(p)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxFileBytes {
		return fileContent{unavailable: "Regular worktree source unavailable or over budget."}
	}
	file, err := root.Open(p)
	if err != nil {
		return fileContent{unavailable: "Worktree source unavailable."}
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxFileBytes+1))
	if err != nil || len(data) > maxFileBytes || bytes.IndexByte(data, 0) >= 0 {
		return fileContent{unavailable: "Worktree source unreadable, binary, or over budget."}
	}
	return fileContent{text: string(data)}
}

type boundedBuffer struct {
	bytes.Buffer
	limit int
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.Len() {
		return 0, fmt.Errorf("source output exceeds budget")
	}
	return b.Buffer.Write(p)
}
func (c *Collector) git(ctx context.Context, limit int, args ...string) (string, error) {
	prefix := []string{"--no-pager", "--no-replace-objects", "--literal-pathspecs", "-c", "core.fsmonitor=false", "-C", c.root}
	command := exec.CommandContext(ctx, "git", append(prefix, args...)...)
	out := &boundedBuffer{limit: limit}
	command.Stdout = out
	// Discard stderr: missing source is represented explicitly without leaking
	// host paths or repository-configured diagnostics into the model/report.
	command.Stderr = io.Discard
	err := command.Run()
	return out.String(), err
}
