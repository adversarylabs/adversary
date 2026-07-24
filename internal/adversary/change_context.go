package adversary

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/adversarylabs/adversary/pkg/detection"
)

type ChangeRequest struct {
	RepoPath string
	Mode     detection.ChangeMode
	BaseRef  string
	HeadRef  string
}

type RunScopeKind string

const (
	RunScopeAllFiles RunScopeKind = "all-files"
	RunScopeWorktree RunScopeKind = "worktree"
	RunScopeBranch   RunScopeKind = "branch"
	RunScopePR       RunScopeKind = "pull-request"
)

type RunScopeRequest struct {
	RepoPath string
	BaseRef  string
	HeadRef  string
	AllFiles bool
	Lookup   EnvironmentLookup
}

type RunScopeResolution struct {
	Kind          RunScopeKind
	Reason        string
	DefaultBase   string
	ReviewContext *detection.Context
	AllFiles      bool
}

type RunScopeResolver interface {
	ResolveRunScope(context.Context, RunScopeRequest) (RunScopeResolution, error)
}

type ChangeResolver interface {
	ResolveChanges(context.Context, ChangeRequest) (detection.Context, error)
}

type RepositoryFileResolver interface {
	RepositoryFiles(context.Context, string) ([]string, error)
}

func (g CommandGitDiffer) RepositoryFiles(ctx context.Context, repoPath string) ([]string, error) {
	root, err := g.repositoryRoot(ctx, repoPath)
	if err != nil {
		return nil, err
	}
	out, stderr, err := g.run(ctx, root, "ls-files", "--cached", "--others", "--exclude-standard", "-z", "--")
	if err != nil {
		if message := strings.TrimSpace(string(stderr)); message != "" {
			return nil, fmt.Errorf("list repository files: %s", message)
		}
		return nil, fmt.Errorf("list repository files: %w", err)
	}
	paths, err := parseNULPaths(out)
	if err != nil {
		return nil, fmt.Errorf("parse repository files: %w", err)
	}
	sort.Strings(paths)
	return paths, nil
}

// ChangeRequestForArgument interprets the optional positional syntax accepted
// by `adversary auto`. A single revision compares it with HEAD; an explicit
// three-dot range retains its two endpoints and merge-base semantics.
func ChangeRequestForArgument(repoPath, argument string) (ChangeRequest, error) {
	argument = strings.TrimSpace(argument)
	if argument == "" {
		return ChangeRequest{RepoPath: repoPath, Mode: detection.ModeDirtyWorktree}, nil
	}
	if strings.Contains(argument, "..") {
		if strings.Count(argument, "...") != 1 {
			return ChangeRequest{}, fmt.Errorf("change range must use exactly one base...head expression")
		}
		base, head, ok := strings.Cut(argument, "...")
		if !ok || strings.Contains(base, "..") || strings.Contains(head, "..") || strings.HasSuffix(base, ".") || strings.HasPrefix(head, ".") || !validRevisionArgument(base) || !validRevisionArgument(head) {
			return ChangeRequest{}, fmt.Errorf("change range must contain valid base and head revisions")
		}
		return ChangeRequest{RepoPath: repoPath, Mode: detection.ModeExplicitRange, BaseRef: base, HeadRef: head}, nil
	}
	if !validRevisionArgument(argument) {
		return ChangeRequest{}, fmt.Errorf("base revision must be a revision name, not a command option or NUL-containing value")
	}
	return ChangeRequest{RepoPath: repoPath, Mode: detection.ModeBranchComparison, BaseRef: argument, HeadRef: "HEAD"}, nil
}

type EnvironmentLookup func(string) (string, bool)

// ResolveRunScope selects the narrowest useful scope for an explicit run.
// Explicit flags win, followed by pull-request CI context, local worktree
// changes, and a clean branch comparison. A clean default branch, a non-Git
// path, or unavailable Git falls back to the full target so `run` remains a
// useful explicit repository audit.
func (g CommandGitDiffer) ResolveRunScope(ctx context.Context, request RunScopeRequest) (RunScopeResolution, error) {
	if request.AllFiles {
		return RunScopeResolution{Kind: RunScopeAllFiles, Reason: "requested by --all-files", AllFiles: true}, nil
	}
	explicit := request.BaseRef != "" || request.HeadRef != ""
	ciRequest, inCI := ChangeRequestFromCI(request.RepoPath, request.Lookup)
	if err := g.validate(); err != nil {
		if explicit || inCI {
			return RunScopeResolution{}, err
		}
		return RunScopeResolution{Kind: RunScopeAllFiles, Reason: "Git is unavailable", AllFiles: true}, nil
	}
	repo := request.RepoPath
	if repo == "" {
		repo = "."
	}
	root, err := g.repositoryRoot(ctx, repo)
	if err != nil {
		if explicit || inCI {
			return RunScopeResolution{}, err
		}
		return RunScopeResolution{Kind: RunScopeAllFiles, Reason: "target is not a Git work tree", AllFiles: true}, nil
	}

	if explicit {
		base, head := request.BaseRef, request.HeadRef
		if head == "" {
			head = "HEAD"
		}
		if base == "" {
			base, _, err = g.defaultBaseRef(ctx, root)
			if err != nil {
				return RunScopeResolution{}, fmt.Errorf("infer --base for explicit --head: %w", err)
			}
		}
		resolved, err := g.ResolveChanges(ctx, ChangeRequest{RepoPath: repo, Mode: detection.ModeExplicitRange, BaseRef: base, HeadRef: head})
		if err != nil {
			return RunScopeResolution{}, err
		}
		return RunScopeResolution{Kind: RunScopeBranch, Reason: "explicit base/head", DefaultBase: base, ReviewContext: &resolved}, nil
	}

	if inCI {
		resolved, err := g.ResolveChanges(ctx, ciRequest)
		if err != nil {
			return RunScopeResolution{}, err
		}
		return RunScopeResolution{Kind: RunScopePR, Reason: "pull-request CI environment", DefaultBase: ciRequest.BaseRef, ReviewContext: &resolved}, nil
	}

	dirty, err := g.ResolveChanges(ctx, ChangeRequest{RepoPath: repo, Mode: detection.ModeDirtyWorktree})
	if err != nil {
		return RunScopeResolution{}, err
	}
	if len(dirty.ChangedFiles) > 0 {
		return RunScopeResolution{Kind: RunScopeWorktree, Reason: "uncommitted changes", ReviewContext: &dirty}, nil
	}

	base, source, err := g.defaultBaseRef(ctx, root)
	if err != nil {
		return RunScopeResolution{Kind: RunScopeAllFiles, Reason: "default branch could not be determined", AllFiles: true}, nil
	}
	current, attached := g.currentBranch(ctx, root)
	if attached && sameBranchRef(base, current) {
		return RunScopeResolution{Kind: RunScopeAllFiles, Reason: "clean default branch", DefaultBase: base, AllFiles: true}, nil
	}
	if !attached {
		baseCommit, baseErr := g.resolveCommit(ctx, root, base)
		headCommit, headErr := g.resolveCommit(ctx, root, "HEAD")
		if baseErr == nil && headErr == nil && baseCommit == headCommit {
			return RunScopeResolution{Kind: RunScopeAllFiles, Reason: "clean default-branch commit", DefaultBase: base, AllFiles: true}, nil
		}
	}
	head := "HEAD"
	if attached {
		head = current
	}
	resolved, err := g.ResolveChanges(ctx, ChangeRequest{RepoPath: repo, Mode: detection.ModeBranchComparison, BaseRef: base, HeadRef: head})
	if err != nil {
		return RunScopeResolution{}, err
	}
	return RunScopeResolution{Kind: RunScopeBranch, Reason: "clean branch compared with default branch via " + source, DefaultBase: base, ReviewContext: &resolved}, nil
}

func (g CommandGitDiffer) defaultBaseRef(ctx context.Context, root string) (string, string, error) {
	if out, _, err := g.run(ctx, root, "config", "--get", "adversary.defaultBase"); err == nil {
		if candidate := strings.TrimSpace(string(out)); validRevisionArgument(candidate) {
			if _, err := g.resolveCommit(ctx, root, candidate); err == nil {
				return candidate, "git config adversary.defaultBase", nil
			}
		}
	}
	remote := "origin"
	if out, _, err := g.run(ctx, root, "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{upstream}"); err == nil {
		if upstream := strings.TrimSpace(string(out)); strings.Contains(upstream, "/") {
			remote = strings.SplitN(upstream, "/", 2)[0]
		}
	}
	for _, ref := range []string{"refs/remotes/" + remote + "/HEAD", "refs/remotes/origin/HEAD"} {
		if out, _, err := g.run(ctx, root, "symbolic-ref", "--quiet", "--short", ref); err == nil {
			candidate := strings.TrimSpace(string(out))
			if validRevisionArgument(candidate) {
				if _, err := g.resolveCommit(ctx, root, candidate); err == nil {
					return candidate, ref, nil
				}
			}
		}
	}
	for _, candidates := range [][]string{{"origin/main", "main"}, {"origin/master", "master"}, {"origin/trunk", "trunk"}} {
		for _, candidate := range candidates {
			if _, err := g.resolveCommit(ctx, root, candidate); err == nil {
				return candidate, "conventional branch fallback", nil
			}
		}
	}
	return "", "", fmt.Errorf("no configured, remote HEAD, or conventional default branch ref is available")
}

func (g CommandGitDiffer) currentBranch(ctx context.Context, root string) (string, bool) {
	out, _, err := g.run(ctx, root, "symbolic-ref", "--quiet", "--short", "HEAD")
	if err != nil {
		return "", false
	}
	branch := strings.TrimSpace(string(out))
	return branch, branch != ""
}

func sameBranchRef(base, current string) bool {
	base = strings.TrimPrefix(base, "refs/remotes/")
	current = strings.TrimPrefix(current, "refs/heads/")
	return base == current || strings.HasSuffix(base, "/"+current)
}

// ChangeRequestFromCI recognizes explicit and common pull-request references.
// It is intentionally pure: environment is captured by process composition and
// Git is still resolved exactly once by ResolveChanges.
func ChangeRequestFromCI(repoPath string, lookup EnvironmentLookup) (ChangeRequest, bool) {
	if lookup == nil {
		return ChangeRequest{}, false
	}
	for _, pair := range [][2]string{
		{"ADVERSARY_BASE_REF", "ADVERSARY_HEAD_REF"},
		{"GITHUB_BASE_REF", "GITHUB_SHA"},
		{"CI_MERGE_REQUEST_TARGET_BRANCH_NAME", "CI_COMMIT_SHA"},
		{"BUILDKITE_PULL_REQUEST_BASE_BRANCH", "BUILDKITE_COMMIT"},
	} {
		base, baseOK := lookup(pair[0])
		head, headOK := lookup(pair[1])
		if baseOK && headOK && validRevisionArgument(base) && validRevisionArgument(head) {
			return ChangeRequest{RepoPath: repoPath, Mode: detection.ModePullRequest, BaseRef: base, HeadRef: head}, true
		}
	}
	return ChangeRequest{}, false
}

// ResolveChanges resolves one immutable description of the Git change. The
// returned context is suitable for sharing with every detector and review in
// one auto invocation; callers must not recalculate it per adversary.
func (g CommandGitDiffer) ResolveChanges(ctx context.Context, request ChangeRequest) (detection.Context, error) {
	if err := g.validate(); err != nil {
		return detection.Context{}, err
	}
	repo := request.RepoPath
	if repo == "" {
		repo = "."
	}
	root, err := g.repositoryRoot(ctx, repo)
	if err != nil {
		return detection.Context{}, err
	}
	result := detection.Context{SchemaVersion: detection.SchemaVersion, RepositoryRoot: root, Mode: request.Mode, ChangedFiles: []detection.ChangedFile{}}
	switch request.Mode {
	case detection.ModeDirtyWorktree:
		changes, err := g.dirtyChanges(ctx, root)
		if err != nil {
			return detection.Context{}, err
		}
		result.ChangedFiles = changes
	case detection.ModeBranchComparison, detection.ModeExplicitRange, detection.ModePullRequest:
		if request.BaseRef == "" || request.HeadRef == "" {
			return detection.Context{}, fmt.Errorf("base and head refs are required for %s", request.Mode)
		}
		if !validRevisionArgument(request.BaseRef) || !validRevisionArgument(request.HeadRef) {
			return detection.Context{}, fmt.Errorf("base and head refs must be revision names, not command options or NUL-containing values")
		}
		base, err := g.resolveBaseCommit(ctx, root, request.Mode, request.BaseRef)
		if err != nil {
			return detection.Context{}, fmt.Errorf("base revision %q is unavailable: %w", request.BaseRef, err)
		}
		head, err := g.resolveCommit(ctx, root, request.HeadRef)
		if err != nil {
			return detection.Context{}, fmt.Errorf("head revision %q is unavailable: %w", request.HeadRef, err)
		}
		mergeBase, err := g.resolveMergeBase(ctx, root, base, head)
		if err != nil {
			return detection.Context{}, err
		}
		changes, err := g.diffChanges(ctx, root, mergeBase, head)
		if err != nil {
			return detection.Context{}, err
		}
		result.BaseRef, result.HeadRef, result.MergeBase = request.BaseRef, request.HeadRef, mergeBase
		result.ChangedFiles = toDetectionChanges(changes)
	default:
		return detection.Context{}, fmt.Errorf("unsupported change mode %q", request.Mode)
	}
	sort.Slice(result.ChangedFiles, func(i, j int) bool {
		if result.ChangedFiles[i].Path == result.ChangedFiles[j].Path {
			return result.ChangedFiles[i].PreviousPath < result.ChangedFiles[j].PreviousPath
		}
		return result.ChangedFiles[i].Path < result.ChangedFiles[j].Path
	})
	return result, nil
}

func (g CommandGitDiffer) resolveBaseCommit(ctx context.Context, root string, mode detection.ChangeMode, ref string) (string, error) {
	if mode == detection.ModePullRequest {
		if remoteBase := pullRequestRemoteRef(ref); remoteBase != "" {
			if base, err := g.resolveCommit(ctx, root, remoteBase); err == nil {
				return base, nil
			}
		}
	}
	return g.resolveCommit(ctx, root, ref)
}

func pullRequestRemoteRef(ref string) string {
	ref = strings.TrimPrefix(ref, "refs/heads/")
	if ref == "" || ref == "HEAD" || strings.HasPrefix(ref, "refs/") || strings.HasPrefix(ref, "origin/") {
		return ""
	}
	return "origin/" + ref
}

func (g CommandGitDiffer) repositoryRoot(ctx context.Context, repo string) (string, error) {
	out, _, err := g.run(ctx, repo, "rev-parse", "--show-toplevel")
	if err != nil {
		return "", fmt.Errorf("%q is not a Git work tree", repo)
	}
	root := strings.TrimSpace(string(out))
	if root == "" {
		return "", fmt.Errorf("Git returned an empty repository root for %q", repo)
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("resolve repository root: %w", err)
	}
	return abs, nil
}

func (g CommandGitDiffer) diffChanges(ctx context.Context, repo, base, head string) ([]GitChange, error) {
	out, stderr, err := g.run(ctx, repo, gitDiffNameStatusArgs(base, head)...)
	if err != nil {
		if message := strings.TrimSpace(string(stderr)); message != "" {
			return nil, fmt.Errorf("git diff failed: %s", message)
		}
		return nil, fmt.Errorf("git diff failed: %w", err)
	}
	changes, err := parseGitChanges(out)
	if err != nil {
		return nil, fmt.Errorf("parse git diff output: %w", err)
	}
	return changes, nil
}

func (g CommandGitDiffer) dirtyChanges(ctx context.Context, repo string) ([]detection.ChangedFile, error) {
	_, _, headErr := g.run(ctx, repo, "rev-parse", "--verify", "--quiet", "HEAD^{commit}")
	var tracked []GitChange
	if headErr == nil {
		changes, err := g.diffChanges(ctx, repo, "HEAD", "")
		if err != nil {
			return nil, err
		}
		tracked = changes
	} else {
		out, stderr, err := g.run(ctx, repo, "diff", "--no-ext-diff", "--ignore-submodules=none", "--cached", "--name-status", "-z", "--find-renames", "--find-copies", "--find-copies-harder", "--")
		if err != nil {
			if message := strings.TrimSpace(string(stderr)); message != "" {
				return nil, fmt.Errorf("git diff --cached failed: %s", message)
			}
			return nil, fmt.Errorf("git diff --cached failed: %w", err)
		}
		tracked, err = parseGitChanges(out)
		if err != nil {
			return nil, fmt.Errorf("parse staged Git changes: %w", err)
		}
	}

	result := toDetectionChanges(tracked)
	out, stderr, err := g.run(ctx, repo, "ls-files", "--others", "--exclude-standard", "-z", "--")
	if err != nil {
		if message := strings.TrimSpace(string(stderr)); message != "" {
			return nil, fmt.Errorf("list untracked files: %s", message)
		}
		return nil, fmt.Errorf("list untracked files: %w", err)
	}
	paths, err := parseNULPaths(out)
	if err != nil {
		return nil, fmt.Errorf("parse untracked files: %w", err)
	}
	seen := make(map[string]struct{}, len(result)+len(paths))
	for _, change := range result {
		seen[change.Path] = struct{}{}
	}
	for _, path := range paths {
		if _, exists := seen[path]; exists {
			continue
		}
		result = append(result, detection.ChangedFile{Path: path, Status: detection.StatusUntracked})
	}
	return result, nil
}

func parseNULPaths(output []byte) ([]string, error) {
	if len(output) == 0 {
		return nil, nil
	}
	if output[len(output)-1] != 0 {
		return nil, fmt.Errorf("unterminated NUL-delimited path list")
	}
	fields := bytes.Split(output[:len(output)-1], []byte{0})
	paths := make([]string, 0, len(fields))
	for _, field := range fields {
		if len(field) == 0 {
			return nil, fmt.Errorf("empty path")
		}
		paths = append(paths, string(field))
	}
	return paths, nil
}

func toDetectionChanges(changes []GitChange) []detection.ChangedFile {
	result := make([]detection.ChangedFile, 0, len(changes))
	for _, change := range changes {
		status := detection.StatusModified
		switch change.Status {
		case GitAdded:
			status = detection.StatusAdded
		case GitDeleted:
			status = detection.StatusDeleted
		case GitRenamed:
			status = detection.StatusRenamed
		case GitCopied:
			status = detection.StatusCopied
		case GitModified, GitTypeChanged:
			status = detection.StatusModified
		}
		result = append(result, detection.ChangedFile{Path: change.Path, PreviousPath: change.OldPath, Status: status})
	}
	return result
}
