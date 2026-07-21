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

type ChangeResolver interface {
	ResolveChanges(context.Context, ChangeRequest) (detection.Context, error)
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
		base, err := g.resolveCommit(ctx, root, request.BaseRef)
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
		out, stderr, err := g.run(ctx, repo, "diff", "--cached", "--name-status", "-z", "--find-renames", "--find-copies", "--find-copies-harder", "--")
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
