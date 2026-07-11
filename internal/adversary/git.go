package adversary

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

type GitChangeStatus string

const (
	GitAdded       GitChangeStatus = "added"
	GitModified    GitChangeStatus = "modified"
	GitDeleted     GitChangeStatus = "deleted"
	GitRenamed     GitChangeStatus = "renamed"
	GitCopied      GitChangeStatus = "copied"
	GitTypeChanged GitChangeStatus = "type-changed"
)

// GitChange preserves both sides of rename/copy records. Path is the path in
// head; OldPath is populated for renames and copies.
type GitChange struct {
	Status  GitChangeStatus
	Path    string
	OldPath string
	Score   int
}

type GitDiffer interface {
	ChangedFiles(ctx context.Context, repoPath, baseRef, headRef string) ([]string, error)
}

type CommandGitDiffer struct{}

func (CommandGitDiffer) ChangedFiles(ctx context.Context, repoPath, baseRef, headRef string) ([]string, error) {
	changes, err := (CommandGitDiffer{}).Changes(ctx, repoPath, baseRef, headRef)
	if err != nil {
		return nil, err
	}
	files := make([]string, 0, len(changes))
	for _, change := range changes {
		files = append(files, change.Path)
	}
	return files, nil
}

// Changes compares the merge-base of baseRef and headRef with headRef
// (git's base...head semantics). The caller must fetch enough history for a
// merge base before invoking this method.
func (CommandGitDiffer) Changes(ctx context.Context, repoPath, baseRef, headRef string) ([]GitChange, error) {
	if baseRef == "" || headRef == "" {
		return nil, fmt.Errorf("base and head refs are required")
	}
	if !validRevisionArgument(baseRef) || !validRevisionArgument(headRef) {
		return nil, fmt.Errorf("base and head refs must be revision names, not command options or NUL-containing values")
	}
	if err := verifyGitRepository(ctx, repoPath); err != nil {
		return nil, err
	}
	commits := make([]string, 0, 2)
	for _, item := range []struct{ label, ref string }{{"base", baseRef}, {"head", headRef}} {
		commit, err := resolveCommit(ctx, repoPath, item.ref)
		if err != nil {
			return nil, fmt.Errorf("%s revision %q is unavailable: %w; in a shallow CI checkout, fetch that revision and its history", item.label, item.ref, err)
		}
		commits = append(commits, commit)
	}
	mergeBase, err := resolveMergeBase(ctx, repoPath, commits[0], commits[1])
	if err != nil {
		return nil, err
	}

	cmd := gitDiffNameStatusCommand(ctx, mergeBase, commits[1])
	cmd.Dir = repoPath

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg != "" {
			return nil, fmt.Errorf("git diff failed: %s", msg)
		}
		return nil, fmt.Errorf("git diff failed: %w", err)
	}

	changes, err := parseGitChanges(stdout.Bytes())
	if err != nil {
		return nil, fmt.Errorf("parse git diff output: %w", err)
	}
	return changes, nil
}

func gitDiffNameStatusCommand(ctx context.Context, baseRef, headRef string) *exec.Cmd {
	return exec.CommandContext(ctx, "git", "diff", "--name-status", "-z", "--find-renames", "--find-copies", "--find-copies-harder", baseRef, headRef, "--")
}

func parseGitChanges(output []byte) ([]GitChange, error) {
	if len(output) == 0 {
		return nil, nil
	}
	fields := bytes.Split(output, []byte{0})
	if len(fields[len(fields)-1]) != 0 {
		return nil, fmt.Errorf("unterminated NUL-delimited record")
	}
	fields = fields[:len(fields)-1]
	changes := make([]GitChange, 0, len(fields)/2)
	for len(fields) > 0 {
		if len(fields) < 2 || len(fields[0]) == 0 || len(fields[1]) == 0 {
			return nil, fmt.Errorf("malformed name-status record")
		}
		code := string(fields[0])
		fields = fields[1:]
		status, score, valid := parseStatusCode(code)
		change := GitChange{Status: status, Score: score}
		if !valid {
			return nil, fmt.Errorf("unsupported git status %q", code)
		}
		if code[0] == 'R' || code[0] == 'C' {
			if len(fields) < 2 || len(fields[1]) == 0 {
				return nil, fmt.Errorf("malformed %s record", code)
			}
			change.OldPath, change.Path = string(fields[0]), string(fields[1])
			fields = fields[2:]
		} else {
			change.Path = string(fields[0])
			fields = fields[1:]
		}
		changes = append(changes, change)
	}
	return changes, nil
}

func parseStatusCode(code string) (GitChangeStatus, int, bool) {
	if len(code) == 1 {
		switch code[0] {
		case 'A':
			return GitAdded, 0, true
		case 'M':
			return GitModified, 0, true
		case 'D':
			return GitDeleted, 0, true
		case 'T':
			return GitTypeChanged, 0, true
		}
	}
	if len(code) < 2 || (code[0] != 'R' && code[0] != 'C') {
		return "", 0, false
	}
	for _, ch := range code[1:] {
		if ch < '0' || ch > '9' {
			return "", 0, false
		}
	}
	score, err := strconv.Atoi(code[1:])
	if err != nil || score > 100 {
		return "", 0, false
	}
	if code[0] == 'R' {
		return GitRenamed, score, true
	}
	return GitCopied, score, true
}

func validRevisionArgument(ref string) bool {
	return ref != "" && !strings.HasPrefix(ref, "-") && !strings.ContainsRune(ref, 0)
}

func verifyGitRepository(ctx context.Context, repoPath string) error {
	cmd := exec.CommandContext(ctx, "git", "rev-parse", "--is-inside-work-tree")
	cmd.Dir = repoPath
	out, err := cmd.CombinedOutput()
	if err != nil || strings.TrimSpace(string(out)) != "true" {
		return fmt.Errorf("%q is not a Git work tree", repoPath)
	}
	return nil
}

func resolveCommit(ctx context.Context, repoPath, ref string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", "rev-parse", "--verify", "--quiet", ref+"^{commit}")
	cmd.Dir = repoPath
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("not a known commit")
	}
	return strings.TrimSpace(string(out)), nil
}

func resolveMergeBase(ctx context.Context, repoPath, baseRef, headRef string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", "merge-base", baseRef, headRef)
	cmd.Dir = repoPath
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("base %q and head %q have no available merge base; fetch additional history in a shallow checkout", baseRef, headRef)
	}
	return strings.TrimSpace(string(out)), nil
}
