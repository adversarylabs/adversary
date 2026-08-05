package githubreview

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/adversarylabs/adversary/internal/githubapi"
)

// WorkspaceResult is the local path prepared for a PR review.
type WorkspaceResult struct {
	Path         string // effective --path (worktree or clone)
	TempDir      string // non-empty if ephemeral (caller should cleanup)
	WorktreeRoot string // if set, TempDir is a linked worktree of this repo
	BaseSHA      string
	HeadSHA      string
	Owner        string
	Repo         string
	Number       int
}

// PreparePRWorkspace resolves PR metadata and a local tree at the PR head.
// Never mutates an existing user checkout: uses a detached worktree or clone.
func PreparePRWorkspace(
	ctx context.Context,
	client *githubapi.Client,
	owner, repo string,
	number int,
	path string,
	existingBase, existingHead string,
	progress io.Writer,
) (WorkspaceResult, error) {
	var out WorkspaceResult
	if client == nil {
		return out, fmt.Errorf("github client required")
	}
	pr, err := client.GetPullRequest(ctx, owner, repo, number)
	if err != nil {
		return out, err
	}
	baseSHA := strings.TrimSpace(pr.Base.SHA)
	headSHA := strings.TrimSpace(pr.Head.SHA)
	if baseSHA == "" || headSHA == "" {
		return out, fmt.Errorf("PR %s/%s#%d missing base/head SHAs", owner, repo, number)
	}
	if existingBase != "" && existingBase != baseSHA && existingBase != pr.Base.Ref {
		return out, fmt.Errorf("--base %q disagrees with PR base %s (%s)", existingBase, baseSHA, pr.Base.Ref)
	}
	if existingHead != "" && existingHead != headSHA && existingHead != pr.Head.Ref {
		return out, fmt.Errorf("--head %q disagrees with PR head %s (%s)", existingHead, headSHA, pr.Head.Ref)
	}
	out.BaseSHA = baseSHA
	if existingBase != "" {
		out.BaseSHA = existingBase
	}
	out.HeadSHA = headSHA
	if existingHead != "" {
		out.HeadSHA = existingHead
	}
	out.Owner, out.Repo = owner, repo
	out.Number = number

	if path == "" {
		path = "."
	}
	if progress != nil {
		fmt.Fprintf(progress, "Resolved PR %s/%s#%d → base %s… head %s…\n",
			owner, repo, number, shortSHA(out.BaseSHA), shortSHA(out.HeadSHA))
	}

	if isGitRepo(path) {
		ws, err := prepareWorktree(ctx, path, number, out.HeadSHA, progress)
		if err != nil {
			return out, err
		}
		out.Path = ws.path
		out.TempDir = ws.path
		out.WorktreeRoot = path
		return out, nil
	}

	// Ephemeral clone when not already in a matching git tree.
	tmp, err := os.MkdirTemp("", "adversary-pr-*")
	if err != nil {
		return out, err
	}
	out.TempDir = tmp
	cloneURL := pr.Base.Repo.CloneURL
	if cloneURL == "" {
		o, r := pr.OwnerRepo()
		cloneURL = fmt.Sprintf("https://github.com/%s/%s.git", o, r)
	}
	if progress != nil {
		fmt.Fprintf(progress, "Cloning PR to %s\n", tmp)
	}
	if err := exec.CommandContext(ctx, "git", "clone", "--depth", "50", cloneURL, tmp).Run(); err != nil {
		_ = os.RemoveAll(tmp)
		return out, fmt.Errorf("clone %s: %w", cloneURL, err)
	}
	_ = exec.CommandContext(ctx, "git", "-C", tmp, "fetch", "origin",
		fmt.Sprintf("pull/%d/head:refs/adversary/pr-%d", number, number)).Run()
	if err := exec.CommandContext(ctx, "git", "-C", tmp, "checkout", "--detach", out.HeadSHA).Run(); err != nil {
		_ = exec.CommandContext(ctx, "git", "-C", tmp, "fetch", "--depth", "200", "origin", out.HeadSHA).Run()
		if err2 := exec.CommandContext(ctx, "git", "-C", tmp, "checkout", "--detach", out.HeadSHA).Run(); err2 != nil {
			_ = os.RemoveAll(tmp)
			return out, fmt.Errorf("checkout PR head: %w", err2)
		}
	}
	out.Path = tmp
	return out, nil
}

type preparedWorktree struct{ path string }

func prepareWorktree(ctx context.Context, repoPath string, prNumber int, headSHA string, progress io.Writer) (preparedWorktree, error) {
	tmp, err := os.MkdirTemp("", "adversary-pr-wt-*")
	if err != nil {
		return preparedWorktree{}, err
	}
	// worktree add wants a non-existent path; MkdirTemp created one — remove it.
	_ = os.RemoveAll(tmp)
	if progress != nil {
		fmt.Fprintf(progress, "Using detached worktree of %s at %s\n", repoPath, tmp)
	}
	_ = exec.CommandContext(ctx, "git", "-C", repoPath, "fetch", "origin",
		fmt.Sprintf("pull/%d/head:refs/adversary/pr-%d", prNumber, prNumber)).Run()
	if err := exec.CommandContext(ctx, "git", "-C", repoPath, "worktree", "add", "--detach", tmp, headSHA).Run(); err != nil {
		// Fetch tip and retry.
		_ = exec.CommandContext(ctx, "git", "-C", repoPath, "fetch", "--depth", "200", "origin", headSHA).Run()
		if err2 := exec.CommandContext(ctx, "git", "-C", repoPath, "worktree", "add", "--detach", tmp, headSHA).Run(); err2 != nil {
			_ = os.RemoveAll(tmp)
			return preparedWorktree{}, fmt.Errorf("git worktree add: %w", err2)
		}
	}
	return preparedWorktree{path: tmp}, nil
}

// CleanupWorkspace removes an ephemeral PR workspace.
// When worktreeRoot is set, removes the linked worktree; otherwise RemoveAll tempDir.
func CleanupWorkspace(path, tempDir, worktreeRoot string) {
	if strings.TrimSpace(tempDir) == "" {
		return
	}
	if strings.TrimSpace(worktreeRoot) != "" {
		_ = exec.Command("git", "-C", worktreeRoot, "worktree", "remove", "--force", tempDir).Run()
	}
	_ = os.RemoveAll(tempDir)
}

// CleanupTempDir removes an ephemeral PR workspace (clone-only helper).
func CleanupTempDir(dir string) {
	CleanupWorkspace("", dir, "")
}

func isGitRepo(path string) bool {
	st, err := os.Stat(filepath.Join(path, ".git"))
	return err == nil && (st.IsDir() || st.Mode().IsRegular())
}

func shortSHA(s string) string {
	if len(s) > 7 {
		return s[:7]
	}
	return s
}

// ActionsContext returns owner/repo and PR number from common GitHub Actions env.
func ActionsContext(lookup func(string) (string, bool)) (repo string, pr int) {
	if lookup == nil {
		return "", 0
	}
	if r, ok := lookup("GITHUB_REPOSITORY"); ok {
		repo = strings.TrimSpace(r)
	}
	if ref, ok := lookup("GITHUB_REF"); ok {
		if strings.HasPrefix(ref, "refs/pull/") {
			parts := strings.Split(ref, "/")
			if len(parts) >= 3 {
				n, _ := strconv.Atoi(parts[2])
				pr = n
			}
		}
	}
	return repo, pr
}
