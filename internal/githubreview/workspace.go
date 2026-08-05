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
	Path    string // effective --path
	TempDir string // non-empty if ephemeral clone (caller should cleanup)
	BaseSHA string
	HeadSHA string
	Owner   string
	Repo    string
	Number  int
}

// PreparePRWorkspace resolves PR metadata and a local checkout for analysis.
// lookup is typically os.LookupEnv; pass a stub in tests.
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
		if progress != nil {
			fmt.Fprintf(progress, "Using local clone at %s\n", path)
		}
		_ = exec.CommandContext(ctx, "git", "-C", path, "fetch", "origin",
			fmt.Sprintf("pull/%d/head:refs/adversary/pr-%d", number, number)).Run()
		if err := exec.CommandContext(ctx, "git", "-C", path, "checkout", "--detach", out.HeadSHA).Run(); err != nil {
			if progress != nil {
				fmt.Fprintf(progress, "warning: could not checkout %s (%v); continuing with worktree\n", shortSHA(out.HeadSHA), err)
			}
		}
		out.Path = path
		return out, nil
	}

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

// CleanupTempDir removes an ephemeral PR workspace.
func CleanupTempDir(dir string) {
	if strings.TrimSpace(dir) != "" {
		_ = os.RemoveAll(dir)
	}
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
