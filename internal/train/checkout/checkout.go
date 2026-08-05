package checkout

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Result of preparing a reviewer git workspace with exact base/head SHAs.
type Result struct {
	Path    string
	Method  string // fetch | synthetic | empty
	BaseSHA string
	HeadSHA string
	Error   string
}

// PrepareForCase materializes a directory adversary can review with --base/--head.
func PrepareForCase(dataRoot, owner, repo, caseID, baseSHA, headSHA string, allowSynthetic bool) Result {
	res := Result{BaseSHA: baseSHA, HeadSHA: headSHA}
	if baseSHA == "" || headSHA == "" {
		res.Error = "missing base or head SHA"
		return res
	}
	dest := filepath.Join(dataRoot, "checkouts", caseID)
	_ = os.RemoveAll(dest)
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		res.Error = err.Error()
		return res
	}

	if owner != "" && repo != "" {
		if r, err := fetchSHAs(dest, owner, repo, baseSHA, headSHA); err == nil {
			return r
		} else {
			res.Error = err.Error()
			if !allowSynthetic {
				_ = os.RemoveAll(dest)
				return res
			}
		}
	}

	if allowSynthetic {
		if err := syntheticTwoCommitRepo(dest); err != nil {
			res.Error = err.Error()
			_ = os.RemoveAll(dest)
			return res
		}
		res.Path = dest
		res.Method = "synthetic"
		res.Error = ""
		return res
	}

	_ = os.RemoveAll(dest)
	if res.Error == "" {
		res.Error = "checkout not prepared"
	}
	return res
}

func fetchSHAs(dest, owner, repo, baseSHA, headSHA string) (Result, error) {
	url := fmt.Sprintf("https://github.com/%s/%s.git", owner, repo)
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return Result{}, err
	}

	run := func(args ...string) ([]byte, error) {
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Dir = dest
		return cmd.CombinedOutput()
	}
	must := func(args ...string) error {
		out, err := run(args...)
		if err != nil {
			return fmt.Errorf("%s: %w (%s)", strings.Join(args, " "), err, truncate(string(out), 400))
		}
		return nil
	}

	// Full objects (no blob:none). Partial clones break git diff with missing trees/blobs.
	if err := must("git", "init"); err != nil {
		return Result{}, err
	}
	if err := must("git", "remote", "add", "origin", url); err != nil {
		return Result{}, err
	}
	// Fetch both tips fully (trees + blobs).
	if err := must("git", "fetch", "--depth", "1", "origin", baseSHA); err != nil {
		return Result{}, err
	}
	if err := must("git", "fetch", "--depth", "1", "origin", headSHA); err != nil {
		return Result{}, err
	}
	if err := must("git", "update-ref", "refs/heads/review-base", baseSHA); err != nil {
		return Result{}, err
	}
	if err := must("git", "update-ref", "refs/heads/review-head", headSHA); err != nil {
		return Result{}, err
	}

	// Adversary requires a merge-base between base and head. Shallow depth-1 of two
	// tips often has none — deepen until merge-base and diff work.
	if err := ensureDiffable(dest, baseSHA, headSHA, run); err != nil {
		return Result{}, err
	}

	if err := must("git", "checkout", "-f", "review-head"); err != nil {
		return Result{}, err
	}
	_, _ = run("git", "remote", "remove", "origin")

	return Result{Path: dest, Method: "fetch", BaseSHA: baseSHA, HeadSHA: headSHA}, nil
}

func ensureDiffable(repo, baseSHA, headSHA string, run func(args ...string) ([]byte, error)) error {
	var last error
	// deepen progressively; re-fetch tips with larger depth when deepen is not enough
	depths := []string{"20", "50", "100", "200", "500", "1000"}
	for i, d := range depths {
		if err := checkDiffable(repo, baseSHA, headSHA); err == nil {
			return nil
		} else {
			last = err
		}
		// Prefer deepen when we still have a remote.
		if _, err := run("git", "fetch", "--deepen", d, "origin"); err != nil {
			// Fallback: re-fetch each tip at greater depth
			_, _ = run("git", "fetch", "--depth", d, "origin", headSHA)
			_, _ = run("git", "fetch", "--depth", d, "origin", baseSHA)
		}
		// Also try fetching the merge-base path via compare-style: fetch head with enough history
		if i == len(depths)-1 {
			// Last resort: unshallow if the repo is shallow
			_, _ = run("git", "fetch", "--unshallow", "origin")
		}
	}
	if err := checkDiffable(repo, baseSHA, headSHA); err == nil {
		return nil
	}
	return fmt.Errorf("could not make base/head diffable: %w", last)
}

func checkDiffable(repo, baseSHA, headSHA string) error {
	// merge-base (adversary requires this)
	cmd := exec.Command("git", "merge-base", baseSHA, headSHA)
	cmd.Dir = repo
	out, err := cmd.CombinedOutput()
	if err != nil || len(bytes.TrimSpace(out)) == 0 {
		return fmt.Errorf("no merge-base: %w (%s)", err, truncate(string(out), 200))
	}
	// full diff readability
	cmd = exec.Command("git", "diff", "--name-only", baseSHA, headSHA)
	cmd.Dir = repo
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("git diff: %w (%s)", err, truncate(string(out), 300))
	}
	return nil
}

func syntheticTwoCommitRepo(dest string) error {
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return err
	}
	run := func(args ...string) error {
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Dir = dest
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("%v: %w (%s)", args, err, truncate(string(out), 200))
		}
		return nil
	}
	if err := run("git", "init"); err != nil {
		return err
	}
	if err := run("git", "config", "user.email", "factory@local"); err != nil {
		return err
	}
	if err := run("git", "config", "user.name", "factory"); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dest, "README.md"), []byte("base\n"), 0o644); err != nil {
		return err
	}
	if err := run("git", "add", "README.md"); err != nil {
		return err
	}
	if err := run("git", "commit", "-m", "base"); err != nil {
		return err
	}
	if err := run("git", "branch", "-M", "review-base"); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dest, "README.md"), []byte("base\nhead change\n"), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dest, "changed.go"), []byte("package p\n// worker lifecycle\nfunc Worker() {}\n"), 0o644); err != nil {
		return err
	}
	if err := run("git", "add", "."); err != nil {
		return err
	}
	if err := run("git", "commit", "-m", "head"); err != nil {
		return err
	}
	if err := run("git", "branch", "review-head"); err != nil {
		return err
	}
	return nil
}

// ResolveBaseHeadRefs returns ref names usable with adversary --base/--head after Prepare.
func ResolveBaseHeadRefs(checkout Result) (base, head string) {
	if checkout.Method == "fetch" {
		return checkout.BaseSHA, checkout.HeadSHA
	}
	return "review-base", "review-head"
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
