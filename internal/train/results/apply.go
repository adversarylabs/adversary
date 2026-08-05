package results

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// ApplyOptions controls writing a result into a local package repo.
type ApplyOptions struct {
	// PackagePath is the absolute path to the local adversary package.
	PackagePath string
	// CreateBranch when true runs git checkout -b and commit (if .git present).
	CreateBranch bool
	// Branch name override (default train/<package>/<id>).
	Branch string
}

// ApplyResult is what apply wrote.
type ApplyResult struct {
	ID          string
	Path        string
	Branch      string
	Committed   bool
	AlreadyDone bool
}

// Apply writes the draft into the package and marks the result applied.
// Default: docs/train-drafts/<id>.md under the package. Optional git branch+commit.
func Apply(stateRoot, id string, opts ApplyOptions) (ApplyResult, error) {
	r, err := Get(stateRoot, id)
	if err != nil {
		return ApplyResult{}, err
	}
	if r.Status == StatusApplied {
		return ApplyResult{ID: r.ID, Path: r.AppliedPath, Branch: r.Branch, AlreadyDone: true}, nil
	}
	if opts.PackagePath == "" {
		return ApplyResult{}, fmt.Errorf("package path required for apply")
	}
	abs, err := filepath.Abs(opts.PackagePath)
	if err != nil {
		return ApplyResult{}, err
	}
	st, err := os.Stat(abs)
	if err != nil || !st.IsDir() {
		return ApplyResult{}, fmt.Errorf("package path not a directory: %s", abs)
	}

	draftDir := filepath.Join(abs, "docs", "train-drafts")
	if err := os.MkdirAll(draftDir, 0o755); err != nil {
		return ApplyResult{}, err
	}
	outPath := filepath.Join(draftDir, r.ID+".md")
	body := formatApplyMarkdown(r)
	if err := os.WriteFile(outPath, []byte(body), 0o644); err != nil {
		return ApplyResult{}, err
	}

	ar := ApplyResult{ID: r.ID, Path: outPath}
	branch := opts.Branch
	if branch == "" {
		pkg := r.Package
		if pkg == "" {
			pkg = "package"
		}
		branch = fmt.Sprintf("train/%s/%s", sanitizeBranch(pkg), r.ID)
	}

	if opts.CreateBranch {
		if committed, b, err := gitCommitDraft(abs, branch, outPath, r); err == nil {
			ar.Committed = committed
			ar.Branch = b
		}
		// git failures are non-fatal: draft file still applied
	}

	r.Status = StatusApplied
	r.AppliedAt = time.Now().UTC()
	r.AppliedPath = outPath
	r.Branch = ar.Branch
	if err := SaveResult(stateRoot, r); err != nil {
		return ar, err
	}
	return ar, nil
}

// Dismiss marks a result dismissed (not applied).
func Dismiss(stateRoot, id string) error {
	r, err := Get(stateRoot, id)
	if err != nil {
		return err
	}
	r.Status = StatusDismissed
	return SaveResult(stateRoot, r)
}

func formatApplyMarkdown(r Result) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Train draft %s\n\n", r.ID)
	fmt.Fprintf(&b, "- **Package:** `%s`\n", r.Package)
	fmt.Fprintf(&b, "- **Kind:** %s — %s\n", KindLabel(r.Kind), KindExplain(r.Kind, r.Status))
	fmt.Fprintf(&b, "- **Summary:** %s\n", r.Summary)
	if r.PRURL != "" {
		fmt.Fprintf(&b, "- **PR:** %s\n", r.PRURL)
	}
	fmt.Fprintf(&b, "- **Run:** `%s`\n", r.RunID)
	fmt.Fprintf(&b, "\n_Applied by `adversary train results apply`. Review before merging into prompts/scope._\n\n")
	if r.Title != "" {
		fmt.Fprintf(&b, "## %s\n\n", r.Title)
	}
	if r.DraftBody != "" {
		b.WriteString(r.DraftBody)
		if !strings.HasSuffix(r.DraftBody, "\n") {
			b.WriteByte('\n')
		}
	}
	return b.String()
}

func sanitizeBranch(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '/' {
			b.WriteRune(r)
		} else if r == ' ' || r == ':' {
			b.WriteByte('-')
		}
	}
	out := b.String()
	if out == "" {
		return "pkg"
	}
	return out
}

func gitCommitDraft(repo, branch, filePath string, r Result) (bool, string, error) {
	if _, err := os.Stat(filepath.Join(repo, ".git")); err != nil {
		return false, "", err
	}
	if _, err := exec.LookPath("git"); err != nil {
		return false, "", err
	}
	// Create / switch branch
	_ = exec.Command("git", "-C", repo, "checkout", "-B", branch).Run()
	rel, err := filepath.Rel(repo, filePath)
	if err != nil {
		rel = filePath
	}
	if err := exec.Command("git", "-C", repo, "add", "--", rel).Run(); err != nil {
		return false, branch, err
	}
	msg := fmt.Sprintf("train: apply draft %s — %s", r.ID, soft(r.Summary, 60))
	cmd := exec.Command("git", "-C", repo, "commit", "-m", msg)
	if out, err := cmd.CombinedOutput(); err != nil {
		// nothing to commit is ok
		if strings.Contains(string(out), "nothing to commit") {
			return false, branch, nil
		}
		return false, branch, fmt.Errorf("git commit: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return true, branch, nil
}
