package checkout

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
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
	return PrepareForCaseContext(context.Background(), dataRoot, owner, repo, caseID, baseSHA, headSHA, allowSynthetic)
}

// PrepareForCaseContext is PrepareForCase with cancelable git/gh work.
func PrepareForCaseContext(ctx context.Context, dataRoot, owner, repo, caseID, baseSHA, headSHA string, allowSynthetic bool) Result {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return Result{Error: "checkout interrupted: " + err.Error()}
	}
	// Delegate to original body by temporarily shadowing — keep single implementation below.
	return prepareForCase(ctx, dataRoot, owner, repo, caseID, baseSHA, headSHA, allowSynthetic)
}

func prepareForCase(ctx context.Context, dataRoot, owner, repo, caseID, baseSHA, headSHA string, allowSynthetic bool) Result {
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
		if r, err := fetchSHAs(ctx, dest, owner, repo, baseSHA, headSHA); err == nil {
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

func fetchSHAs(ctx context.Context, dest, owner, repo, baseSHA, headSHA string) (Result, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return Result{}, fmt.Errorf("checkout interrupted: %w", err)
	}
	url := fmt.Sprintf("https://github.com/%s/%s.git", owner, repo)
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return Result{}, err
	}

	run := func(args ...string) ([]byte, error) {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("checkout interrupted: %w", err)
		}
		cmd := exec.CommandContext(ctx, args[0], args[1:]...)
		cmd.Dir = dest
		out, err := cmd.CombinedOutput()
		if ctx.Err() != nil {
			return out, fmt.Errorf("checkout interrupted: %w", ctx.Err())
		}
		return out, err
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
	// Deepen the exact reviewed tips progressively. A plain `git fetch --deepen`
	// follows the remote's configured branch refspec, so it can deepen current
	// branches while leaving SHA-fetched historical PR tips at depth 1.
	depths := []string{"20", "50", "100", "200", "500", "1000"}
	for _, d := range depths {
		if err := checkDiffable(repo, baseSHA, headSHA); err == nil {
			return nil
		} else {
			last = err
		}
		_, _ = run("git", "fetch", "--depth", d, "origin", headSHA)
		_, _ = run("git", "fetch", "--depth", d, "origin", baseSHA)
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

// ChangedFileEvidence returns a bounded patch for one changed file, retaining
// the hunk that contains targetLine when the complete patch is too large.
func ChangedFileEvidence(ctx context.Context, repo, baseRef, headRef, file string, targetLine, maxBytes int) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if repo == "" || baseRef == "" || headRef == "" || file == "" {
		return "", fmt.Errorf("repository, refs, and file are required")
	}
	cmd := exec.CommandContext(ctx, "git", "diff", "--no-ext-diff", "--unified=40", baseRef, headRef, "--", file)
	cmd.Dir = repo
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("git diff changed-file evidence: %w (%s)", err, truncate(string(out), 300))
	}
	out = boundChangedFileEvidence(out, targetLine, maxBytes)
	return strings.TrimSpace(string(out)), nil
}

var diffHunkHeader = regexp.MustCompile(`(?m)^@@ -[0-9]+(?:,[0-9]+)? \+([0-9]+)(?:,([0-9]+))? @@`)

func boundChangedFileEvidence(diff []byte, targetLine, maxBytes int) []byte {
	if maxBytes <= 0 || len(diff) <= maxBytes {
		return diff
	}
	matches := diffHunkHeader.FindAllSubmatchIndex(diff, -1)
	if targetLine <= 0 || len(matches) == 0 {
		return append(append([]byte(nil), diff[:maxBytes]...), []byte("\n[diff truncated]\n")...)
	}

	selected := -1
	selectedDistance := int(^uint(0) >> 1)
	for i, match := range matches {
		start, _ := strconv.Atoi(string(diff[match[2]:match[3]]))
		count := 1
		if match[4] >= 0 {
			count, _ = strconv.Atoi(string(diff[match[4]:match[5]]))
		}
		end := start + count
		if count == 0 {
			end = start + 1
		}
		distance := start - targetLine
		if targetLine >= start && targetLine < end {
			selected = i
			break
		}
		if distance < 0 {
			distance = -distance
		}
		if distance < selectedDistance {
			selected, selectedDistance = i, distance
		}
	}

	firstHunk := matches[0][0]
	start := matches[selected][0]
	end := len(diff)
	if selected+1 < len(matches) {
		end = matches[selected+1][0]
	}
	result := append([]byte(nil), diff[:firstHunk]...)
	if selected > 0 {
		result = append(result, []byte("[earlier diff hunks omitted]\n")...)
	}
	result = append(result, diff[start:end]...)
	if selected+1 < len(matches) {
		result = append(result, []byte("[later diff hunks omitted]\n")...)
	}
	if len(result) <= maxBytes {
		return result
	}

	// A single very large hunk can still exceed the budget. Keep a window
	// around the reviewed head-side line instead of falling back to its prefix.
	return boundDiffHunkAroundLine(diff[:firstHunk], diff[start:end], targetLine, maxBytes)
}

func boundDiffHunkAroundLine(fileHeader, hunk []byte, targetLine, maxBytes int) []byte {
	headerEnd := bytes.IndexByte(hunk, '\n') + 1
	if headerEnd <= 0 {
		return append(append([]byte(nil), hunk[:maxBytes]...), []byte("\n[diff truncated]\n")...)
	}
	match := diffHunkHeader.FindSubmatch(hunk[:headerEnd])
	line, _ := strconv.Atoi(string(match[1]))
	bodyLines := bytes.SplitAfter(hunk[headerEnd:], []byte("\n"))
	targetIndex := 0
	for i, patchLine := range bodyLines {
		if len(patchLine) > 0 && patchLine[0] != '-' && line == targetLine {
			targetIndex = i
			break
		}
		if len(patchLine) > 0 && patchLine[0] != '-' {
			line++
		}
	}
	fixed := append(append([]byte(nil), fileHeader...), hunk[:headerEnd]...)
	fixed = append(fixed, []byte("[diff excerpt centered on reviewed line]\n")...)
	remaining := maxBytes - len(fixed)
	if remaining <= 0 {
		return fixed
	}
	left, right := targetIndex, targetIndex+1
	used := len(bodyLines[targetIndex])
	for used < remaining && (left > 0 || right < len(bodyLines)) {
		if left > 0 && used+len(bodyLines[left-1]) <= remaining {
			left--
			used += len(bodyLines[left])
		}
		if right < len(bodyLines) && used+len(bodyLines[right]) <= remaining {
			used += len(bodyLines[right])
			right++
		}
		if (left == 0 || used+len(bodyLines[left-1]) > remaining) && (right == len(bodyLines) || used+len(bodyLines[right]) > remaining) {
			break
		}
	}
	for _, patchLine := range bodyLines[left:right] {
		fixed = append(fixed, patchLine...)
	}
	return fixed
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
