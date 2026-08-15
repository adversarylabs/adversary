package checkout

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestPrepareSyntheticTwoCommitRepo(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	root := t.TempDir()
	res := PrepareForCase(root, "", "", "case-syn", "aaa", "bbb", true)
	if res.Path == "" || res.Method != "synthetic" {
		t.Fatalf("%+v", res)
	}
	base, head := ResolveBaseHeadRefs(res)
	if base != "review-base" || head != "review-head" {
		t.Fatalf("refs %s %s", base, head)
	}
	cmd := exec.Command("git", "diff", "--name-only", "review-base", "review-head")
	cmd.Dir = res.Path
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("diff: %v %s", err, out)
	}
	if _, err := os.Stat(filepath.Join(res.Path, "changed.go")); err != nil {
		t.Fatal(err)
	}
}

func TestChangedFileEvidenceReturnsBoundedReviewedPatch(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	root := t.TempDir()
	res := PrepareForCase(root, "", "", "case-evidence", "aaa", "bbb", true)
	diff, err := ChangedFileEvidence(context.Background(), res.Path, "HEAD~1", "HEAD", "changed.go", 4_000)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(diff, "+func Worker() {}") || !strings.Contains(diff, "diff --git a/changed.go") {
		t.Fatalf("unexpected changed-file evidence:\n%s", diff)
	}
	if other, err := ChangedFileEvidence(context.Background(), res.Path, "HEAD~1", "HEAD", "README.md", 20); err != nil || !strings.Contains(other, "[diff truncated]") {
		t.Fatalf("bounded evidence=%q err=%v", other, err)
	}
}

func TestPrepareLiveWithoutNetworkRefusesSynthetic(t *testing.T) {
	root := t.TempDir()
	res := PrepareForCase(root, "open-telemetry", "opentelemetry-go", "case-x",
		"0000000000000000000000000000000000000001",
		"0000000000000000000000000000000000000002",
		false)
	if res.Path != "" {
		t.Fatalf("expected empty path when fetch fails and synthetic disallowed, got %+v", res)
	}
	if res.Error == "" {
		t.Fatal("expected error")
	}
}

func TestEnsureDiffableDeepensExactReviewedTips(t *testing.T) {
	var calls []string
	run := func(args ...string) ([]byte, error) {
		calls = append(calls, strings.Join(args, " "))
		return nil, nil
	}

	err := ensureDiffable(t.TempDir(), "base-reviewed-sha", "head-reviewed-sha", run)
	if err == nil {
		t.Fatal("expected an empty repository to remain non-diffable")
	}
	for _, want := range []string{
		"git fetch --depth 20 origin head-reviewed-sha",
		"git fetch --depth 20 origin base-reviewed-sha",
	} {
		if !slices.Contains(calls, want) {
			t.Fatalf("missing exact-tip fetch %q in %v", want, calls)
		}
	}
	if slices.Contains(calls, "git fetch --deepen 20 origin") {
		t.Fatalf("must not deepen unrelated remote branches: %v", calls)
	}
}

// Integration: real GitHub SHAs from a small public commit pair must support git diff.
func TestFetchRealSHAsDiffable(t *testing.T) {
	if testing.Short() {
		t.Skip("network")
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	// Two commits from opentelemetry-go PR history (known public).
	// Use SHAs from a recent known-good fetch if env not set.
	base := os.Getenv("FACTORY_TEST_BASE_SHA")
	head := os.Getenv("FACTORY_TEST_HEAD_SHA")
	if base == "" || head == "" {
		// Resolve via gh if available: latest merged PR base/head
		out, err := exec.Command("gh", "api",
			"repos/open-telemetry/opentelemetry-go/pulls?state=closed&per_page=5",
			"--jq", `[.[] | select(.merged_at != null)][0] | "\(.base.sha) \(.head.sha)"`).CombinedOutput()
		if err != nil {
			t.Skipf("cannot resolve real SHAs: %v %s", err, out)
		}
		var b, h string
		if _, err := fmtSscanf(string(out), &b, &h); err != nil {
			t.Skipf("parse shas: %q", out)
		}
		base, head = b, h
	}
	root := t.TempDir()
	res := PrepareForCase(root, "open-telemetry", "opentelemetry-go", "live-diff", base, head, false)
	if res.Path == "" {
		t.Fatalf("prepare failed: %s", res.Error)
	}
	if err := checkDiffable(res.Path, base, head); err != nil {
		t.Fatal(err)
	}
}

func fmtSscanf(s string, base, head *string) (int, error) {
	fields := splitFields(s)
	if len(fields) < 2 {
		return 0, os.ErrInvalid
	}
	*base = fields[0]
	*head = fields[1]
	return 2, nil
}

func splitFields(s string) []string {
	var out []string
	start := -1
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' || s[i] == '\n' || s[i] == '\t' || s[i] == '\r' {
			if start >= 0 {
				out = append(out, s[start:i])
				start = -1
			}
			continue
		}
		if start < 0 {
			start = i
		}
	}
	if start >= 0 {
		out = append(out, s[start:])
	}
	return out
}
