package catalogapply

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/adversarylabs/adversary/internal/train/results"
	"github.com/adversarylabs/adversary/internal/train/workspace"
	"gopkg.in/yaml.v3"
)

func TestApplyExistingAdversaryWritesRuleOnce(t *testing.T) {
	root, state := t.TempDir(), t.TempDir()
	dir := filepath.Join(root, "adversaries", "operability")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	policy := filepath.Join(dir, "README.md")
	if err := os.WriteFile(policy, []byte("# Operability\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	saveResult(t, state, results.Result{ID: "candidate-1", Package: "operability", ProposedRule: "Log tenant-scoped failures.", CommentURL: "https://github.com/acme/api/pull/1#discussion_r2"})
	cfg := workspace.Config{Adversaries: workspace.AdversariesConfig{Root: filepath.Join(root, "adversaries")}}
	if err := Apply(context.Background(), state, root, cfg, "candidate-1"); err != nil {
		t.Fatal(err)
	}
	if err := Apply(context.Background(), state, root, cfg, "candidate-1"); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(policy)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(raw), "Log tenant-scoped failures.") != 1 || !strings.Contains(string(raw), "adversary-catalog-train:candidate-1") {
		t.Fatalf("policy:\n%s", raw)
	}
	row, err := results.Get(state, "candidate-1")
	if err != nil || row.Status != results.StatusApplied || row.AppliedPath != policy {
		t.Fatalf("row=%+v err=%v", row, err)
	}
}

func TestApplyNewAdversaryCreatesPolicyAndManifestEntry(t *testing.T) {
	root, state := t.TempDir(), t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "adversaries"), 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := "apiVersion: adversarylabs.dev/v1alpha1\nkind: AdversaryCatalog\nspec:\n  adversaries: []\n"
	if err := os.WriteFile(filepath.Join(root, "adversarylabs.yaml"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	saveResult(t, state, results.Result{
		ID: "candidate-2", Package: "release-contracts", ProposedRule: "Keep release channels synchronized.",
		AdversaryMission: "Protect private release channel contracts.",
	})
	cfg := workspace.Config{Adversaries: workspace.AdversariesConfig{Root: filepath.Join(root, "adversaries")}}
	if err := Apply(context.Background(), state, root, cfg, "candidate-2"); err != nil {
		t.Fatal(err)
	}
	policy, err := os.ReadFile(filepath.Join(root, "adversaries", "release-contracts", "README.md"))
	if err != nil || !strings.Contains(string(policy), "Keep release channels synchronized.") {
		t.Fatalf("policy=%q err=%v", policy, err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "adversarylabs.yaml"))
	if err != nil || !strings.Contains(string(raw), "id: release-contracts") || !strings.Contains(string(raw), "Protect private release channel contracts.") {
		t.Fatalf("manifest=%q err=%v", raw, err)
	}
}

func TestCreatePullRequestUsesIsolatedWorktree(t *testing.T) {
	root, state := t.TempDir(), t.TempDir()
	remote := filepath.Join(t.TempDir(), "catalog.git")
	runGit(t, "", "init", "--bare", "--initial-branch=main", remote)
	runGit(t, "", "init", "--initial-branch=main", root)
	runGit(t, root, "config", "user.name", "Catalog Trainer")
	runGit(t, root, "config", "user.email", "catalog@example.com")
	dir := filepath.Join(root, "adversaries", "operability")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	policy := filepath.Join(dir, "README.md")
	if err := os.WriteFile(policy, []byte("# Operability\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "adversarylabs.yaml"), []byte("apiVersion: adversarylabs.dev/v1alpha1\nkind: AdversaryCatalog\nspec:\n  adversaries: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(t, root, "add", "-A")
	runGit(t, root, "commit", "-m", "Initial catalog")
	runGit(t, root, "remote", "add", "origin", remote)
	runGit(t, root, "push", "-u", "origin", "main")
	runGit(t, root, "remote", "set-head", "origin", "main")

	saveResult(t, state, results.Result{
		ID: "candidate-3", Package: "operability", ProposedRule: "Return an actionable recovery step.",
		CommentURL: "https://github.com/acme/api/pull/9#discussion_r4",
	})
	calledGH := false
	planner := func(_ context.Context, request ChangeRequest) (ChangePlan, error) {
		return ChangePlan{Summary: "Teach actionable failures", Files: []ChangeFile{
			{Path: "adversaries/operability/README.md", Content: "# Operability\n\n## Review for\n\n- Return actionable recovery details to users.\n"},
			{Path: "adversaries/operability/tests/candidate-3.yaml", Content: regressionYAML(request)},
		}}, nil
	}
	runner := func(ctx context.Context, dir, name string, args ...string) ([]byte, error) {
		if name == "gh" {
			calledGH = true
			if !strings.Contains(strings.Join(args, " "), "--base main") {
				t.Fatalf("gh args=%q", args)
			}
			return []byte("https://github.com/acme/catalog/pull/17\n"), nil
		}
		if name == "npm" {
			if len(args) > 0 && args[0] == "ci" {
				dependency := filepath.Join(dir, "node_modules", "transitive-package", "index.js")
				if err := os.MkdirAll(filepath.Dir(dependency), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(dependency, []byte("generated dependency\n"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			return []byte("ok\n"), nil
		}
		if len(args) > 0 && (args[0] == "validate" || args[0] == "pack") {
			return []byte("ok\n"), nil
		}
		command := exec.CommandContext(ctx, name, args...)
		command.Dir = dir
		return command.CombinedOutput()
	}
	// Absolute catalog roots must be safely rebased into the temporary worktree,
	// never followed back into the current checkout.
	cfg := workspace.Config{Adversaries: workspace.AdversariesConfig{Root: filepath.Join(root, "adversaries")}}
	if err := createPullRequest(context.Background(), state, root, cfg, "candidate-3", planner, runner); err != nil {
		t.Fatal(err)
	}
	if !calledGH {
		t.Fatal("gh pr create was not called")
	}
	current, err := os.ReadFile(policy)
	if err != nil || strings.Contains(string(current), "actionable recovery") {
		t.Fatalf("current checkout changed: %q err=%v", current, err)
	}
	row, err := results.Get(state, "candidate-3")
	if err != nil {
		t.Fatal(err)
	}
	if row.Status != results.StatusProposed || row.CatalogPRURL != "https://github.com/acme/catalog/pull/17" || row.Branch == "" || row.AppliedPath != "adversaries/operability/README.md" {
		t.Fatalf("row=%+v", row)
	}
	proposed := runGit(t, "", "--git-dir", remote, "show", "refs/heads/"+row.Branch+":adversaries/operability/README.md")
	if !strings.Contains(proposed, "Return actionable recovery details") {
		t.Fatalf("proposed policy:\n%s", proposed)
	}
	regression := runGit(t, "", "--git-dir", remote, "show", "refs/heads/"+row.Branch+":adversaries/operability/tests/candidate-3.yaml")
	if !strings.Contains(regression, "expected: no_finding") || !strings.Contains(regression, "discussion_r4") {
		t.Fatalf("proposed regression:\n%s", regression)
	}
	manifest := runGit(t, "", "--git-dir", remote, "show", "refs/heads/"+row.Branch+":adversaries/operability/adversary.yaml")
	source := runGit(t, "", "--git-dir", remote, "show", "refs/heads/"+row.Branch+":adversaries/operability/src/index.ts")
	if !strings.Contains(manifest, "runtime:") || !strings.Contains(source, "reviewPolicy") {
		t.Fatalf("generated adversary is not runnable:\n%s\n%s", manifest, source)
	}
	tree := runGit(t, "", "--git-dir", remote, "ls-tree", "-r", "--name-only", "refs/heads/"+row.Branch)
	if strings.Contains(tree, "node_modules/") {
		t.Fatalf("catalog PR committed installed dependencies:\n%s", tree)
	}
}

func TestApplyPlannedRejectsBookkeepingOnlyChange(t *testing.T) {
	root, state := t.TempDir(), t.TempDir()
	dir := filepath.Join(root, "adversaries", "operability")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("# Operability\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	saveResult(t, state, results.Result{ID: "candidate-4", Package: "operability", ProposedRule: "Show actionable errors."})
	cfg := workspace.Config{Adversaries: workspace.AdversariesConfig{Root: filepath.Join(root, "adversaries")}}
	planner := func(context.Context, ChangeRequest) (ChangePlan, error) {
		return ChangePlan{Files: []ChangeFile{
			{Path: "adversaries/operability/README.md", Content: "# Operability\n\n## Learned rules\n- Show actionable errors.\n"},
			{Path: "adversaries/operability/notes.md", Content: "candidate-4\n"},
		}}, nil
	}
	err := ApplyPlanned(context.Background(), state, root, cfg, "candidate-4", planner)
	if err == nil || !strings.Contains(err.Error(), "regression coverage") {
		t.Fatalf("expected regression error, got %v", err)
	}
}

func TestResolveNPMUsesNVMBinWhenProcessPATHIsMinimal(t *testing.T) {
	bin := t.TempDir()
	name := "npm"
	if runtime.GOOS == "windows" {
		name = "npm.cmd"
	}
	path := filepath.Join(bin, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", t.TempDir())
	t.Setenv("NVM_BIN", bin)
	resolved, err := resolveNPM(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if resolved != path {
		t.Fatalf("resolved=%q want %q", resolved, path)
	}
}

func TestExecCommandKeepsAbsoluteLaunchersSiblingRuntimeOnPATH(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shebang behavior is Unix-specific")
	}
	bin := t.TempDir()
	node := filepath.Join(bin, "node")
	if err := os.WriteFile(node, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	npm := filepath.Join(bin, "npm")
	if err := os.WriteFile(npm, []byte("#!/usr/bin/env node\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", t.TempDir())
	if output, err := execCommand(context.Background(), t.TempDir(), npm, "--version"); err != nil {
		t.Fatalf("absolute npm launcher could not find sibling node: %v\n%s", err, output)
	}
}

func regressionYAML(request ChangeRequest) string {
	return "version: 1\n" +
		"candidate_id: " + request.CandidateID + "\n" +
		"adversary: " + request.Adversary + "\n" +
		"evidence: " + request.Evidence + "\n" +
		"rule: " + request.ProposedRule + "\n" +
		"cases:\n" +
		"  - name: reports generic failures\n" +
		"    review_input: user sees an error without recovery detail\n" +
		"    expected: finding\n" +
		"    reason: the failure is not actionable\n" +
		"  - name: accepts actionable failures\n" +
		"    review_input: user sees the cause and recovery command\n" +
		"    expected: no_finding\n" +
		"    reason: actionable context is preserved\n"
}

func TestCanonicalRegressionRepairsColonInPlainScalar(t *testing.T) {
	row := results.Result{
		ID: "api-boundary-and-logging", Package: "engineering-conventions",
		CommentURL: "https://github.com/acme/api/pull/42#discussion_r9",
	}
	raw := []byte(`version: 1
candidate_id: api-boundary-and-logging
adversary: engineering-conventions
evidence: https://github.com/acme/api/pull/42#discussion_r9
rule: At API boundaries: preserve actionable errors and log context
cases:
  - name: reports missing context
    review_input: Handler failure: returns a generic message without logging the cause
    expected: finding
    reason: The boundary loses context: operators cannot diagnose it
  - name: accepts useful context
    review_input: Handler preserves the cause and logs a safe request identifier
    expected: no_finding
    reason: The user and operator both have actionable context
`)
	canonical, err := canonicalRegression(raw, row)
	if err != nil {
		t.Fatal(err)
	}
	var spec regressionSpec
	if err := yaml.Unmarshal(canonical, &spec); err != nil {
		t.Fatalf("canonical regression is invalid: %v\n%s", err, canonical)
	}
	if spec.Rule != "At API boundaries: preserve actionable errors and log context" || len(spec.Cases) != 2 || !strings.Contains(spec.Cases[0].Input, "Handler failure:") {
		t.Fatalf("repaired regression lost content: %+v", spec)
	}
}

func runGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	command := exec.Command("git", args...)
	command.Dir = dir
	out, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

func saveResult(t *testing.T, state string, row results.Result) {
	t.Helper()
	row.Kind = results.KindHuman
	row.Status = results.StatusNew
	row.Summary = "Human review evidence"
	row.CreatedAt = time.Now().UTC()
	if err := results.SaveResult(state, row); err != nil {
		t.Fatal(err)
	}
}
