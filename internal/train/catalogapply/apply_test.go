package catalogapply

import (
	"context"
	"errors"
	"fmt"
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
		return managedRulePlan(request, "actionable-errors"), nil
	}
	runner := func(ctx context.Context, dir, name string, args ...string) ([]byte, error) {
		if name == "gh" {
			calledGH = true
			joined := strings.Join(args, " ")
			if !strings.Contains(joined, "--base main") || !strings.Contains(joined, "--title Add actionable error checks to operability") {
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
	if err := createPullRequest(context.Background(), state, root, cfg, "candidate-3", planner, runner, nil); err != nil {
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
	if row.Status != results.StatusProposed || row.CatalogPRURL != "https://github.com/acme/catalog/pull/17" || row.Branch == "" || row.AppliedPath != "adversaries/operability/rules/actionable-errors/rule.yaml" {
		t.Fatalf("row=%+v", row)
	}
	proposed := runGit(t, "", "--git-dir", remote, "show", "refs/heads/"+row.Branch+":adversaries/operability/rules/actionable-errors/rule.yaml")
	if !strings.Contains(proposed, "Return actionable recovery details") {
		t.Fatalf("proposed policy:\n%s", proposed)
	}
	regression := runGit(t, "", "--git-dir", remote, "show", "refs/heads/"+row.Branch+":adversaries/operability/rules/actionable-errors/cases.yaml")
	if !strings.Contains(regression, "expected: no_finding") || !strings.Contains(regression, "discussion_r4") {
		t.Fatalf("proposed regression:\n%s", regression)
	}
	manifest := runGit(t, "", "--git-dir", remote, "show", "refs/heads/"+row.Branch+":adversaries/operability/adversary.yaml")
	source := runGit(t, "", "--git-dir", remote, "show", "refs/heads/"+row.Branch+":adversaries/operability/src/index.ts")
	commitTitle := strings.TrimSpace(runGit(t, "", "--git-dir", remote, "log", "-1", "--format=%s", "refs/heads/"+row.Branch))
	if !strings.Contains(manifest, "runtime:") || !strings.Contains(source, "reviewPolicy") {
		t.Fatalf("generated adversary is not runnable:\n%s\n%s", manifest, source)
	}
	if commitTitle != "Add actionable error checks to operability" {
		t.Fatalf("commit title=%q", commitTitle)
	}
	tree := runGit(t, "", "--git-dir", remote, "ls-tree", "-r", "--name-only", "refs/heads/"+row.Branch)
	if strings.Contains(tree, "node_modules/") {
		t.Fatalf("catalog PR committed installed dependencies:\n%s", tree)
	}
}

func managedRulePlan(request ChangeRequest, id string) ChangePlan {
	rule := fmt.Sprintf("version: 1\nid: %s\nsummary: Return actionable recovery details to users.\nguidance: Report changed code that hides a concrete failure; allow code that preserves actionable detail.\nseverity: medium\nconfidence: high\nevidence: %s\n", id, request.Evidence)
	cases := fmt.Sprintf("version: 1\nrule_id: %s\ncandidate_id: %s\nevidence: %s\ncases:\n  - name: hidden failure\n    review_input: The exact changed path hides the failure.\n    expected: finding\n    reason: The user cannot recover.\n  - name: actionable failure\n    review_input: The change displays the cause and recovery step.\n    expected: no_finding\n    reason: The error is actionable.\n", id, request.CandidateID, request.Evidence)
	base := "adversaries/" + request.Adversary + "/rules/" + id + "/"
	return ChangePlan{Summary: "Add actionable error checks to " + request.Adversary, Strategy: StrategyModelBacked, Files: []ChangeFile{{Path: base + "rule.yaml", Content: rule}, {Path: base + "cases.yaml", Content: cases}}}
}

func TestApplyPlannedRetriesQualityReviewWithRejectedPlan(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "adversaries"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "adversarylabs.yaml"), []byte("apiVersion: adversarylabs.dev/v1alpha1\nkind: AdversaryCatalog\nspec:\n  adversaries: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	row := results.Result{
		ID: "candidate-quality", Package: "reliability", ProposedRule: "Retry failed initialization.",
		AdversaryMission: "Catch reliability regressions.", CommentURL: "https://example.test/evidence",
	}
	calls := 0
	planner := func(_ context.Context, request ChangeRequest) (ChangePlan, error) {
		calls++
		if calls == 1 {
			if request.GenerationAttempt != 1 || request.MaxGenerationTurns != 8 || request.MaxQualityTurns != 2 {
				t.Fatalf("initial generation attempt metadata=%d/%d", request.GenerationAttempt, request.MaxGenerationTurns)
			}
			return ChangePlan{Summary: "Reject brittle initialization in reliability", Strategy: StrategyDeterministic, Files: []ChangeFile{
				{Path: "adversaries/reliability/README.md", Content: "# Reliability\n"},
				{Path: "adversaries/reliability/src/rules/lazy.ts", Content: "// brittle regex implementation\n"},
				{Path: "adversaries/reliability/test/lazy.test.ts", Content: "// weak fixture\n"},
			}}, fmt.Errorf("generated change deterministic quality review requested revision: inspect source structure")
		}
		if request.PreviousPlan == nil || len(request.PreviousPlan.Files) != 3 || !strings.Contains(request.PreviousPlan.Files[1].Content, "brittle regex") {
			t.Fatalf("quality repair omitted rejected generated plan: %+v", request.PreviousPlan)
		}
		if !strings.Contains(request.ValidationFeedback, "inspect source structure") {
			t.Fatalf("quality repair omitted critic feedback: %q", request.ValidationFeedback)
		}
		if request.GenerationAttempt != 2 || request.MaxGenerationTurns != 8 || request.MaxQualityTurns != 2 {
			t.Fatalf("repair generation attempt metadata=%d/%d", request.GenerationAttempt, request.MaxGenerationTurns)
		}
		return managedRulePlan(request, "retry-initialization"), nil
	}
	cfg := workspace.Config{Adversaries: workspace.AdversariesConfig{Root: filepath.Join(root, "adversaries")}}
	if _, err := applyPlannedCandidate(context.Background(), root, cfg, row, planner); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("planner calls=%d want 2", calls)
	}
}

func TestWriteManagedDeterministicPlanUsesCatalogExtensionPoint(t *testing.T) {
	root := t.TempDir()
	prefix := "adversaries/operability/"
	dir := filepath.Join(root, "adversaries", "operability")
	request := ChangeRequest{
		Adversary: "operability", Executable: true, PolicyDriven: true, ManagedRuntime: 1,
		EvidenceFile: "src/restore.ts",
		Files: []SourceFile{
			{Path: prefix + "README.md", Content: "# Operability\n"},
			{Path: prefix + "src/index.ts", Content: "import { registerDeterministicRules } from \"./deterministic.js\";\nregisterDeterministicRules(app);\n"},
			{Path: prefix + "src/deterministic.ts", Content: "export function registerDeterministicRules() {}\n"},
		},
	}
	plan := ChangePlan{Summary: "Enforce restore error paths in operability", Strategy: StrategyDeterministic, Files: []ChangeFile{
		{Path: prefix + "README.md", Content: "# Operability\n\n- Restore failures include recovery details.\n"},
		{Path: prefix + "src/deterministic.ts", Content: "import { registerRestoreRule } from \"./rules/restore-errors.js\";\nexport function registerDeterministicRules(app: unknown) { registerRestoreRule(app); }\n"},
		{Path: prefix + "src/rules/restore-errors.ts", Content: "export function registerRestoreRule(app: unknown) { void app; }\n"},
		{Path: prefix + "test/restore-errors.test.ts", Content: "import { createApp } from \"../src/index.ts\";\nconst evidencePath = \"src/restore.ts\"; const fixtureDirectory = \"/tmp/fixture\";\nvoid createApp().run({input:{source:{path:fixtureDirectory}}}); void evidencePath;\n"},
	}}
	for name, mutate := range map[string]func(*ChangePlan){
		"managed entrypoint": func(value *ChangePlan) {
			value.Files[1] = ChangeFile{Path: prefix + "src/index.ts", Content: "// replaced\n"}
		},
		"model call": func(value *ChangePlan) {
			value.Files[2].Content = "export function registerRestoreRule(ctx: any) { return ctx.model.review({}); }\n"
		},
		"read-only node fs mutation": func(value *ChangePlan) {
			value.Files[3].Content = "import * as fs from \"node:fs\";\nimport { createApp } from \"../src/index.ts\";\nconst evidencePath = \"src/restore.ts\";\n(fs as any).readFileSync = () => evidencePath;\nvoid createApp().run({});\n"
		},
		"evidence path tripwire": func(value *ChangePlan) {
			value.Files[2].Content = "export function registerRestoreRule(ctx: any) { if (ctx.change.changedFiles.includes(\"src/restore.ts\")) ctx.finding({}); }\n"
		},
		"literal evidence line": func(value *ChangePlan) {
			value.Files[2].Content = "export async function registerRestoreRule(ctx: any) { await ctx.loadInScopeSources(); ctx.finding({evidence: [{line: 257}]}); }\n"
		},
		"direct helper test": func(value *ChangePlan) {
			value.Files[3].Content = "import { createApp } from \"../src/index.ts\";\nimport { registerRestoreRule } from \"../src/rules/restore-errors.ts\";\nconst evidencePath = \"src/restore.ts\";\nvoid registerRestoreRule; void createApp().run({}); void evidencePath;\n"
		},
		"missing repository source input": func(value *ChangePlan) {
			value.Files[3].Content = "import { createApp } from \"../src/index.ts\";\nconst evidencePath = \"src/restore.ts\";\nvoid createApp().run({}); void evidencePath;\n"
		},
	} {
		t.Run("rejects "+name, func(t *testing.T) {
			invalid := plan
			invalid.Files = append([]ChangeFile(nil), plan.Files...)
			mutate(&invalid)
			if _, err := writeChangePlan(root, filepath.Join(root, "adversaries"), dir, results.Result{Package: "operability"}, request, invalid); err == nil {
				t.Fatalf("accepted deterministic plan with %s", name)
			}
		})
	}
	target, err := writeChangePlan(root, filepath.Join(root, "adversaries"), dir, results.Result{Package: "operability"}, request, plan)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(target) != "README.md" {
		t.Fatalf("target=%q", target)
	}
	if _, err := os.Stat(filepath.Join(dir, "src", "rules", "restore-errors.ts")); err != nil {
		t.Fatal(err)
	}
}

func TestWriteManagedGoDeterministicPlanRequiresSemanticQuery(t *testing.T) {
	root := t.TempDir()
	prefix := "adversaries/reliability/"
	dir := filepath.Join(root, "adversaries", "reliability")
	request := ChangeRequest{
		Adversary: "reliability", Executable: true, PolicyDriven: true, ManagedRuntime: 1,
		EvidenceFile: "pkg/store/resolver.go",
		Files: []SourceFile{
			{Path: prefix + "README.md", Content: "# Reliability\n"},
			{Path: prefix + "src/index.ts", Content: "import { registerDeterministicRules } from \"./deterministic.js\";\nregisterDeterministicRules(app);\n"},
			{Path: prefix + "src/deterministic.ts", Content: "export function registerDeterministicRules() {}\n"},
		},
	}
	semanticPlan := ChangePlan{Summary: "Reject poisoned lazy initialization in reliability", Strategy: StrategyDeterministic, Files: []ChangeFile{
		{Path: prefix + "README.md", Content: "# Reliability\n\n- Retry failed lazy initialization.\n"},
		{Path: prefix + "src/deterministic.ts", Content: "import { registerRule } from \"./rules/lazy.js\";\nexport function registerDeterministicRules(app: unknown) { registerRule(app); }\n"},
		{Path: prefix + "src/rules/lazy.ts", Content: "import { defineSemanticQuery } from \"@adversarylabs/sdk\";\nconst query = defineSemanticQuery({language:\"go\",within:\"function\",steps:[{kind:\"call\",capture:\"call\"}]});\nexport function registerRule(app: any) { app.rule(\"lazy\", (ctx: any) => ctx.repoGraph?.semanticMatches(query)); }\n"},
		{Path: prefix + "test/lazy.test.ts", Content: "import { createApp } from \"../src/index.ts\";\nconst fixtureDirectory = \"/tmp/fixture\"; const evidencePath = \"pkg/store/resolver.go\";\nconst repoGraph = { semanticMatches: () => [] };\nvoid createApp().run({input:{source:{path:fixtureDirectory}},repoGraph:repoGraph as any}); void evidencePath;\n"},
	}}
	if _, err := writeChangePlan(root, filepath.Join(root, "adversaries"), dir, results.Result{Package: "reliability"}, request, semanticPlan); err != nil {
		t.Fatal(err)
	}

	textPlan := semanticPlan
	textPlan.Files = append([]ChangeFile(nil), semanticPlan.Files...)
	textPlan.Files[2].Content = "export async function registerRule(app: any) { app.rule(\"lazy\", async (ctx: any) => ctx.loadInScopeSources()); }\n"
	if _, err := writeChangePlan(root, filepath.Join(root, "adversaries"), dir, results.Result{Package: "reliability"}, request, textPlan); err == nil || !strings.Contains(err.Error(), "may not parse source text") {
		t.Fatalf("expected source parsing rejection, got %v", err)
	}

	missingGraphTest := semanticPlan
	missingGraphTest.Files = append([]ChangeFile(nil), semanticPlan.Files...)
	missingGraphTest.Files[3].Content = "import { createApp } from \"../src/index.ts\";\nconst evidencePath = \"pkg/store/resolver.go\"; const fixtureDirectory = \"/tmp/fixture\";\nvoid createApp().run({input:{source:{path:fixtureDirectory}}}); void evidencePath;\n"
	if _, err := writeChangePlan(root, filepath.Join(root, "adversaries"), dir, results.Result{Package: "reliability"}, request, missingGraphTest); err == nil || !strings.Contains(err.Error(), "must inject semantic RepoGraph") {
		t.Fatalf("expected RepoGraph test rejection, got %v", err)
	}

	uncheckedQuery := semanticPlan
	uncheckedQuery.Files = append([]ChangeFile(nil), semanticPlan.Files...)
	uncheckedQuery.Files[2].Content = "export function registerRule(app: any) { app.rule(\"lazy\", (ctx: any) => ctx.repoGraph?.semanticMatches({language:\"go\",within:\"function\",steps:[]})); }\n"
	if _, err := writeChangePlan(root, filepath.Join(root, "adversaries"), dir, results.Result{Package: "reliability"}, request, uncheckedQuery); err == nil || !strings.Contains(err.Error(), "defineSemanticQuery") {
		t.Fatalf("expected unchecked query rejection, got %v", err)
	}
}

func TestPlannedProgressHasOnlyOneRunningStage(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "adversaries", "operability")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("# Operability\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	row := results.Result{ID: "candidate-progress", Package: "operability", ProposedRule: "Show actionable failures."}
	cfg := workspace.Config{Adversaries: workspace.AdversariesConfig{Root: filepath.Join(root, "adversaries")}}
	active := map[string]bool{}
	maxRunning := 0
	report := func(update Progress) {
		if update.State == "running" {
			active[update.Stage] = true
		} else {
			delete(active, update.Stage)
		}
		if len(active) > maxRunning {
			maxRunning = len(active)
		}
	}
	planner := func(_ context.Context, request ChangeRequest) (ChangePlan, error) {
		request.Progress(Progress{Stage: "overlap", State: "running"})
		request.Progress(Progress{Stage: "overlap", State: "complete"})
		request.Progress(Progress{Stage: "strategy", State: "running"})
		request.Progress(Progress{Stage: "strategy", State: "complete"})
		request.Progress(Progress{Stage: "generate", State: "running"})
		request.Progress(Progress{Stage: "generate", State: "complete"})
		return managedRulePlan(request, "actionable-failures"), nil
	}
	if _, _, err := applyPlannedCandidateWithProgress(context.Background(), root, cfg, row, planner, report); err != nil {
		t.Fatal(err)
	}
	if maxRunning != 1 || len(active) != 0 {
		t.Fatalf("max running stages=%d active=%v", maxRunning, active)
	}
}

func TestCatalogPullRequestTitleFallsBackToSpecificRule(t *testing.T) {
	row := results.Result{Package: "engineering-conventions", ProposedRule: "Prevent seedData from being re-invented."}
	if got, want := catalogPullRequestTitle(row, ""), "Update engineering-conventions: Prevent seedData from being re-invented"; got != want {
		t.Fatalf("title=%q want %q", got, want)
	}
}

func TestApplyPlannedRollsBackNewAdversaryWhenGenerationFails(t *testing.T) {
	root, state := t.TempDir(), t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "adversaries"), 0o755); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(root, "adversarylabs.yaml")
	manifest := []byte("apiVersion: adversarylabs.dev/v1alpha1\nkind: AdversaryCatalog\nspec:\n  adversaries: []\n")
	if err := os.WriteFile(manifestPath, manifest, 0o644); err != nil {
		t.Fatal(err)
	}
	saveResult(t, state, results.Result{
		ID: "candidate-rollback", Package: "release-contracts", ProposedRule: "Keep release channels synchronized.",
		AdversaryMission: "Protect private release channel contracts.",
	})
	cfg := workspace.Config{Adversaries: workspace.AdversariesConfig{Root: filepath.Join(root, "adversaries")}}
	err := ApplyPlanned(context.Background(), state, root, cfg, "candidate-rollback", func(context.Context, ChangeRequest) (ChangePlan, error) {
		return ChangePlan{}, errors.New("model unavailable")
	})
	if err == nil || !strings.Contains(err.Error(), "model unavailable") {
		t.Fatalf("err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "adversaries", "release-contracts")); !os.IsNotExist(err) {
		t.Fatalf("failed generation left scaffold behind: %v", err)
	}
	gotManifest, err := os.ReadFile(manifestPath)
	if err != nil || string(gotManifest) != string(manifest) {
		t.Fatalf("manifest changed after rollback: %q err=%v", gotManifest, err)
	}
}

func TestCatalogTreeRollbackRestoresCachesAndRootMode(t *testing.T) {
	root := filepath.Join(t.TempDir(), "operability")
	if err := os.MkdirAll(root, 0o750); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{
		"README.md":              "original policy",
		"node_modules/cache.txt": "original dependency cache",
		".adversary/state.json":  "original runtime state",
		".git/config":            "original nested repository",
	} {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	snapshot, err := captureCatalogTree(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(root, "node_modules")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".adversary", "state.json"), []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := restoreCatalogTree(root, snapshot); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(root)
	if err != nil || info.Mode().Perm() != 0o750 {
		t.Fatalf("root mode=%v err=%v", info.Mode().Perm(), err)
	}
	for name, want := range map[string]string{
		"node_modules/cache.txt": "original dependency cache",
		".adversary/state.json":  "original runtime state",
		".git/config":            "original nested repository",
	} {
		got, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(name)))
		if err != nil || string(got) != want {
			t.Fatalf("restored %s=%q err=%v", name, got, err)
		}
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
		return ChangePlan{Summary: "Add actionable error checks to operability", Files: []ChangeFile{
			{Path: "adversaries/operability/README.md", Content: "# Operability\n\n## Learned rules\n- Show actionable errors.\n"},
			{Path: "adversaries/operability/notes.md", Content: "candidate-4\n"},
		}}, nil
	}
	err := ApplyPlanned(context.Background(), state, root, cfg, "candidate-4", planner)
	if err == nil || !strings.Contains(err.Error(), "managed rule") {
		t.Fatalf("expected regression error, got %v", err)
	}
}

func TestApplyPlannedRetriesDisconnectedImplementation(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "adversaries", "migrations")
	for path, content := range map[string]string{
		"README.md":          "# Migrations\n",
		"adversary.yaml":     "name: private/migrations\nruntime:\n  name: node\n  command: [dist/index.js]\n",
		"package.json":       `{"name":"migrations","scripts":{"test":"tsx --test test/*.test.ts"}}`,
		"src/index.ts":       "export function createApp() { return {}; }\n",
		"test/index.test.ts": "import { createApp } from \"../src/index.ts\";\nvoid createApp();\n",
	} {
		target := filepath.Join(dir, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	row := results.Result{ID: "candidate-wiring", Package: "migrations", ProposedRule: "Enforce migration names."}
	cfg := workspace.Config{Adversaries: workspace.AdversariesConfig{Root: filepath.Join(root, "adversaries")}}
	calls := 0
	planner := func(_ context.Context, request ChangeRequest) (ChangePlan, error) {
		calls++
		files := []ChangeFile{
			{Path: "adversaries/migrations/README.md", Content: "# Migrations\n\n- Enforce migration names.\n"},
			{Path: "adversaries/migrations/src/naming.ts", Content: "export const checksNaming = true;\n"},
			{Path: "adversaries/migrations/test/naming.test.ts", Content: "import { checksNaming } from \"../src/naming.ts\";\nvoid checksNaming;\n"},
		}
		if calls == 2 {
			if !strings.Contains(request.ValidationFeedback, "not reachable") || len(request.PreviousPlanFiles) != 3 {
				t.Fatalf("retry request lacks useful feedback: %+v", request)
			}
			files = append(files,
				ChangeFile{Path: "adversaries/migrations/src/index.ts", Content: "import { checksNaming } from \"./naming.js\";\nexport function createApp() { return { checksNaming }; }\n"},
				ChangeFile{Path: "adversaries/migrations/test/naming-runtime.test.ts", Content: "import { createApp } from \"../src/index.ts\";\nvoid createApp().run({});\n"},
			)
		}
		return ChangePlan{Summary: "Enforce migration naming in migrations", Files: files}, nil
	}
	if _, err := applyPlannedCandidate(context.Background(), root, cfg, row, planner); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("planner calls=%d want 2", calls)
	}
	index, err := os.ReadFile(filepath.Join(dir, "src", "index.ts"))
	if err != nil || !strings.Contains(string(index), "./naming.js") {
		t.Fatalf("runtime was not wired: %q err=%v", index, err)
	}
}

func TestApplyPlannedReservesLatePackageValidationRepairFromCleanBaseline(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "adversaries", "reliability")
	for path, content := range map[string]string{
		"README.md":          "# Reliability\n",
		"adversary.yaml":     "name: private/reliability\nruntime:\n  name: node\n  command: [dist/index.js]\n",
		"package.json":       `{"name":"reliability","scripts":{"test":"npm run build"}}`,
		"src/index.ts":       "export function createApp() { return {}; }\n",
		"test/index.test.ts": "import { createApp } from \"../src/index.ts\";\nvoid createApp();\n",
	} {
		target := filepath.Join(dir, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	row := results.Result{ID: "candidate-compile", Package: "reliability", ProposedRule: "Reject poisoned lazy initialization."}
	cfg := workspace.Config{Adversaries: workspace.AdversariesConfig{Root: filepath.Join(root, "adversaries")}}
	plannerCalls := 0
	planner := func(_ context.Context, request ChangeRequest) (ChangePlan, error) {
		plannerCalls++
		if plannerCalls == 8 {
			if !strings.Contains(request.ValidationFeedback, "error TS1005") || len(request.PreviousPlanFiles) != 3 || request.PreviousPlan == nil || len(request.PreviousPlan.Files) != 3 {
				t.Fatalf("compiler feedback was not supplied to repair attempt: %+v", request)
			}
			if !strings.Contains(request.PreviousPlan.Files[1].Content, "broken") {
				t.Fatalf("repair request omitted failed generated source: %+v", request.PreviousPlan)
			}
			baseline, err := os.ReadFile(filepath.Join(dir, "src", "index.ts"))
			if err != nil || strings.Contains(string(baseline), "broken") {
				t.Fatalf("repair did not start from clean baseline: %q err=%v", baseline, err)
			}
		}
		source := "export function createApp() { return { repaired: true }; }\n"
		if plannerCalls == 7 {
			source = "export function createApp( { // broken\n"
		}
		plan := ChangePlan{Summary: "Reject poisoned initialization in reliability", Files: []ChangeFile{
			{Path: "adversaries/reliability/README.md", Content: "# Reliability\n\n- Reject poisoned lazy initialization.\n"},
			{Path: "adversaries/reliability/src/index.ts", Content: source},
			{Path: "adversaries/reliability/test/poisoned-lazy-initialization.test.ts", Content: "import { createApp } from \"../src/index.ts\";\nvoid createApp();\n"},
		}}
		if plannerCalls <= 6 {
			return plan, fmt.Errorf("generated change deterministic quality review requested revision: correction %d", plannerCalls)
		}
		return plan, nil
	}
	testRuns := 0
	runner := func(_ context.Context, validationDir, _ string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "test" {
			testRuns++
			source, err := os.ReadFile(filepath.Join(validationDir, "src", "index.ts"))
			if err != nil {
				return nil, err
			}
			if strings.Contains(string(source), "broken") {
				return []byte("src/index.ts(1,28): error TS1005: ')' expected.\n"), errors.New("exit status 2")
			}
		}
		return []byte("ok\n"), nil
	}
	var updates []Progress
	_, _, err := applyPlannedCandidateWithProgressOptionsAndRunner(context.Background(), root, cfg, row, planner, func(update Progress) {
		updates = append(updates, update)
	}, false, runner)
	if err != nil {
		t.Fatal(err)
	}
	if plannerCalls != 8 || testRuns != 2 {
		t.Fatalf("planner calls=%d test runs=%d", plannerCalls, testRuns)
	}
	if source, err := os.ReadFile(filepath.Join(dir, "src", "index.ts")); err != nil || !strings.Contains(string(source), "repaired") {
		t.Fatalf("repaired source=%q err=%v", source, err)
	}
	foundRepair, foundSuccess := false, false
	for _, update := range updates {
		foundRepair = foundRepair || update.Stage == "validate" && update.State == "pending"
		foundSuccess = foundSuccess || update.Stage == "validate" && update.State == "complete"
	}
	if !foundRepair || !foundSuccess {
		t.Fatalf("validation progress did not report repair and success: %+v", updates)
	}
}

func TestApplyPlannedCorrectsReplacedTestAndEvidencePath(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "adversaries", "conventions")
	for path, content := range map[string]string{
		"README.md":          "# Conventions\n",
		"adversary.yaml":     "name: private/conventions\nruntime:\n  name: node\n  command: [dist/index.js]\n",
		"package.json":       `{"name":"conventions"}`,
		"src/index.ts":       "export function createApp() { return { run() {} }; }\n",
		"test/index.test.ts": "import { createApp } from \"../src/index.ts\";\nvoid createApp();\n",
	} {
		target := filepath.Join(dir, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	row := results.Result{ID: "candidate-policy", Package: "conventions", ProposedRule: "Keep metadata out of app specs.", File: "gen/gen/kots_default_specs/LICENSE"}
	cfg := workspace.Config{Adversaries: workspace.AdversariesConfig{Root: filepath.Join(root, "adversaries")}}
	calls := 0
	planner := func(_ context.Context, request ChangeRequest) (ChangePlan, error) {
		calls++
		files := []ChangeFile{
			{Path: "adversaries/conventions/README.md", Content: "# Conventions\n\n- Keep metadata out of app specs.\n"},
			{Path: "adversaries/conventions/tests/candidate-policy.yaml", Content: regressionYAML(request)},
			{Path: "adversaries/conventions/src/index.ts", Content: "export function createApp() { return { learnedRule: \"Keep metadata out of app specs.\", run() {} }; }\n"},
		}
		switch calls {
		case 1:
			files = append(files, ChangeFile{Path: "adversaries/conventions/test/index.test.ts", Content: "import { createApp } from \"../src/index.ts\";\nvoid createApp().run();\n"})
		case 2:
			if !strings.Contains(request.ValidationFeedback, "replaced existing native test") {
				t.Fatalf("retry request lacks preservation feedback: %+v", request)
			}
			files = append(files, ChangeFile{Path: "adversaries/conventions/test/app-spec-metadata.test.ts", Content: "import { createApp } from \"../src/index.ts\";\nconst evidencePath = \"gen/app-specs/LICENSE\";\nif (!evidencePath || !createApp().learnedRule) throw new Error(\"rule is not executable\");\n"})
		case 3:
			if strings.Contains(request.ValidationFeedback, "replaced existing native test") || !strings.Contains(request.ValidationFeedback, "exact evidence path") {
				t.Fatalf("retry request did not focus on latest validation feedback: %+v", request)
			}
			files = append(files, ChangeFile{Path: "adversaries/conventions/test/app-spec-metadata.test.ts", Content: "import { createApp } from \"../src/index.ts\";\nconst evidencePath = \"gen/gen/kots_default_specs/LICENSE\";\nif (!evidencePath || !createApp().learnedRule) throw new Error(\"rule is not executable\");\n"})
		}
		return ChangePlan{Summary: "Enforce caller conventions in conventions", Files: files}, nil
	}
	if _, err := applyPlannedCandidate(context.Background(), root, cfg, row, planner); err != nil {
		t.Fatal(err)
	}
	if calls != 3 {
		t.Fatalf("planner calls=%d want 3", calls)
	}
	source, err := os.ReadFile(filepath.Join(dir, "src", "index.ts"))
	if err != nil || !strings.Contains(string(source), "learnedRule") {
		t.Fatalf("policy runtime was not changed: %q err=%v", source, err)
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

func TestCommandFailureMessageKeepsFailingTAPAssertion(t *testing.T) {
	output := strings.Repeat("ok 1 - passing test\n", 200) + "# Subtest: rejects invalid migration\nnot ok 9 - rejects invalid migration\n  ---\n  error: expected one finding, received zero\n  stack: test/rule.test.ts:42:3\n  ...\n1..9\n# fail 1\n"
	message := commandFailureMessage(output)
	if strings.Contains(message, "ok 1 - passing test") || !strings.Contains(message, "not ok 9") || !strings.Contains(message, "expected one finding, received zero") {
		t.Fatalf("message did not isolate the TAP failure:\n%s", message)
	}
}

func TestCommandFailureMessageKeepsEarlyTAPFailuresAndDropsPassingTail(t *testing.T) {
	output := "# Subtest: host contract finds the accepted condition\n" +
		"not ok 1 - host contract finds the accepted condition\n" +
		"  ---\n  error: expected one finding, received zero\n  ...\n" +
		"# Subtest: host contract rejects shadowed bindings\n" +
		"not ok 2 - host contract rejects shadowed bindings\n" +
		"  ---\n  error: expected zero findings, received one\n  ...\n" +
		strings.Repeat("# Subtest: passing generated test\nok 9 - passing generated test\n", 200)
	message := commandFailureMessage(output)
	for _, expected := range []string{
		"not ok 1 - host contract finds the accepted condition",
		"expected one finding, received zero",
		"not ok 2 - host contract rejects shadowed bindings",
		"expected zero findings, received one",
	} {
		if !strings.Contains(message, expected) {
			t.Fatalf("message omitted %q:\n%s", expected, message)
		}
	}
	if strings.Contains(message, "passing generated test") {
		t.Fatalf("message retained the passing TAP tail:\n%s", message)
	}
}

func TestDecodeFailureCanBeRepaired(t *testing.T) {
	err := fmt.Errorf("decode generated catalog change: merged file count 1 is outside 2..16")
	if !isRetryablePlanError(err) {
		t.Fatal("structurally incomplete model output should stay in the bounded repair loop")
	}
}

func TestCatalogRollbackRestoresManifestSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink behavior requires elevated privileges on some Windows hosts")
	}
	root := t.TempDir()
	target := filepath.Join(root, "real-manifest.yaml")
	manifest := filepath.Join(root, "adversarylabs.yaml")
	if err := os.WriteFile(target, []byte("original\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real-manifest.yaml", manifest); err != nil {
		t.Fatal(err)
	}
	snapshot, err := captureCatalogFile(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifest, []byte("changed through symlink\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(manifest); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifest, []byte("generated\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := restoreCatalogFile(manifest, snapshot); err != nil {
		t.Fatal(err)
	}
	link, err := os.Readlink(manifest)
	if err != nil || link != "real-manifest.yaml" {
		t.Fatalf("restored manifest link=%q err=%v", link, err)
	}
	raw, err := os.ReadFile(target)
	if err != nil || string(raw) != "original\n" {
		t.Fatalf("symlink target changed: %q err=%v", raw, err)
	}
}

func TestRunnableValidationDoesNotMutatePackageDependencies(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "adversary")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{
		"package.json":      `{"scripts":{"test":"true"}}`,
		"package-lock.json": `{"lockfileVersion":3}`,
		"adversary.yaml":    "name: private/test\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	runner := func(_ context.Context, commandDir, name string, args ...string) ([]byte, error) {
		if name == "npm" && len(args) > 0 && args[0] == "ci" {
			dependency := filepath.Join(commandDir, "node_modules", "generated", "index.js")
			if err := os.MkdirAll(filepath.Dir(dependency), 0o755); err != nil {
				return nil, err
			}
			if err := os.WriteFile(dependency, []byte("generated"), 0o644); err != nil {
				return nil, err
			}
		}
		return []byte("ok"), nil
	}
	if err := validateRunnablePackage(context.Background(), dir, runner); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "node_modules")); !os.IsNotExist(err) {
		t.Fatalf("validation mutated source package: %v", err)
	}
}

func TestRunnableValidationSynchronizesCompleteBuildOutput(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "adversary")
	for name, content := range map[string]string{
		"package.json":      `{"scripts":{"test":"build"}}`,
		"package-lock.json": `{"lockfileVersion":3}`,
		"adversary.yaml":    "name: private/test\n",
		"dist/index.js":     "export {};\n",
	} {
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	runner := func(_ context.Context, commandDir, name string, args ...string) ([]byte, error) {
		if name == "npm" && len(args) > 0 && args[0] == "test" {
			for path, content := range map[string]string{
				"dist/index.js":                `import "./deterministic.js";`,
				"dist/deterministic.js":        `import "./rules/lazy.js";`,
				"dist/rules/lazy.js":           `export const rule = true;`,
				"dist/rules/lazy.js.map":       `{}`,
				"dist/rules/lazy-definition.d": `export declare const rule = true;`,
			} {
				target := filepath.Join(commandDir, filepath.FromSlash(path))
				if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
					return nil, err
				}
				if err := os.WriteFile(target, []byte(content), 0o644); err != nil {
					return nil, err
				}
			}
		}
		return []byte("ok"), nil
	}
	if err := validateRunnablePackageAndSync(context.Background(), dir, runner); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"dist/index.js", "dist/deterministic.js", "dist/rules/lazy.js"} {
		if _, err := os.Stat(filepath.Join(dir, filepath.FromSlash(path))); err != nil {
			t.Fatalf("validated build output omitted %s: %v", path, err)
		}
	}
	if err := os.Remove(filepath.Join(dir, "dist", "rules", "lazy.js")); err != nil {
		t.Fatal(err)
	}
	if err := validateCompiledRelativeImports(dir); err == nil || !strings.Contains(err.Error(), "missing module") {
		t.Fatalf("incomplete committed runtime was accepted: %v", err)
	}
}

func TestReadCatalogPoliciesIncludesEveryAdversaryAndLearnedRule(t *testing.T) {
	root := t.TempDir()
	adversaries := filepath.Join(root, "adversaries")
	for path, content := range map[string]string{
		"operability/README.md":                         "# Operability",
		"operability/rules/actionable-errors/rule.yaml": "id: actionable-errors",
		"compatibility/README.md":                       "# Compatibility",
		"compatibility/src/index.ts":                    "ignored",
	} {
		full := filepath.Join(adversaries, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	files, err := readCatalogPolicies(root, adversaries)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 3 {
		t.Fatalf("catalog policy files=%+v", files)
	}
	for _, file := range files {
		if strings.HasSuffix(file.Path, "src/index.ts") {
			t.Fatalf("implementation leaked into overlap corpus: %+v", files)
		}
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

func TestPullRequestBodyUsesCanonicalGeneratedRule(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "rule.yaml")
	raw := []byte("version: 1\nid: request-field-propagation\nsummary: Propagate accepted request fields\nguidance: Report a request selector that is validated but not used by the downstream operation.\nseverity: medium\nconfidence: medium\nevidence: https://example.test/evidence\n")
	if err := os.WriteFile(target, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	body := pullRequestBody(results.Result{
		ID: "candidate", Package: "compatibility", ProposedRule: "use themand do everything", CommentURL: "https://example.test/evidence",
	}, target, true, true)
	for _, want := range []string{"## Generated rule", "Propagate accepted request fields", "Minimum confidence: `medium`", "semantic evaluation", "Managed runtime template: synchronized"} {
		if !strings.Contains(body, want) {
			t.Fatalf("body missing %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "themand") {
		t.Fatalf("body used the stale proposed rule instead of canonical generated content:\n%s", body)
	}
}
