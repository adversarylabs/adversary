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
	return ChangePlan{Summary: "Add actionable error checks to " + request.Adversary, Files: []ChangeFile{{Path: base + "rule.yaml", Content: rule}, {Path: base + "cases.yaml", Content: cases}}}
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

func TestApplyPlannedCorrectsReplacedTestAndEvidencePath(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "adversaries", "conventions")
	for path, content := range map[string]string{
		"README.md":          "# Conventions\n",
		"adversary.yaml":     "name: private/conventions\nruntime:\n  name: node\n  command: [dist/index.js]\n",
		"package.json":       `{"name":"conventions","adversarylabsCatalogRuntime":1}`,
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
			if !strings.Contains(request.ValidationFeedback, "replaced existing native test") || !strings.Contains(request.ValidationFeedback, "exact evidence path") {
				t.Fatalf("retry request did not retain validation feedback: %+v", request)
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
