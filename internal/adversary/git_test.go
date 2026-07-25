package adversary

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/adversarylabs/adversary/pkg/detection"
)

func TestParseChangedFiles(t *testing.T) {
	output := []byte("A\x00 leading and trailing \x00D\x00line\nbreak\x00R100\x00old name\x00new name\x00")
	got, err := parseGitChanges(output)
	if err != nil {
		t.Fatal(err)
	}
	want := []GitChange{
		{Status: GitAdded, Path: " leading and trailing "},
		{Status: GitDeleted, Path: "line\nbreak"},
		{Status: GitRenamed, OldPath: "old name", Path: "new name", Score: 100},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("changes = %#v, want %#v", got, want)
	}
}

func TestParseGitChangesRejectsMalformedOutput(t *testing.T) {
	for _, output := range [][]byte{
		[]byte("A\x00file"), []byte("R100\x00old\x00"), []byte("X\x00file\x00"),
		[]byte("AA\x00file\x00"), []byte("M100\x00file\x00"), []byte("R\x00old\x00new\x00"),
		[]byte("R-1\x00old\x00new\x00"), []byte("R101\x00old\x00new\x00"),
		[]byte("C1x\x00old\x00new\x00"), []byte("D0\x00file\x00"),
	} {
		if _, err := parseGitChanges(output); err == nil {
			t.Fatalf("accepted %q", output)
		}
	}
}

func TestCommandGitDifferChangedFiles(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}

	repo := t.TempDir()
	runGit(t, repo, "init", "-b", "main")
	runGit(t, repo, "config", "user.email", "test@example.com")
	runGit(t, repo, "config", "user.name", "Test User")
	writeFile(t, filepath.Join(repo, "a.txt"), "one\n")
	runGit(t, repo, "add", ".")
	runGit(t, repo, "commit", "-m", "initial")
	runGit(t, repo, "tag", "base")
	writeFile(t, filepath.Join(repo, "b.txt"), "two\n")
	writeFile(t, filepath.Join(repo, "line\nbreak"), "odd\n")
	runGit(t, repo, "add", ".")
	runGit(t, repo, "commit", "-m", "change")

	got, err := systemGitDiffer(t).ChangedFiles(context.Background(), repo, "base", "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "b.txt" || got[1] != "line\nbreak" {
		t.Fatalf("changed files = %#v", got)
	}
}

func TestGitDiffNameOnlyCommandConstruction(t *testing.T) {
	got := gitDiffNameStatusArgs("main", "HEAD")
	want := []string{"diff", "--no-ext-diff", "--ignore-submodules=none", "--name-status", "-z", "--find-renames", "--find-copies", "--find-copies-harder", "main", "HEAD", "--"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Args = %#v, want %#v", got, want)
	}
}

func TestResolveDirtyChangesIncludesStagedUnstagedAndUntracked(t *testing.T) {
	repo := newGitRepository(t)
	writeFile(t, filepath.Join(repo, "staged.txt"), "base\n")
	writeFile(t, filepath.Join(repo, "unstaged.txt"), "base\n")
	runGit(t, repo, "add", ".")
	runGit(t, repo, "commit", "-m", "base")
	writeFile(t, filepath.Join(repo, "staged.txt"), "staged\n")
	runGit(t, repo, "add", "staged.txt")
	writeFile(t, filepath.Join(repo, "staged.txt"), "staged and unstaged\n")
	writeFile(t, filepath.Join(repo, "unstaged.txt"), "unstaged\n")
	writeFile(t, filepath.Join(repo, "untracked.txt"), "new\n")

	context, err := systemGitDiffer(t).ResolveChanges(context.Background(), ChangeRequest{RepoPath: repo, Mode: detection.ModeDirtyWorktree})
	if err != nil {
		t.Fatal(err)
	}
	want := []detection.ChangedFile{
		{Path: "staged.txt", Status: detection.StatusModified},
		{Path: "unstaged.txt", Status: detection.StatusModified},
		{Path: "untracked.txt", Status: detection.StatusUntracked},
	}
	if !reflect.DeepEqual(context.ChangedFiles, want) {
		t.Fatalf("changes = %#v, want %#v", context.ChangedFiles, want)
	}
}

func TestResolveDirtyChangesPreservesRenameDeleteAndOddUntrackedPath(t *testing.T) {
	repo := newGitRepository(t)
	writeFile(t, filepath.Join(repo, "rename-me"), strings.Repeat("same\n", 20))
	writeFile(t, filepath.Join(repo, "delete-me"), "gone\n")
	runGit(t, repo, "add", ".")
	runGit(t, repo, "commit", "-m", "base")
	runGit(t, repo, "mv", "rename-me", "renamed")
	runGit(t, repo, "rm", "delete-me")
	writeFile(t, filepath.Join(repo, "odd\nname"), "new\n")

	got, err := systemGitDiffer(t).ResolveChanges(context.Background(), ChangeRequest{RepoPath: repo, Mode: detection.ModeDirtyWorktree})
	if err != nil {
		t.Fatal(err)
	}
	want := []detection.ChangedFile{
		{Path: "delete-me", Status: detection.StatusDeleted},
		{Path: "odd\nname", Status: detection.StatusUntracked},
		{Path: "renamed", PreviousPath: "rename-me", Status: detection.StatusRenamed},
	}
	if !reflect.DeepEqual(got.ChangedFiles, want) {
		t.Fatalf("changes = %#v, want %#v", got.ChangedFiles, want)
	}
}

func TestResolveBranchComparisonUsesMergeBase(t *testing.T) {
	repo := newGitRepository(t)
	writeFile(t, filepath.Join(repo, "base"), "base\n")
	runGit(t, repo, "add", ".")
	runGit(t, repo, "commit", "-m", "base")
	runGit(t, repo, "switch", "-c", "feature-branch")
	writeFile(t, filepath.Join(repo, "feature"), "feature\n")
	runGit(t, repo, "add", ".")
	runGit(t, repo, "commit", "-m", "feature")
	featureCommit := strings.TrimSpace(runGitOutput(t, repo, "rev-parse", "HEAD"))
	runGit(t, repo, "switch", "main")
	writeFile(t, filepath.Join(repo, "main-only"), "main\n")
	runGit(t, repo, "add", ".")
	runGit(t, repo, "commit", "-m", "main")
	runGit(t, repo, "switch", "--detach", featureCommit)

	got, err := systemGitDiffer(t).ResolveChanges(context.Background(), ChangeRequest{RepoPath: repo, Mode: detection.ModeBranchComparison, BaseRef: "main", HeadRef: "HEAD"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.ChangedFiles) != 1 || got.ChangedFiles[0].Path != "feature" {
		t.Fatalf("merge-base changes = %#v", got.ChangedFiles)
	}
	if got.MergeBase == "" || got.BaseRef != "main" || got.HeadRef != "HEAD" {
		t.Fatalf("context = %#v", got)
	}
}

func TestResolveChangesUsesRepositoryRootFromSubdirectory(t *testing.T) {
	repo := newGitRepository(t)
	writeFile(t, filepath.Join(repo, "tracked"), "base\n")
	runGit(t, repo, "add", ".")
	runGit(t, repo, "commit", "-m", "base")
	subdir := filepath.Join(repo, "nested")
	if err := os.Mkdir(subdir, 0755); err != nil {
		t.Fatal(err)
	}
	got, err := systemGitDiffer(t).ResolveChanges(context.Background(), ChangeRequest{RepoPath: subdir, Mode: detection.ModeDirtyWorktree})
	if err != nil {
		t.Fatal(err)
	}
	wantRoot := strings.TrimSpace(runGitOutput(t, repo, "rev-parse", "--show-toplevel"))
	if got.RepositoryRoot != wantRoot {
		t.Fatalf("repository root = %q, want %q", got.RepositoryRoot, wantRoot)
	}
}

func TestResolveDirtyChangesSupportsUnbornRepository(t *testing.T) {
	repo := newGitRepository(t)
	writeFile(t, filepath.Join(repo, "staged"), "new\n")
	runGit(t, repo, "add", "staged")
	writeFile(t, filepath.Join(repo, "untracked"), "new\n")
	got, err := systemGitDiffer(t).ResolveChanges(context.Background(), ChangeRequest{RepoPath: repo, Mode: detection.ModeDirtyWorktree})
	if err != nil {
		t.Fatal(err)
	}
	want := []detection.ChangedFile{{Path: "staged", Status: detection.StatusAdded}, {Path: "untracked", Status: detection.StatusUntracked}}
	if !reflect.DeepEqual(got.ChangedFiles, want) {
		t.Fatalf("changes = %#v, want %#v", got.ChangedFiles, want)
	}
}

func TestResolveDirtyChangesDisablesExternalDiffForUnbornRepository(t *testing.T) {
	repo := newGitRepository(t)
	runGit(t, repo, "config", "diff.external", "adversary-test-missing-external-diff")
	writeFile(t, filepath.Join(repo, "staged"), "new\n")
	runGit(t, repo, "add", "staged")

	got, err := systemGitDiffer(t).ResolveChanges(context.Background(), ChangeRequest{RepoPath: repo, Mode: detection.ModeDirtyWorktree})
	if err != nil {
		t.Fatal(err)
	}
	want := []detection.ChangedFile{{Path: "staged", Status: detection.StatusAdded}}
	if !reflect.DeepEqual(got.ChangedFiles, want) {
		t.Fatalf("changes = %#v, want %#v", got.ChangedFiles, want)
	}
}

func TestParseNULPathsRejectsMalformedOutput(t *testing.T) {
	for _, value := range [][]byte{[]byte("path"), []byte("path\x00\x00")} {
		if _, err := parseNULPaths(value); err == nil {
			t.Fatalf("accepted %q", value)
		}
	}
}

func TestChangeRequestForArgument(t *testing.T) {
	for _, tc := range []struct {
		argument string
		mode     detection.ChangeMode
		base     string
		head     string
	}{
		{"", detection.ModeDirtyWorktree, "", ""},
		{"main", detection.ModeBranchComparison, "main", "HEAD"},
		{"main...feature", detection.ModeExplicitRange, "main", "feature"},
	} {
		got, err := ChangeRequestForArgument(".", tc.argument)
		if err != nil {
			t.Fatal(err)
		}
		if got.Mode != tc.mode || got.BaseRef != tc.base || got.HeadRef != tc.head {
			t.Fatalf("ChangeRequestForArgument(%q) = %#v", tc.argument, got)
		}
	}
	for _, invalid := range []string{"main..HEAD", "main....HEAD", "...HEAD", "main...", "--output=x"} {
		if _, err := ChangeRequestForArgument(".", invalid); err == nil {
			t.Fatalf("accepted invalid argument %q", invalid)
		}
	}
}

func TestChangeRequestFromCI(t *testing.T) {
	values := map[string]string{"GITHUB_BASE_REF": "main", "GITHUB_SHA": "abc123"}
	got, ok := ChangeRequestFromCI(".", func(name string) (string, bool) { value, exists := values[name]; return value, exists })
	if !ok || got.Mode != detection.ModePullRequest || got.BaseRef != "main" || got.HeadRef != "abc123" {
		t.Fatalf("CI request = %#v, %t", got, ok)
	}
}

func TestResolveRunScopeUsesDirtyWorktreeBeforeBranchComparison(t *testing.T) {
	repo := newGitRepository(t)
	writeFile(t, filepath.Join(repo, "tracked.txt"), "base\n")
	runGit(t, repo, "add", ".")
	runGit(t, repo, "commit", "-m", "base")
	runGit(t, repo, "config", "adversary.defaultBase", "main")
	runGit(t, repo, "switch", "-c", "feature")
	writeFile(t, filepath.Join(repo, "tracked.txt"), "dirty\n")
	writeFile(t, filepath.Join(repo, "untracked.txt"), "new\n")

	got, err := systemGitDiffer(t).ResolveRunScope(context.Background(), RunScopeRequest{RepoPath: repo})
	if err != nil {
		t.Fatal(err)
	}
	if got.Kind != RunScopeWorktree || got.AllFiles || got.ReviewContext == nil {
		t.Fatalf("scope = %#v", got)
	}
	want := []detection.ChangedFile{
		{Path: "tracked.txt", Status: detection.StatusModified},
		{Path: "untracked.txt", Status: detection.StatusUntracked},
	}
	if !reflect.DeepEqual(got.ReviewContext.ChangedFiles, want) {
		t.Fatalf("changes = %#v, want %#v", got.ReviewContext.ChangedFiles, want)
	}
	if got.ReviewContext.Mode != detection.ModeDirtyWorktree {
		t.Fatalf("mode = %q", got.ReviewContext.Mode)
	}
}

func TestResolveRunScopeUsesPullRequestContextBeforeDirtyWorktree(t *testing.T) {
	repo := newGitRepository(t)
	writeFile(t, filepath.Join(repo, "base.txt"), "base\n")
	runGit(t, repo, "add", ".")
	runGit(t, repo, "commit", "-m", "base")
	staleLocalBase := strings.TrimSpace(runGitOutput(t, repo, "rev-parse", "HEAD"))
	writeFile(t, filepath.Join(repo, "current-base.txt"), "current base\n")
	runGit(t, repo, "add", ".")
	runGit(t, repo, "commit", "-m", "current base")
	runGit(t, repo, "switch", "-c", "feature")
	writeFile(t, filepath.Join(repo, "committed.txt"), "feature\n")
	runGit(t, repo, "add", ".")
	runGit(t, repo, "commit", "-m", "feature")
	writeFile(t, filepath.Join(repo, "local-only.txt"), "dirty\n")
	runGit(t, repo, "update-ref", "refs/remotes/origin/main", "main")
	runGit(t, repo, "update-ref", "refs/heads/main", staleLocalBase)
	values := map[string]string{"ADVERSARY_BASE_REF": "main", "ADVERSARY_HEAD_REF": "HEAD"}

	got, err := systemGitDiffer(t).ResolveRunScope(context.Background(), RunScopeRequest{
		RepoPath: repo,
		Lookup:   func(name string) (string, bool) { value, ok := values[name]; return value, ok },
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Kind != RunScopePR || got.ReviewContext == nil || got.ReviewContext.Mode != detection.ModePullRequest {
		t.Fatalf("scope = %#v", got)
	}
	if len(got.ReviewContext.ChangedFiles) != 1 || got.ReviewContext.ChangedFiles[0].Path != "committed.txt" {
		t.Fatalf("PR changes = %#v", got.ReviewContext.ChangedFiles)
	}
}

func TestResolveRunScopeUsesConfiguredNonOriginPullRequestBase(t *testing.T) {
	repo := newGitRepository(t)
	writeFile(t, filepath.Join(repo, "old-base.txt"), "old base\n")
	runGit(t, repo, "add", ".")
	runGit(t, repo, "commit", "-m", "old base")
	staleBase := strings.TrimSpace(runGitOutput(t, repo, "rev-parse", "HEAD"))
	writeFile(t, filepath.Join(repo, "current-base.txt"), "current base\n")
	runGit(t, repo, "add", ".")
	runGit(t, repo, "commit", "-m", "current base")
	currentBase := strings.TrimSpace(runGitOutput(t, repo, "rev-parse", "HEAD"))
	runGit(t, repo, "switch", "-c", "feature")
	writeFile(t, filepath.Join(repo, "feature.txt"), "feature\n")
	runGit(t, repo, "add", ".")
	runGit(t, repo, "commit", "-m", "feature")
	runGit(t, repo, "remote", "add", "origin", repo)
	runGit(t, repo, "remote", "add", "upstream", repo)
	runGit(t, repo, "update-ref", "refs/remotes/origin/main", staleBase)
	runGit(t, repo, "update-ref", "refs/remotes/upstream/main", currentBase)
	runGit(t, repo, "config", "branch.main.remote", "upstream")
	runGit(t, repo, "update-ref", "refs/heads/main", staleBase)
	values := map[string]string{"ADVERSARY_BASE_REF": "main", "ADVERSARY_HEAD_REF": "HEAD"}

	got, err := systemGitDiffer(t).ResolveRunScope(context.Background(), RunScopeRequest{
		RepoPath: repo,
		Lookup:   func(name string) (string, bool) { value, ok := values[name]; return value, ok },
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.ReviewContext == nil || len(got.ReviewContext.ChangedFiles) != 1 || got.ReviewContext.ChangedFiles[0].Path != "feature.txt" {
		t.Fatalf("PR scope = %#v", got)
	}
}

func TestResolveRunScopeUsesMergeBaseForCleanFeatureBranch(t *testing.T) {
	repo := newGitRepository(t)
	writeFile(t, filepath.Join(repo, "base.txt"), "base\n")
	runGit(t, repo, "add", ".")
	runGit(t, repo, "commit", "-m", "base")
	runGit(t, repo, "config", "adversary.defaultBase", "main")
	runGit(t, repo, "switch", "-c", "feature")
	writeFile(t, filepath.Join(repo, "feature.txt"), "feature\n")
	runGit(t, repo, "add", ".")
	runGit(t, repo, "commit", "-m", "feature")

	got, err := systemGitDiffer(t).ResolveRunScope(context.Background(), RunScopeRequest{RepoPath: repo})
	if err != nil {
		t.Fatal(err)
	}
	if got.Kind != RunScopeBranch || got.DefaultBase != "main" || got.ReviewContext == nil {
		t.Fatalf("scope = %#v", got)
	}
	if got.ReviewContext.Mode != detection.ModeBranchComparison || got.ReviewContext.MergeBase == "" {
		t.Fatalf("review context = %#v", got.ReviewContext)
	}
	if got.ReviewContext.BaseRef != "main" || got.ReviewContext.HeadRef != "feature" {
		t.Fatalf("refs = %s...%s", got.ReviewContext.BaseRef, got.ReviewContext.HeadRef)
	}
	if len(got.ReviewContext.ChangedFiles) != 1 || got.ReviewContext.ChangedFiles[0].Path != "feature.txt" {
		t.Fatalf("branch changes = %#v", got.ReviewContext.ChangedFiles)
	}
}

func TestResolveRunScopeFallsBackToAllFilesOnCleanDefaultOrNonGitTarget(t *testing.T) {
	repo := newGitRepository(t)
	writeFile(t, filepath.Join(repo, "base.txt"), "base\n")
	runGit(t, repo, "add", ".")
	runGit(t, repo, "commit", "-m", "base")
	runGit(t, repo, "config", "adversary.defaultBase", "main")

	clean, err := systemGitDiffer(t).ResolveRunScope(context.Background(), RunScopeRequest{RepoPath: repo})
	if err != nil {
		t.Fatal(err)
	}
	if clean.Kind != RunScopeAllFiles || !clean.AllFiles || clean.ReviewContext != nil || clean.Reason != "clean default branch" {
		t.Fatalf("clean default scope = %#v", clean)
	}

	nonGit, err := systemGitDiffer(t).ResolveRunScope(context.Background(), RunScopeRequest{RepoPath: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if nonGit.Kind != RunScopeAllFiles || !nonGit.AllFiles || nonGit.ReviewContext != nil {
		t.Fatalf("non-Git scope = %#v", nonGit)
	}
}

func TestResolveRunScopeCompletesPartialExplicitRefs(t *testing.T) {
	repo := newGitRepository(t)
	writeFile(t, filepath.Join(repo, "base.txt"), "base\n")
	runGit(t, repo, "add", ".")
	runGit(t, repo, "commit", "-m", "base")
	runGit(t, repo, "config", "adversary.defaultBase", "main")
	runGit(t, repo, "switch", "-c", "feature")
	writeFile(t, filepath.Join(repo, "feature.txt"), "feature\n")
	runGit(t, repo, "add", ".")
	runGit(t, repo, "commit", "-m", "feature")

	baseOnly, err := systemGitDiffer(t).ResolveRunScope(context.Background(), RunScopeRequest{RepoPath: repo, BaseRef: "main"})
	if err != nil {
		t.Fatal(err)
	}
	if baseOnly.ReviewContext == nil || baseOnly.ReviewContext.BaseRef != "main" || baseOnly.ReviewContext.HeadRef != "HEAD" {
		t.Fatalf("base-only scope = %#v", baseOnly)
	}

	headOnly, err := systemGitDiffer(t).ResolveRunScope(context.Background(), RunScopeRequest{RepoPath: repo, HeadRef: "HEAD"})
	if err != nil {
		t.Fatal(err)
	}
	if headOnly.ReviewContext == nil || headOnly.ReviewContext.BaseRef != "main" || headOnly.ReviewContext.HeadRef != "HEAD" {
		t.Fatalf("head-only scope = %#v", headOnly)
	}
}

func TestResolveRunScopeExplicitAllFilesDoesNotRequireGit(t *testing.T) {
	got, err := (CommandGitDiffer{}).ResolveRunScope(context.Background(), RunScopeRequest{RepoPath: t.TempDir(), AllFiles: true})
	if err != nil {
		t.Fatal(err)
	}
	if got.Kind != RunScopeAllFiles || !got.AllFiles || got.Reason != "requested by --all-files" {
		t.Fatalf("scope = %#v", got)
	}
}

func TestDefaultBaseRefUsesRemoteHEADWithoutNetworkAccess(t *testing.T) {
	repo := newGitRepository(t)
	writeFile(t, filepath.Join(repo, "base.txt"), "base\n")
	runGit(t, repo, "add", ".")
	runGit(t, repo, "commit", "-m", "base")
	runGit(t, repo, "update-ref", "refs/remotes/origin/trunk", "HEAD")
	runGit(t, repo, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/trunk")

	got, source, err := systemGitDiffer(t).defaultBaseRef(context.Background(), repo)
	if err != nil {
		t.Fatal(err)
	}
	if got != "origin/trunk" || source != "refs/remotes/origin/HEAD" {
		t.Fatalf("default base = %q via %q", got, source)
	}
}

func TestCommandGitDifferModelsRenameAndDelete(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	repo := t.TempDir()
	runGit(t, repo, "init")
	runGit(t, repo, "config", "user.email", "test@example.com")
	runGit(t, repo, "config", "user.name", "Test User")
	writeFile(t, filepath.Join(repo, "rename me"), strings.Repeat("same\n", 20))
	writeFile(t, filepath.Join(repo, "delete me"), "gone\n")
	runGit(t, repo, "add", ".")
	runGit(t, repo, "commit", "-m", "base")
	runGit(t, repo, "tag", "base")
	runGit(t, repo, "mv", "rename me", "renamed\nfile")
	runGit(t, repo, "rm", "delete me")
	runGit(t, repo, "commit", "-m", "change")
	got, err := systemGitDiffer(t).Changes(context.Background(), repo, "base", "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	want := []GitChange{{Status: GitDeleted, Path: "delete me"}, {Status: GitRenamed, OldPath: "rename me", Path: "renamed\nfile", Score: 100}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("changes = %#v, want %#v", got, want)
	}
}

func TestCommandGitDifferFindsCopyFromUnchangedTrackedSource(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	repo := t.TempDir()
	runGit(t, repo, "init")
	runGit(t, repo, "config", "user.email", "test@example.com")
	runGit(t, repo, "config", "user.name", "Test User")
	source := " source\tfile "
	copied := "copy\nfile"
	writeFile(t, filepath.Join(repo, source), strings.Repeat("unchanged source\n", 40))
	runGit(t, repo, "add", ".")
	runGit(t, repo, "commit", "-m", "base")
	runGit(t, repo, "tag", "base")
	data, err := os.ReadFile(filepath.Join(repo, source))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, copied), data, 0644); err != nil {
		t.Fatal(err)
	}
	runGit(t, repo, "add", ".")
	runGit(t, repo, "commit", "-m", "copy")
	got, err := systemGitDiffer(t).Changes(context.Background(), repo, "base", "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	want := []GitChange{{Status: GitCopied, OldPath: source, Path: copied, Score: 100}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("changes = %#v, want %#v", got, want)
	}
}

func TestCommandGitDifferErrorsAreActionable(t *testing.T) {
	differ := systemGitDiffer(t)
	_, err := differ.Changes(context.Background(), t.TempDir(), "main", "HEAD")
	if err == nil || !strings.Contains(err.Error(), "not a Git work tree") {
		t.Fatalf("error = %v", err)
	}
	_, err = differ.Changes(context.Background(), ".", "--output=x", "HEAD")
	if err == nil || !strings.Contains(err.Error(), "command options") {
		t.Fatalf("error = %v", err)
	}
}

func TestCommandGitDifferUsesCanonicalCapturedProcessState(t *testing.T) {
	executable := filepath.Join(t.TempDir(), "git")
	capturedPath, livePath := t.TempDir(), t.TempDir()
	environment := NewProcessEnvironment([]string{"PATH=" + capturedPath, "GIT_CONFIG_NOSYSTEM=1"}, false)
	t.Setenv("PATH", livePath)
	output := &recordingOutputRunner{}
	differ := CommandGitDiffer{Executable: executable, Environment: environment, Output: output}
	if _, _, err := differ.run(context.Background(), t.TempDir(), "status", "--porcelain"); err != nil {
		t.Fatal(err)
	}
	if output.options.Path != executable {
		t.Fatalf("Git executable = %q", output.options.Path)
	}
	joined := strings.Join(output.options.Env, "\n")
	if !strings.Contains(joined, "GIT_CONFIG_NOSYSTEM=1") || !strings.Contains(joined, "PATH="+capturedPath) || strings.Contains(joined, livePath) {
		t.Fatalf("Git environment = %#v", output.options.Env)
	}
}

func systemGitDiffer(t *testing.T) CommandGitDiffer {
	t.Helper()
	path, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git not installed")
	}
	path, err = filepath.Abs(path)
	if err != nil {
		t.Fatal(err)
	}
	return CommandGitDiffer{Executable: path, Environment: NewProcessEnvironment(os.Environ(), runtime.GOOS == "windows"), Output: ExecProcessOutputRunner{}}
}

func TestRunConfigHostExecutionSpec(t *testing.T) {
	config := NewRunConfig(ResolvedAdversary{
		Name:          "local/adversary",
		Image:         "adversary-local-typescript",
		Command:       []string{"node", "/tmp/adversary/dist/index.js"},
		LocalDir:      true,
		ExecutionPath: "/tmp/adversary",
	}, "/repo", "/tmp/adversary-run", RunOptions{NoNetwork: true})

	spec := config.RuntimeSpec()
	if spec.Image != "adversary-local-typescript" {
		t.Fatalf("Image = %q", spec.Image)
	}
	if !reflect.DeepEqual(spec.Command, []string{"node", "/tmp/adversary/dist/index.js"}) {
		t.Fatalf("Command = %#v", spec.Command)
	}
	if spec.AdversaryPath != "/tmp/adversary" {
		t.Fatalf("AdversaryPath = %q", spec.AdversaryPath)
	}
	if !spec.Permissions.Required.NetworkIsolation {
		t.Fatal("required network isolation is false")
	}
	if value, ok := spec.Env["ADVERSARY_CHANGE_CONTEXT"]; !ok || value != "" {
		t.Fatalf("all-files review context environment = %q, %t", value, ok)
	}
}

func TestRunConfigShellUsesHostShell(t *testing.T) {
	config := NewRunConfig(ResolvedAdversary{
		Command:       []string{"node", "/tmp/adversary/dist/index.js"},
		ExecutionPath: "/tmp/adversary",
	}, "/repo", "/tmp/adversary-run", RunOptions{Shell: true})

	spec := config.RuntimeSpec()
	if !spec.Shell {
		t.Fatal("Shell is false")
	}
}

func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v failed: %v\n%s", args, err, out)
	}
}

func newGitRepository(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	repo := t.TempDir()
	runGit(t, repo, "init", "-b", "main")
	runGit(t, repo, "config", "user.email", "test@example.com")
	runGit(t, repo, "config", "user.name", "Test User")
	return repo
}

func runGitOutput(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v failed: %v\n%s", args, err, out)
	}
	return string(out)
}
