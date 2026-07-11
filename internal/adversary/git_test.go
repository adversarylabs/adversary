package adversary

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
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
	runGit(t, repo, "init")
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

	got, err := CommandGitDiffer{}.ChangedFiles(context.Background(), repo, "base", "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "b.txt" || got[1] != "line\nbreak" {
		t.Fatalf("changed files = %#v", got)
	}
}

func TestGitDiffNameOnlyCommandConstruction(t *testing.T) {
	cmd := gitDiffNameStatusCommand(context.Background(), "main", "HEAD")
	want := []string{"git", "diff", "--name-status", "-z", "--find-renames", "--find-copies", "--find-copies-harder", "main", "HEAD", "--"}
	if !reflect.DeepEqual(cmd.Args, want) {
		t.Fatalf("Args = %#v, want %#v", cmd.Args, want)
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
	got, err := (CommandGitDiffer{}).Changes(context.Background(), repo, "base", "HEAD")
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
	got, err := (CommandGitDiffer{}).Changes(context.Background(), repo, "base", "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	want := []GitChange{{Status: GitCopied, OldPath: source, Path: copied, Score: 100}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("changes = %#v, want %#v", got, want)
	}
}

func TestCommandGitDifferErrorsAreActionable(t *testing.T) {
	_, err := (CommandGitDiffer{}).Changes(context.Background(), t.TempDir(), "main", "HEAD")
	if err == nil || !strings.Contains(err.Error(), "not a Git work tree") {
		t.Fatalf("error = %v", err)
	}
	_, err = (CommandGitDiffer{}).Changes(context.Background(), ".", "--output=x", "HEAD")
	if err == nil || !strings.Contains(err.Error(), "command options") {
		t.Fatalf("error = %v", err)
	}
}

func TestRunConfigHostExecutionSpec(t *testing.T) {
	config := NewRunConfig(ResolvedAdversary{
		Name:          "local/adversary",
		Image:         "adversary-local-typescript",
		Command:       []string{"node", "/tmp/adversary/dist/index.js"},
		LocalDir:      true,
		ExecutionPath: "/tmp/adversary",
	}, "/repo", "/tmp/adversary-run", RunOptions{NoNetwork: true})

	spec := config.ContainerSpec()
	if spec.Image != "adversary-local-typescript" {
		t.Fatalf("Image = %q", spec.Image)
	}
	if !reflect.DeepEqual(spec.Command, []string{"node", "/tmp/adversary/dist/index.js"}) {
		t.Fatalf("Command = %#v", spec.Command)
	}
	if spec.AdversaryPath != "/tmp/adversary" {
		t.Fatalf("AdversaryPath = %q", spec.AdversaryPath)
	}
	if !spec.NetworkDisabled {
		t.Fatal("NetworkDisabled is false")
	}
}

func TestRunConfigShellUsesHostShell(t *testing.T) {
	config := NewRunConfig(ResolvedAdversary{
		Command:       []string{"node", "/tmp/adversary/dist/index.js"},
		ExecutionPath: "/tmp/adversary",
	}, "/repo", "/tmp/adversary-run", RunOptions{Shell: true})

	spec := config.ContainerSpec()
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
