package adversary

import (
	"context"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
)

func TestParseChangedFiles(t *testing.T) {
	got := parseChangedFiles("a.txt\n.github/workflows/test.yml\n\n")
	want := []string{"a.txt", ".github/workflows/test.yml"}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got[%d] = %q, want %q", i, got[i], want[i])
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
	runGit(t, repo, "add", ".")
	runGit(t, repo, "commit", "-m", "change")

	got, err := CommandGitDiffer{}.ChangedFiles(context.Background(), repo, "base", "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "b.txt" {
		t.Fatalf("changed files = %#v", got)
	}
}

func TestGitDiffNameOnlyCommandConstruction(t *testing.T) {
	cmd := gitDiffNameOnlyCommand(context.Background(), "main", "HEAD")
	want := []string{"git", "diff", "--name-only", "main...HEAD"}
	if !reflect.DeepEqual(cmd.Args, want) {
		t.Fatalf("Args = %#v, want %#v", cmd.Args, want)
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
