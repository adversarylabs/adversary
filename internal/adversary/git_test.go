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

func TestDockerRunArgs(t *testing.T) {
	got := dockerRunArgs(ContainerSpec{
		Image:           "example/adversary:latest",
		Command:         []string{"/adversary/run"},
		RepoPath:        "/repo",
		RunDir:          "/tmp/adversary-run",
		NetworkDisabled: true,
	})
	want := []string{
		"run",
		"--rm",
		"-v", "/repo:/workspace:ro",
		"-v", "/tmp/adversary-run/input.json:/adversary/input.json:ro",
		"-v", "/tmp/adversary-run/output.json:/adversary/output.json",
		"--network", "none",
		"example/adversary:latest",
		"/adversary/run",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("args = %#v, want %#v", got, want)
	}
}

func TestDockerBuildArgs(t *testing.T) {
	got := dockerBuildArgs(BuildSpec{
		Image:   "example/adversary:latest",
		Context: "./examples/adversary",
	})
	want := []string{"build", "-t", "example/adversary:latest", "./examples/adversary"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("args = %#v, want %#v", got, want)
	}
}

func TestDockerRunArgsWithEnvAndShell(t *testing.T) {
	got := dockerRunArgs(ContainerSpec{
		Image:    "example/adversary:latest",
		RepoPath: "/repo",
		RunDir:   "/tmp/adversary-run",
		Env: map[string]string{
			"ADVERSARY_OUTPUT":  "/adversary/output.json",
			"ADVERSARY_REPO":    "/workspace",
			"ADVERSARY_VERBOSE": "1",
		},
		Shell: true,
	})
	want := []string{
		"run",
		"--rm",
		"-it",
		"-v", "/repo:/workspace:ro",
		"-v", "/tmp/adversary-run/input.json:/adversary/input.json:ro",
		"-v", "/tmp/adversary-run/output.json:/adversary/output.json",
		"-e", "ADVERSARY_OUTPUT=/adversary/output.json",
		"-e", "ADVERSARY_REPO=/workspace",
		"-e", "ADVERSARY_VERBOSE=1",
		"example/adversary:latest",
		"/bin/sh",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("args = %#v, want %#v", got, want)
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
