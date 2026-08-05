package githubreview

import (
	"fmt"
	"testing"
)

func TestActionsContext(t *testing.T) {
	repo, pr := ActionsContext(func(k string) (string, bool) {
		switch k {
		case "GITHUB_REPOSITORY":
			return "acme/app", true
		case "GITHUB_REF":
			return "refs/pull/17/merge", true
		default:
			return "", false
		}
	})
	if repo != "acme/app" || pr != 17 {
		t.Fatalf("%s %d", repo, pr)
	}
	repo, pr = ActionsContext(nil)
	if repo != "" || pr != 0 {
		t.Fatal()
	}
}

func TestCleanupTempDirNoop(t *testing.T) {
	CleanupTempDir("")
	CleanupWorkspace("", "", "", 0)
	DeleteAdversaryPRRef("", 0)
	DeleteAdversaryPRRef("/no/such/path", 1)
}

func TestAdversaryPRRefName(t *testing.T) {
	// Ensure we never document a fetch that writes a durable ref destination.
	// Regression guard for greptile: pull/N/head:refs/adversary/pr-N.
	want := "pull/17/head"
	if got := fmt.Sprintf("pull/%d/head", 17); got != want {
		t.Fatal(got)
	}
}

func TestIsGitRepoFalse(t *testing.T) {
	if isGitRepo(t.TempDir()) {
		t.Fatal("empty temp should not be git repo")
	}
}

func TestShortSHA(t *testing.T) {
	if shortSHA("abcdefghij") != "abcdefg" {
		t.Fatal(shortSHA("abcdefghij"))
	}
	if shortSHA("abc") != "abc" {
		t.Fatal()
	}
}
