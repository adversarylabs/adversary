package githubreview

import (
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
	CleanupWorkspace("", "", "")
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
