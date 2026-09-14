package outcomecontext

import (
	"strings"
	"testing"
)

func TestGitHubPullRequestBuildsBoundedAttributedSources(t *testing.T) {
	context := GitHubPullRequest("acme/app", 42, "  Add delegated trust  ", strings.Repeat("x", MaxSourceCharacters+10))
	if context == nil {
		t.Fatal("expected context")
	}
	if context.Subject.Repository != "acme/app" || context.Subject.PullRequest != 42 {
		t.Fatalf("subject = %#v", context.Subject)
	}
	if len(context.Sources) != 2 || context.Sources[0].Text != "Add delegated trust" {
		t.Fatalf("sources = %#v", context.Sources)
	}
	if context.Intent.Objective != "Add delegated trust" || context.Intent.Confidence != "low" {
		t.Fatalf("intent = %#v", context.Intent)
	}
	if err := context.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestGitHubPullRequestRejectsInvalidNumber(t *testing.T) {
	for _, number := range []int{0, -1} {
		if got := GitHubPullRequest("acme/app", number, "title", "body"); got != nil {
			t.Fatalf("number %d produced context %#v", number, got)
		}
	}
}

func TestGitHubPullRequestRejectsOverlongRepository(t *testing.T) {
	if got := GitHubPullRequest(strings.Repeat("r", MaxRepositoryCharacters+1), 1, "title", "body"); got != nil {
		t.Fatalf("overlong repository produced context %#v", got)
	}
}

func TestValidateMatchesSubjectAndUnicodeSchemaLimits(t *testing.T) {
	valid := GitHubPullRequest(strings.Repeat("r", MaxRepositoryCharacters), 1, strings.Repeat("🙂", MaxSourceCharacters), "body")
	if valid == nil || valid.Validate() != nil {
		t.Fatalf("boundary context = %#v", valid)
	}

	invalidRepository := *valid
	invalidRepository.Subject.Repository = strings.Repeat("r", MaxRepositoryCharacters+1)
	if err := invalidRepository.Validate(); err == nil {
		t.Fatal("expected repository length error")
	}
	invalidSource := *valid
	invalidSource.Sources = []Source{{Kind: "pull_request_title", Text: strings.Repeat("🙂", MaxSourceCharacters+1)}}
	if err := invalidSource.Validate(); err == nil {
		t.Fatal("expected source character length error")
	}
}

func TestGitHubPullRequestOmitsEmptyContext(t *testing.T) {
	if got := GitHubPullRequest("acme/app", 42, " ", "\n"); got != nil {
		t.Fatalf("context = %#v", got)
	}
}

func TestValidateRejectsDuplicateSources(t *testing.T) {
	context := Context{
		SchemaVersion: SchemaVersion,
		Subject:       Subject{Provider: "github", Repository: "acme/app", PullRequest: 42},
		Sources: []Source{
			{Kind: "pull_request_title", Text: "one"},
			{Kind: "pull_request_title", Text: "two"},
		},
		Intent: Intent{Objective: "test", Confidence: "low"},
	}
	if err := context.Validate(); err == nil {
		t.Fatal("expected duplicate source validation error")
	}
}
