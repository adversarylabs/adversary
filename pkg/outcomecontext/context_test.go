package outcomecontext

import (
	"strings"
	"testing"
)

func TestGitHubPullRequestBuildsBoundedAttributedSources(t *testing.T) {
	context := GitHubPullRequest("acme/app", 42, "  Add delegated trust  ", strings.Repeat("x", MaxTextBytes+10))
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

func TestGitHubPullRequestOmitsEmptyContext(t *testing.T) {
	if got := GitHubPullRequest("acme/app", 42, " ", "\n"); got != nil {
		t.Fatalf("context = %#v", got)
	}
}

func TestValidateRejectsDuplicateSources(t *testing.T) {
	context := Context{
		SchemaVersion: SchemaVersion,
		Sources: []Source{
			{Kind: "pull_request_title", Text: "one"},
			{Kind: "pull_request_title", Text: "two"},
		},
	}
	if err := context.Validate(); err == nil {
		t.Fatal("expected duplicate source validation error")
	}
}
