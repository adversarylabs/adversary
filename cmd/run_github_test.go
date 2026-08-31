package cmd

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/adversarylabs/adversary/internal/githubapi"
	"github.com/adversarylabs/adversary/internal/githubreview"
	"github.com/adversarylabs/adversary/internal/modelreview"
	"github.com/adversarylabs/adversary/pkg/review"
)

func TestPeelPRURL(t *testing.T) {
	pr, rest, err := peelPRURL([]string{"https://github.com/acme/app/pull/9", "adversarylabs/go-cli"})
	if err != nil {
		t.Fatal(err)
	}
	if pr == nil || pr.Number != 9 || pr.Owner != "acme" || pr.Repo != "app" {
		t.Fatalf("%#v", pr)
	}
	if len(rest) != 1 || rest[0] != "adversarylabs/go-cli" {
		t.Fatalf("%v", rest)
	}
	_, _, err = peelPRURL([]string{
		"https://github.com/a/b/pull/1",
		"https://github.com/a/b/pull/2",
	})
	if err == nil {
		t.Fatal("expected multi URL error")
	}
	pr, rest, err = peelPRURL([]string{"go-cli", "secrets"})
	if err != nil || pr != nil || len(rest) != 2 {
		t.Fatalf("%v %v %v", pr, rest, err)
	}
}

func TestCollectEnvelopeAndProjectUnderFindings(t *testing.T) {
	var envs []githubreview.NamedEnvelope
	line := 4
	collectEnvelope(&envs, "go-cli")(review.RunEnvelope{
		ProtocolVersion: 1,
		Result: review.ReviewResult{
			Adversary:    review.ReviewAdversary{Name: "go-cli"},
			Positives:    []review.Note{{Key: "p", Summary: "nice"}},
			Observations: []review.Note{{Key: "o", Summary: "note"}},
			Findings: []review.Finding{
				{
					ID: "f1", Title: "Issue", Category: "c", Severity: "high", Confidence: "high",
					Summary: "bad", Evidence: []review.Evidence{{File: "main.go", Line: &line}},
					Recommendation: "fix it",
				},
				{
					ID: "f2", Title: "Low", Category: "c", Severity: "low", Confidence: "high",
					Summary: "meh", Evidence: []review.Evidence{{File: "x.go", Line: &line}},
				},
			},
			Suppressed: review.Suppressed{},
			SuppressedFindings: []review.Finding{
				{ID: "sup", Title: "S", Category: "c", Severity: "high", Confidence: "high", Summary: "no", Evidence: []review.Evidence{}},
			},
		},
	})
	if len(envs) != 1 {
		t.Fatalf("%d", len(envs))
	}
	plan := githubreview.ProjectFindings(envs, githubreview.ProjectOptions{
		Repository:  "acme/app",
		PullRequest: 1,
		MinSeverity: "medium",
		Voice:       githubreview.VoiceInfo{Source: "cli_default"},
	})
	if len(plan.Comments) != 1 || plan.Comments[0].FindingID != "f1" {
		t.Fatalf("%#v", plan.Comments)
	}
	if plan.Skipped[0].Reason != "below_min_severity" {
		t.Fatalf("%#v", plan.Skipped)
	}
	raw, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"sup"`) || strings.Contains(string(raw), "nice") {
		t.Fatalf("leaked: %s", raw)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "plan.json")
	if err := githubreview.WritePlanFile(path, plan); err != nil {
		t.Fatal(err)
	}
	githubreview.MarkDiffNotFetched(&plan)
	for _, c := range plan.Comments {
		switch c.Placement {
		case "inline", "review_body", "unplaceable":
		default:
			t.Fatalf("bad placement %q", c.Placement)
		}
	}
}

func TestResolvePRRunContextFlagConflicts(t *testing.T) {
	ctx := context.Background()
	ref := &githubapi.PRRef{Owner: "acme", Repo: "app", Number: 42}

	cases := []struct {
		name    string
		opts    runOptions
		wantSub string
	}{
		{
			name: "disagreeing github-pr",
			opts: runOptions{
				prURL:    ref,
				githubPR: 99,
			},
			wantSub: "disagrees with PR URL number",
		},
		{
			name: "disagreeing github-repo",
			opts: runOptions{
				prURL:      ref,
				githubRepo: "other/repo",
			},
			wantSub: "disagrees with PR URL",
		},
		{
			name: "matching flags not conflict",
			opts: runOptions{
				prURL:      ref,
				githubPR:   42,
				githubRepo: "acme/app",
			},
			wantSub: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := resolvePRRunContext(ctx, &tc.opts, nil)
			if tc.wantSub == "" {
				if err != nil && strings.Contains(err.Error(), "disagrees") {
					t.Fatalf("unexpected conflict: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("err=%v want substring %q", err, tc.wantSub)
			}
		})
	}
}

func TestMaybeGitHubReviewEnhancesWithFakeProviderWiring(t *testing.T) {
	// Same sequence as maybeGitHubReview: ProjectFindings then EnhanceBodies with voice prompt.
	line := 5
	envs := []githubreview.NamedEnvelope{{
		Adversary: "go-cli",
		Envelope: review.RunEnvelope{
			ProtocolVersion: 1,
			Result: review.ReviewResult{
				Adversary:    review.ReviewAdversary{Name: "go-cli"},
				Positives:    []review.Note{},
				Observations: []review.Note{},
				Findings: []review.Finding{{
					ID: "fx", Title: "Bug", Category: "c", Severity: "high", Confidence: "high",
					Summary: "sum", Evidence: []review.Evidence{{File: "z.go", Line: &line}},
				}},
				Suppressed: review.Suppressed{},
			},
		},
	}}
	plan := githubreview.ProjectFindings(envs, githubreview.ProjectOptions{
		Repository: "acme/app", PullRequest: 1, Voice: githubreview.VoiceInfo{Source: "cli_default"},
	})
	if plan.Comments[0].BodySource != "template" {
		t.Fatalf("expected template first: %s", plan.Comments[0].BodySource)
	}
	fp := &cmdEnhanceFake{body: "LLM polished comment"}
	githubreview.EnhanceBodies(context.Background(), &plan, githubreview.EnhanceOptions{
		Provider:    fp,
		VoicePrompt: githubreview.DefaultVoicePrompt,
	})
	if plan.Comments[0].BodySource != "llm" || !strings.Contains(plan.Comments[0].Body, "LLM polished") {
		t.Fatalf("%#v", plan.Comments[0])
	}
	if !strings.Contains(plan.Comments[0].Body, "adversary-review:v2") {
		t.Fatal("marker missing")
	}
	if fp.calls != 1 {
		t.Fatalf("calls %d", fp.calls)
	}
}

type cmdEnhanceFake struct {
	body  string
	calls int
}

func (e *cmdEnhanceFake) Name() string  { return "fake" }
func (e *cmdEnhanceFake) Model() string { return "m" }
func (e *cmdEnhanceFake) Review(_ context.Context, req modelreview.Request) (modelreview.Result, error) {
	e.calls++
	if strings.TrimSpace(req.Prompt) == "" {
		return modelreview.Result{}, &modelreview.ProviderError{Message: "empty prompt"}
	}
	out, _ := json.Marshal(map[string]string{"body": e.body})
	return modelreview.Result{Output: out}, nil
}
