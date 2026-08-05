package githubreview

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/adversarylabs/adversary/internal/application"
	"github.com/adversarylabs/adversary/internal/githubapi"
)

const maxInlineComments = 50

// PostOptions controls live GitHub review creation.
type PostOptions struct {
	Client   *githubapi.Client
	Owner    string
	Repo     string
	Number   int
	Submit   bool // submit as COMMENT after create
	DryRun   bool
	Progress func(string) // optional stderr messages
}

// PostResult is returned after a successful create/submit.
type PostResult struct {
	ReviewID  string
	ReviewURL string
	State     string
	Posted    int
	BodyOnly  int
}

// Post creates a pending PR review (optionally submits as COMMENT).
func Post(ctx context.Context, plan CommentPlan, opts PostOptions) (*PostResult, error) {
	if opts.DryRun {
		return &PostResult{}, nil
	}
	if opts.Client == nil {
		return nil, &application.Error{Operation: "github-review", Kind: "usage", Err: fmt.Errorf("github client required")}
	}
	if opts.Owner == "" || opts.Repo == "" || opts.Number <= 0 {
		return nil, &application.Error{Operation: "github-review", Kind: "usage", Err: fmt.Errorf("owner, repo, and pr number required")}
	}
	if len(plan.Comments) == 0 && strings.TrimSpace(plan.ReviewBody) == "" {
		if opts.Progress != nil {
			opts.Progress("GitHub review: nothing to post")
		}
		return &PostResult{}, nil
	}

	// Resolve GraphQL node id + head OID.
	var q struct {
		Repository struct {
			PullRequest struct {
				ID         string `json:"id"`
				HeadRefOid string `json:"headRefOid"`
				URL        string `json:"url"`
			} `json:"pullRequest"`
		} `json:"repository"`
	}
	err := opts.Client.GraphQL(ctx, `
query($owner:String!,$name:String!,$number:Int!){
  repository(owner:$owner,name:$name){
    pullRequest(number:$number){ id headRefOid url }
  }
}`, map[string]any{"owner": opts.Owner, "name": opts.Repo, "number": opts.Number}, &q)
	if err != nil {
		return nil, mapGitHubErr("resolve pull request", err)
	}
	prID := q.Repository.PullRequest.ID
	headOID := q.Repository.PullRequest.HeadRefOid
	if prID == "" || headOID == "" {
		return nil, &application.Error{Operation: "github-review", Kind: "network", Err: fmt.Errorf("pull request not found")}
	}

	// Fetch patches and place.
	files, err := opts.Client.ListPullRequestFiles(ctx, opts.Owner, opts.Repo, opts.Number)
	if err != nil {
		return nil, mapGitHubErr("list pull request files", err)
	}
	ApplyPlacement(&plan, files, headOID)

	// Cap inline threads.
	var threads []map[string]any
	var bodySections []string
	if strings.TrimSpace(plan.ReviewBody) != "" {
		bodySections = append(bodySections, strings.TrimSpace(plan.ReviewBody))
	}
	inline := 0
	for _, c := range plan.Comments {
		if c.Placement == "unplaceable" {
			continue
		}
		if c.Placement == "inline" && inline < maxInlineComments {
			th := map[string]any{
				"path": c.Anchor.Path,
				"body": c.Body,
				"line": *c.Anchor.Line,
				"side": c.Anchor.Side,
			}
			if c.Anchor.EndLine != nil && *c.Anchor.EndLine != *c.Anchor.Line {
				th["startLine"] = *c.Anchor.Line
				th["line"] = *c.Anchor.EndLine
				th["startSide"] = c.Anchor.Side
			}
			// For multi-line, GitHub wants startLine + line as end.
			if c.Anchor.EndLine != nil && *c.Anchor.EndLine != *c.Anchor.Line {
				th["startLine"] = *c.Anchor.Line
				th["line"] = *c.Anchor.EndLine
			}
			threads = append(threads, th)
			inline++
			continue
		}
		// review_body or overflow
		loc := c.Anchor.Path
		if c.Anchor.Line != nil {
			loc = fmt.Sprintf("%s:%d", c.Anchor.Path, *c.Anchor.Line)
		}
		bodySections = append(bodySections, fmt.Sprintf("### %s — %s\n\n%s\n\n_%s_", c.Severity, c.Title, c.Body, loc))
	}

	reviewBody := strings.Join(bodySections, "\n\n---\n\n")
	if reviewBody == "" {
		reviewBody = "Adversary review"
	}
	reviewBody += "\n\n<!-- adversary-review:v1 batch -->\n"

	input := map[string]any{
		"pullRequestId": prID,
		"commitOID":     headOID,
		"body":          reviewBody,
	}
	if len(threads) > 0 {
		input["threads"] = threads
	}

	var mut struct {
		AddPullRequestReview struct {
			PullRequestReview struct {
				ID    string `json:"id"`
				URL   string `json:"url"`
				State string `json:"state"`
			} `json:"pullRequestReview"`
		} `json:"addPullRequestReview"`
	}
	err = opts.Client.GraphQL(ctx, `
mutation($input:AddPullRequestReviewInput!){
  addPullRequestReview(input:$input){
    pullRequestReview{ id url state }
  }
}`, map[string]any{"input": input}, &mut)
	if err != nil {
		// Fallback: body-only pending review if threads field rejected.
		if strings.Contains(err.Error(), "threads") || strings.Contains(err.Error(), "Field") {
			delete(input, "threads")
			// Fold threads into body.
			for _, th := range threads {
				reviewBody += fmt.Sprintf("\n\n**%s**\n\n%v\n", th["path"], th["body"])
			}
			input["body"] = reviewBody
			err = opts.Client.GraphQL(ctx, `
mutation($input:AddPullRequestReviewInput!){
  addPullRequestReview(input:$input){
    pullRequestReview{ id url state }
  }
}`, map[string]any{"input": input}, &mut)
		}
		if err != nil {
			return nil, mapGitHubErr("add pull request review", err)
		}
	}

	res := &PostResult{
		ReviewID:  mut.AddPullRequestReview.PullRequestReview.ID,
		ReviewURL: mut.AddPullRequestReview.PullRequestReview.URL,
		State:     mut.AddPullRequestReview.PullRequestReview.State,
		Posted:    len(threads),
		BodyOnly:  len(bodySections),
	}

	if opts.Submit && res.ReviewID != "" {
		var sub struct {
			SubmitPullRequestReview struct {
				PullRequestReview struct {
					ID    string `json:"id"`
					URL   string `json:"url"`
					State string `json:"state"`
				} `json:"pullRequestReview"`
			} `json:"submitPullRequestReview"`
		}
		err = opts.Client.GraphQL(ctx, `
mutation($input:SubmitPullRequestReviewInput!){
  submitPullRequestReview(input:$input){
    pullRequestReview{ id url state }
  }
}`, map[string]any{"input": map[string]any{
			"pullRequestReviewId": res.ReviewID,
			"event":               "COMMENT",
		}}, &sub)
		if err != nil {
			return res, mapGitHubErr("submit pull request review", err)
		}
		res.State = sub.SubmitPullRequestReview.PullRequestReview.State
		if sub.SubmitPullRequestReview.PullRequestReview.URL != "" {
			res.ReviewURL = sub.SubmitPullRequestReview.PullRequestReview.URL
		}
	}

	if opts.Progress != nil && res.ReviewURL != "" {
		opts.Progress("GitHub review: " + res.ReviewURL + " (" + res.State + ")")
	}
	return res, nil
}

func mapGitHubErr(op string, err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	kind := "network"
	if _, ok := err.(*githubapi.AuthError); ok {
		kind = "auth"
	} else if strings.Contains(msg, "auth") || strings.Contains(msg, "401") || strings.Contains(msg, "403") {
		kind = "auth"
	}
	return &application.Error{Operation: op, Kind: kind, Err: err}
}

// WritePlanFile writes CommentPlan JSON.
func WritePlanFile(path string, plan CommentPlan) error {
	raw, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	return os.WriteFile(path, raw, 0o644)
}
