package githubapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// Issue is a created or fetched GitHub issue.
type Issue struct {
	Number  int    `json:"number"`
	HTMLURL string `json:"html_url"`
	Title   string `json:"title"`
	State   string `json:"state"`
}

// CreateIssueInput is the body for POST /repos/{owner}/{repo}/issues.
type CreateIssueInput struct {
	Title  string   `json:"title"`
	Body   string   `json:"body,omitempty"`
	Labels []string `json:"labels,omitempty"`
}

// CreateIssue opens an issue on owner/repo. Requires a token with issues:write.
func (c *Client) CreateIssue(ctx context.Context, owner, repo string, in CreateIssueInput) (Issue, error) {
	owner = strings.TrimSpace(owner)
	repo = strings.TrimSpace(repo)
	if owner == "" || repo == "" {
		return Issue{}, fmt.Errorf("owner and repo are required")
	}
	if strings.TrimSpace(in.Title) == "" {
		return Issue{}, fmt.Errorf("issue title is required")
	}
	if strings.TrimSpace(c.Token) == "" {
		return Issue{}, fmt.Errorf("GitHub token required to create issues")
	}
	path := fmt.Sprintf("/repos/%s/%s/issues", url.PathEscape(owner), url.PathEscape(repo))
	payload, err := json.Marshal(in)
	if err != nil {
		return Issue{}, err
	}
	body, _, err := c.RESTPost(ctx, path, payload)
	if err != nil {
		return Issue{}, err
	}
	var issue Issue
	if err := json.Unmarshal(body, &issue); err != nil {
		return Issue{}, fmt.Errorf("decode create issue response: %w", err)
	}
	if issue.HTMLURL == "" {
		return Issue{}, fmt.Errorf("create issue: empty html_url in response")
	}
	return issue, nil
}

// RESTPost performs POST restBase+path with a JSON body (no automatic retries).
func (c *Client) RESTPost(ctx context.Context, path string, body []byte) ([]byte, http.Header, error) {
	return c.do(ctx, http.MethodPost, c.resolveREST(path), body, false)
}
