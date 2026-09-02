package githubapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// ReviewComment is the subset of a GitHub pull-request review comment needed
// to reconstruct feedback threads and post an acknowledgement.
type ReviewComment struct {
	ID                int64  `json:"id"`
	Body              string `json:"body"`
	HTMLURL           string `json:"html_url"`
	Path              string `json:"path"`
	Line              int    `json:"line"`
	CommitID          string `json:"commit_id"`
	OriginalCommitID  string `json:"original_commit_id"`
	InReplyToID       int64  `json:"in_reply_to_id"`
	AuthorAssociation string `json:"author_association"`
	CreatedAt         string `json:"created_at"`
	User              struct {
		Login string `json:"login"`
		Type  string `json:"type"`
	} `json:"user"`
}

// ListPullRequestReviewComments returns every inline comment and reply on a PR.
func (c *Client) ListPullRequestReviewComments(ctx context.Context, owner, repo string, number int) ([]ReviewComment, error) {
	path := fmt.Sprintf("/repos/%s/%s/pulls/%d/comments?per_page=100", url.PathEscape(owner), url.PathEscape(repo), number)
	raw, err := c.RESTGetPaginated(ctx, path)
	if err != nil {
		return nil, err
	}
	var comments []ReviewComment
	if err := json.Unmarshal(raw, &comments); err != nil {
		return nil, fmt.Errorf("decode pull request review comments: %w", err)
	}
	return comments, nil
}

// ReplyToPullRequestReviewComment posts a reply in an existing inline thread.
func (c *Client) ReplyToPullRequestReviewComment(ctx context.Context, owner, repo string, number int, commentID int64, body string) (ReviewComment, error) {
	if strings.TrimSpace(c.Token) == "" {
		return ReviewComment{}, fmt.Errorf("GitHub token required to reply to review comments")
	}
	if owner == "" || repo == "" || number <= 0 || commentID <= 0 || strings.TrimSpace(body) == "" {
		return ReviewComment{}, fmt.Errorf("owner, repo, pull request, comment, and body are required")
	}
	payload, err := json.Marshal(map[string]string{"body": body})
	if err != nil {
		return ReviewComment{}, err
	}
	path := fmt.Sprintf("/repos/%s/%s/pulls/%d/comments/%d/replies", url.PathEscape(owner), url.PathEscape(repo), number, commentID)
	raw, _, err := c.RESTPost(ctx, path, payload)
	if err != nil {
		return ReviewComment{}, err
	}
	var comment ReviewComment
	if err := json.Unmarshal(raw, &comment); err != nil {
		return ReviewComment{}, fmt.Errorf("decode review comment reply: %w", err)
	}
	if comment.ID == 0 {
		return ReviewComment{}, fmt.Errorf("review comment reply returned no id")
	}
	return comment, nil
}

// ReviewCommentTime parses GitHub's timestamp without making callers duplicate
// its wire-format handling.
func ReviewCommentTime(value string) time.Time {
	t, _ := time.Parse(time.RFC3339, value)
	return t
}
