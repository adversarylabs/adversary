package reviewui

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/adversarylabs/adversary/internal/githubapi"
	"github.com/adversarylabs/adversary/internal/githubauth"
)

var discussionIDPattern = regexp.MustCompile(`(?:discussion_r|pullrequestreview-)([0-9]+)`)

// LoadGitHubContext loads source lines adjacent to the compact diff hunk. It
// uses the exact commit attached to the review comment, not the repository's
// current default branch.
func LoadGitHubContext(ctx context.Context, request ContextRequest) (ContextResult, error) {
	owner, repo, err := repositoryFromPRURL(request.PRURL)
	if err != nil {
		return ContextResult{}, err
	}
	match := discussionIDPattern.FindStringSubmatch(request.CommentURL)
	if len(match) != 2 {
		return ContextResult{}, fmt.Errorf("this finding has no inline GitHub review comment to expand")
	}
	commentID, err := strconv.ParseInt(match[1], 10, 64)
	if err != nil {
		return ContextResult{}, fmt.Errorf("parse review comment id: %w", err)
	}
	token, err := githubauth.RequireToken()
	if err != nil {
		return ContextResult{}, err
	}
	client := githubapi.NewClient(token)
	var comment struct {
		Path             string `json:"path"`
		CommitID         string `json:"commit_id"`
		OriginalCommitID string `json:"original_commit_id"`
	}
	if err := client.RESTGetJSON(ctx, fmt.Sprintf("/repos/%s/%s/pulls/comments/%d", url.PathEscape(owner), url.PathEscape(repo), commentID), &comment); err != nil {
		return ContextResult{}, fmt.Errorf("load review comment: %w", err)
	}
	ref := strings.TrimSpace(comment.OriginalCommitID)
	if ref == "" {
		ref = strings.TrimSpace(comment.CommitID)
	}
	path := strings.TrimSpace(comment.Path)
	if path == "" {
		path = strings.TrimSpace(request.File)
	}
	if ref == "" || path == "" {
		return ContextResult{}, fmt.Errorf("the review comment does not identify a file revision")
	}
	var content struct {
		Encoding string `json:"encoding"`
		Content  string `json:"content"`
	}
	endpoint := fmt.Sprintf("/repos/%s/%s/contents/%s?ref=%s", url.PathEscape(owner), url.PathEscape(repo), escapePath(path), url.QueryEscape(ref))
	if err := client.RESTGetJSON(ctx, endpoint, &content); err != nil {
		return ContextResult{}, fmt.Errorf("load source context: %w", err)
	}
	if content.Encoding != "base64" {
		return ContextResult{}, fmt.Errorf("GitHub returned unsupported source encoding %q", content.Encoding)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(content.Content, "\n", ""))
	if err != nil {
		return ContextResult{}, fmt.Errorf("decode source context: %w", err)
	}
	return contextWindow(strings.Split(string(raw), "\n"), request)
}

func repositoryFromPRURL(raw string) (string, string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", "", fmt.Errorf("parse PR URL: %w", err)
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) < 4 || parts[2] != "pull" || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("finding has no valid GitHub PR URL")
	}
	return parts[0], parts[1], nil
}

func escapePath(path string) string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	for i := range parts {
		parts[i] = url.PathEscape(parts[i])
	}
	return strings.Join(parts, "/")
}

func contextWindow(fileLines []string, request ContextRequest) (ContextResult, error) {
	oldStart, oldCount, newStart, newCount, err := hunkRange(request.DiffHunk)
	if err != nil {
		return ContextResult{}, err
	}
	// Review comment commit IDs point at the PR-side file. Prefer the new-side
	// range, falling back to the old range for unusual legacy hunks.
	start, count := newStart, newCount
	if start <= 0 {
		start, count = oldStart, oldCount
	}
	if count < 1 {
		count = 1
	}
	want := request.Count
	if want < 1 || want > 50 {
		want = 5
	}
	offset := request.Offset
	if offset < 0 {
		offset = 0
	}
	var first, last int // one-based inclusive
	if request.Direction == "up" {
		last = start - 1 - offset
		first = last - want + 1
		if first < 1 {
			first = 1
		}
	} else if request.Direction == "down" {
		first = start + count + offset
		last = first + want - 1
		if last > len(fileLines) {
			last = len(fileLines)
		}
	} else {
		return ContextResult{}, fmt.Errorf("direction must be up or down")
	}
	if first > last || first > len(fileLines) || last < 1 {
		return ContextResult{Lines: []ContextLine{}}, nil
	}
	lines := make([]ContextLine, 0, last-first+1)
	for number := first; number <= last; number++ {
		lines = append(lines, ContextLine{Number: number, Text: fileLines[number-1]})
	}
	hasMore := (request.Direction == "up" && first > 1) || (request.Direction == "down" && last < len(fileLines))
	return ContextResult{Lines: lines, HasMore: hasMore}, nil
}

func hunkRange(hunk string) (oldStart, oldCount, newStart, newCount int, err error) {
	header := strings.SplitN(strings.TrimSpace(hunk), "\n", 2)[0]
	re := regexp.MustCompile(`^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@`)
	match := re.FindStringSubmatch(header)
	if len(match) != 5 {
		return 0, 0, 0, 0, fmt.Errorf("inline diff range is unavailable")
	}
	oldStart, _ = strconv.Atoi(match[1])
	newStart, _ = strconv.Atoi(match[3])
	oldCount, newCount = 1, 1
	if match[2] != "" {
		oldCount, _ = strconv.Atoi(match[2])
	}
	if match[4] != "" {
		newCount, _ = strconv.Atoi(match[4])
	}
	return oldStart, oldCount, newStart, newCount, nil
}
