package githubapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// SearchPR is one issue/PR search hit.
type SearchPR struct {
	Number     int    `json:"number"`
	Title      string `json:"title"`
	HTMLURL    string `json:"html_url"`
	Repository struct {
		FullName string `json:"full_name"`
	} `json:"repository_url"` // filled manually
	// REST search returns repository_url like https://api.github.com/repos/o/r
	RepoURL string `json:"repository_url"`
}

// SearchPullRequests runs GET /search/issues with type:pr query.
func (c *Client) SearchPullRequests(ctx context.Context, q string, perPage int) ([]SearchPR, error) {
	if perPage <= 0 {
		perPage = 30
	}
	if perPage > 100 {
		perPage = 100
	}
	path := fmt.Sprintf("/search/issues?q=%s&per_page=%d", url.QueryEscape(q), perPage)
	var result struct {
		Items []struct {
			Number        int    `json:"number"`
			Title         string `json:"title"`
			HTMLURL       string `json:"html_url"`
			RepositoryURL string `json:"repository_url"`
		} `json:"items"`
	}
	if err := c.RESTGetJSON(ctx, path, &result); err != nil {
		return nil, err
	}
	out := make([]SearchPR, 0, len(result.Items))
	for _, it := range result.Items {
		out = append(out, SearchPR{
			Number:  it.Number,
			Title:   it.Title,
			HTMLURL: it.HTMLURL,
			RepoURL: it.RepositoryURL,
		})
	}
	return out, nil
}

// OwnerRepoFromAPIURL parses .../repos/owner/name.
func OwnerRepoFromAPIURL(apiURL string) (owner, repo string) {
	const marker = "/repos/"
	i := strings.Index(apiURL, marker)
	if i < 0 {
		return "", ""
	}
	rest := apiURL[i+len(marker):]
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	if len(parts) < 2 {
		return "", ""
	}
	return parts[0], parts[1]
}

// BuildAuthorPRSearchQuery builds a GitHub search query for reviewed-by etc.
func BuildAuthorPRSearchQuery(author, role string, orgs []string, since string, mergedOnly bool) string {
	var parts []string
	parts = append(parts, "type:pr")
	if mergedOnly {
		parts = append(parts, "is:merged")
	}
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "reviewed-by", "reviewer", "reviews", "":
		parts = append(parts, "reviewed-by:"+author)
	case "commenter", "comments":
		parts = append(parts, "commenter:"+author)
	case "author":
		parts = append(parts, "author:"+author)
	default:
		parts = append(parts, "reviewed-by:"+author)
	}
	if since != "" {
		parts = append(parts, "merged:>="+strings.TrimSpace(since))
	}
	for _, org := range orgs {
		org = strings.TrimSpace(org)
		if org != "" {
			parts = append(parts, "org:"+org)
		}
	}
	return strings.Join(parts, " ")
}

// MarshalJSON helper unused — keep SearchPR simple.
var _ = json.Marshal
