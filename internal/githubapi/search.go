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
	Number  int    `json:"number"`
	Title   string `json:"title"`
	HTMLURL string `json:"html_url"`
	// RepoURL is the REST repository_url (https://api.github.com/repos/o/r).
	RepoURL string `json:"repository_url"`
}

// SearchPullRequests runs GET /search/issues with type:pr query.
// maxResults may exceed 100; pages are fetched until enough items or no more.
func (c *Client) SearchPullRequests(ctx context.Context, q string, maxResults int) ([]SearchPR, error) {
	if maxResults <= 0 {
		maxResults = 30
	}
	if maxResults > 1000 {
		// GitHub search API hard-caps around 1000 results.
		maxResults = 1000
	}
	perPage := 100
	if maxResults < perPage {
		perPage = maxResults
	}
	var out []SearchPR
	for page := 1; len(out) < maxResults; page++ {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		path := fmt.Sprintf("/search/issues?q=%s&per_page=%d&page=%d",
			url.QueryEscape(q), perPage, page)
		var result struct {
			Items []struct {
				Number        int    `json:"number"`
				Title         string `json:"title"`
				HTMLURL       string `json:"html_url"`
				RepositoryURL string `json:"repository_url"`
			} `json:"items"`
			IncompleteResults bool `json:"incomplete_results"`
		}
		if err := c.RESTGetJSON(ctx, path, &result); err != nil {
			return out, err
		}
		if len(result.Items) == 0 {
			break
		}
		for _, it := range result.Items {
			out = append(out, SearchPR{
				Number:  it.Number,
				Title:   it.Title,
				HTMLURL: it.HTMLURL,
				RepoURL: it.RepositoryURL,
			})
			if len(out) >= maxResults {
				break
			}
		}
		if len(result.Items) < perPage {
			break
		}
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
func BuildAuthorPRSearchQuery(author, role string, orgs []string, since, language string, mergedOnly bool) string {
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
	if language != "" {
		parts = append(parts, "language:"+strings.TrimSpace(language))
	}
	for _, org := range orgs {
		org = strings.TrimSpace(org)
		if org != "" {
			parts = append(parts, "org:"+org)
		}
	}
	return strings.Join(parts, " ")
}

// Ensure json is used if we add more types later.
var _ = json.Marshal
