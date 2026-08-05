package collect

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

// PRRef is a discovered pull request candidate.
type PRRef struct {
	Number int
	Title  string
	URL    string
}

// DiscoverOpts controls discovery filtering.
type DiscoverOpts struct {
	// Limit is how many NEW candidates to return (not including skipped).
	Limit int
	// Skip PRs already in discovery state (or any other set).
	Skip map[int]bool
	// ListLimit is how many merged PRs to pull from GitHub before filtering.
	ListLimit int
}

// DiscoverPRs finds recently merged PRs that look like they have human review activity.
func DiscoverPRs(owner, repo string, limit int) ([]PRRef, error) {
	return DiscoverPRsWithOpts(owner, repo, DiscoverOpts{Limit: limit})
}

// DiscoverPRsWithOpts is DiscoverPRs with skip-set and larger list window.
func DiscoverPRsWithOpts(owner, repo string, opts DiscoverOpts) ([]PRRef, error) {
	if opts.Limit <= 0 {
		opts.Limit = 5
	}
	if opts.ListLimit <= 0 {
		// Pull a wide window so skip-set still leaves fresh candidates.
		opts.ListLimit = 100
		if opts.ListLimit < opts.Limit*10 {
			opts.ListLimit = opts.Limit * 10
		}
		if opts.ListLimit > 200 {
			opts.ListLimit = 200
		}
	}
	if opts.Skip == nil {
		opts.Skip = map[int]bool{}
	}
	if _, err := exec.LookPath("gh"); err != nil {
		return nil, fmt.Errorf("gh not installed")
	}

	cmd := exec.Command("gh", "pr", "list",
		"--repo", owner+"/"+repo,
		"--state", "merged",
		"--limit", fmt.Sprintf("%d", opts.ListLimit),
		"--json", "number,title,url,author,reviews,commentsCount",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return discoverPRsREST(owner, repo, opts)
	}

	var rows []struct {
		Number        int    `json:"number"`
		Title         string `json:"title"`
		URL           string `json:"url"`
		CommentsCount int    `json:"commentsCount"`
		Author        struct {
			Login string `json:"login"`
		} `json:"author"`
		Reviews []struct {
			State string `json:"state"`
		} `json:"reviews"`
	}
	if err := json.Unmarshal(out, &rows); err != nil {
		return discoverPRsREST(owner, repo, opts)
	}

	var candidates []PRRef
	var fallback []PRRef
	for _, p := range rows {
		if opts.Skip[p.Number] {
			continue
		}
		login := strings.ToLower(p.Author.Login)
		if strings.Contains(login, "dependabot") || strings.Contains(login, "renovate") || strings.Contains(login, "bot") {
			continue
		}
		ref := PRRef{Number: p.Number, Title: p.Title, URL: p.URL}
		fallback = append(fallback, ref)
		if len(p.Reviews) > 0 || p.CommentsCount > 0 || hasReviewActivity(owner, repo, p.Number) {
			candidates = append(candidates, ref)
		}
		if len(candidates) >= opts.Limit {
			break
		}
	}
	if len(candidates) == 0 {
		for _, ref := range fallback {
			candidates = append(candidates, ref)
			if len(candidates) >= opts.Limit {
				break
			}
		}
	}
	if len(candidates) == 0 {
		return nil, fmt.Errorf("no new merged PRs for %s/%s (skipped %d already-seen)", owner, repo, len(opts.Skip))
	}
	return candidates, nil
}

func discoverPRsREST(owner, repo string, opts DiscoverOpts) ([]PRRef, error) {
	// GitHub max per_page is 100; paginate lightly if needed.
	perPage := 100
	if opts.ListLimit > 0 && opts.ListLimit < perPage {
		perPage = opts.ListLimit
	}
	api := fmt.Sprintf("repos/%s/%s/pulls?state=closed&per_page=%d&sort=created&direction=desc", owner, repo, perPage)
	cmd := exec.Command("gh", "api", api)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("gh api: %w (%s)", err, sanitize(string(out)))
	}
	var prs []struct {
		Number   int    `json:"number"`
		Title    string `json:"title"`
		HTMLURL  string `json:"html_url"`
		MergedAt string `json:"merged_at"`
		User     struct {
			Login string `json:"login"`
		} `json:"user"`
	}
	if err := json.Unmarshal(out, &prs); err != nil {
		return nil, err
	}
	var candidates []PRRef
	for _, p := range prs {
		if p.MergedAt == "" || opts.Skip[p.Number] {
			continue
		}
		login := strings.ToLower(p.User.Login)
		if strings.Contains(login, "dependabot") || strings.Contains(login, "bot") {
			continue
		}
		if !hasReviewActivity(owner, repo, p.Number) {
			continue
		}
		candidates = append(candidates, PRRef{Number: p.Number, Title: p.Title, URL: p.HTMLURL})
		if len(candidates) >= opts.Limit {
			break
		}
	}
	if len(candidates) == 0 {
		return nil, fmt.Errorf("no new merged PRs with review activity for %s/%s (skipped %d)", owner, repo, len(opts.Skip))
	}
	return candidates, nil
}

func hasReviewActivity(owner, repo string, pr int) bool {
	cOut, err := exec.Command("gh", "api",
		fmt.Sprintf("repos/%s/%s/pulls/%d/comments", owner, repo, pr)).CombinedOutput()
	if err != nil {
		return false
	}
	var comments []struct {
		Body string `json:"body"`
	}
	if json.Unmarshal(cOut, &comments) != nil {
		return false
	}
	for _, c := range comments {
		if len(strings.TrimSpace(c.Body)) > 30 {
			return true
		}
	}
	// formal reviews with body
	revOut, err := exec.Command("gh", "api",
		fmt.Sprintf("repos/%s/%s/pulls/%d/reviews", owner, repo, pr)).CombinedOutput()
	if err != nil {
		return false
	}
	var revs []struct {
		Body  string `json:"body"`
		State string `json:"state"`
	}
	if json.Unmarshal(revOut, &revs) != nil {
		return false
	}
	for _, r := range revs {
		if r.State == "PENDING" {
			continue
		}
		if len(strings.TrimSpace(r.Body)) > 40 {
			return true
		}
	}
	return false
}
