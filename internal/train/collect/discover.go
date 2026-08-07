package collect

import (
	"context"
	"encoding/json"
	"fmt"
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
	// Context cancels listing (Ctrl+C).
	Context context.Context
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
//
// Rate-limit policy: use REST list calls; never probe each PR with extra
// comments/reviews API calls under concurrent hunt.
func DiscoverPRsWithOpts(owner, repo string, opts DiscoverOpts) ([]PRRef, error) {
	if opts.Limit <= 0 {
		opts.Limit = 5
	}
	if opts.ListLimit <= 0 {
		opts.ListLimit = 40
		if opts.ListLimit < opts.Limit*8 {
			opts.ListLimit = opts.Limit * 8
		}
		if opts.ListLimit > 80 {
			opts.ListLimit = 80
		}
	}
	if opts.Skip == nil {
		opts.Skip = map[int]bool{}
	}
	ctx := opts.Context
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("discover interrupted: %w", err)
	}
	client, err := clientFor(ctx)
	if err != nil {
		return nil, err
	}

	// Single page only — do NOT use RESTGetPaginated here. Full pagination on
	// kubernetes/golang-scale repos downloads the entire closed-PR history (GB of
	// JSON) and appears hung for tens of minutes. ListLimit is a window cap.
	perPage := opts.ListLimit
	if perPage > 100 {
		perPage = 100
	}
	path := fmt.Sprintf("/repos/%s/%s/pulls?state=closed&per_page=%d&sort=updated&direction=desc", owner, repo, perPage)
	raw, _, err := client.RESTGet(ctx, path)
	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("discover interrupted: %w", ctx.Err())
		}
		return nil, err
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
	if err := json.Unmarshal(raw, &prs); err != nil {
		return nil, err
	}

	var candidates []PRRef
	var fallback []PRRef
	for _, p := range prs {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("discover interrupted: %w", err)
		}
		if p.MergedAt == "" || opts.Skip[p.Number] {
			continue
		}
		login := strings.ToLower(p.User.Login)
		if strings.Contains(login, "dependabot") || strings.Contains(login, "renovate") || strings.Contains(login, "bot") {
			continue
		}
		ref := PRRef{Number: p.Number, Title: p.Title, URL: p.HTMLURL}
		fallback = append(fallback, ref)
		// Without list-metadata reviews count, accept merged non-bot PRs.
		candidates = append(candidates, ref)
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
