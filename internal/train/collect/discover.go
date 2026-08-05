package collect

import (
	"context"
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
	// Context cancels gh listing (Ctrl+C).
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
// Rate-limit policy: use one list call per repo; never probe each PR with extra
// comments/reviews API calls (that was burning authenticated quota under
// concurrent hunt). Prefer list metadata (reviews, commentsCount); otherwise
// accept non-bot merged PRs as candidates and let collect decide.
func DiscoverPRsWithOpts(owner, repo string, opts DiscoverOpts) ([]PRRef, error) {
	if opts.Limit <= 0 {
		opts.Limit = 5
	}
	if opts.ListLimit <= 0 {
		// Modest window: enough to skip-set progress without listing 100 every wave.
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
	if _, err := exec.LookPath("gh"); err != nil {
		return nil, fmt.Errorf("gh not installed")
	}
	ctx := opts.Context
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("discover interrupted: %w", err)
	}

	out, err := ghRun(ctx, "pr", "list",
		"--repo", owner+"/"+repo,
		"--state", "merged",
		"--limit", fmt.Sprintf("%d", opts.ListLimit),
		"--json", "number,title,url,author,reviews,commentsCount",
	)
	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("discover interrupted: %w", ctx.Err())
		}
		if IsRateLimit(err) {
			// Do NOT fall through to REST — that multiplies failed API calls.
			return nil, err
		}
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
		if IsRateLimit(err) {
			return nil, err
		}
		return discoverPRsREST(owner, repo, opts)
	}

	var candidates []PRRef
	var fallback []PRRef
	for _, p := range rows {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("discover interrupted: %w", err)
		}
		if opts.Skip[p.Number] {
			continue
		}
		login := strings.ToLower(p.Author.Login)
		if strings.Contains(login, "dependabot") || strings.Contains(login, "renovate") || strings.Contains(login, "bot") {
			continue
		}
		ref := PRRef{Number: p.Number, Title: p.Title, URL: p.URL}
		fallback = append(fallback, ref)
		// List metadata only — no per-PR hasReviewActivity probes.
		if len(p.Reviews) > 0 || p.CommentsCount > 0 {
			candidates = append(candidates, ref)
		}
		if len(candidates) >= opts.Limit {
			break
		}
	}
	if len(candidates) == 0 {
		// Still try merged non-bot PRs; collect will no-op if no human comments.
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
	// GitHub max per_page is 100; keep small to save quota.
	perPage := 40
	if opts.ListLimit > 0 && opts.ListLimit < perPage {
		perPage = opts.ListLimit
	}
	ctx := opts.Context
	if ctx == nil {
		ctx = context.Background()
	}
	api := fmt.Sprintf("repos/%s/%s/pulls?state=closed&per_page=%d&sort=created&direction=desc", owner, repo, perPage)
	out, err := ghRun(ctx, "api", api)
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
	if err := json.Unmarshal(out, &prs); err != nil {
		return nil, err
	}
	var candidates []PRRef
	for _, p := range prs {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("discover interrupted: %w", err)
		}
		if p.MergedAt == "" || opts.Skip[p.Number] {
			continue
		}
		login := strings.ToLower(p.User.Login)
		if strings.Contains(login, "dependabot") || strings.Contains(login, "bot") {
			continue
		}
		// No per-PR activity probes — rate-limit safe.
		candidates = append(candidates, PRRef{Number: p.Number, Title: p.Title, URL: p.HTMLURL})
		if len(candidates) >= opts.Limit {
			break
		}
	}
	if len(candidates) == 0 {
		return nil, fmt.Errorf("no new merged PRs for %s/%s (skipped %d)", owner, repo, len(opts.Skip))
	}
	return candidates, nil
}
