package collect

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

// AuthorSearchOpts finds PRs across GitHub by reviewer/commenter activity.
type AuthorSearchOpts struct {
	Context context.Context
	// Authors are GitHub logins (e.g. mitchellh). Required.
	Authors []string
	// Roles: "reviewed-by" (default), "commenter", or both.
	// Maps to gh search prs flags.
	Roles []string
	// Orgs optional owner filter (gh --owner); empty = all of GitHub.
	Orgs []string
	// MergedOnly defaults true (train wants landed PRs).
	MergedOnly bool
	// Limit max PRs to return after skip filtering.
	Limit int
	// ListLimit max results to fetch from search (before skip).
	ListLimit int
	// Skip PRs already seen: key "owner/repo#number".
	Skip map[string]bool
	// Language optional (gh --language).
	Language string
	// Since optional ISO date (merged-at >=) e.g. "2022-01-01".
	Since string
}

// AuthorPRRef is a search hit with repo coordinates.
type AuthorPRRef struct {
	Owner  string
	Repo   string
	Number int
	Title  string
	URL    string
}

// SkipKey is the discovery skip identity for a PR.
func (r AuthorPRRef) SkipKey() string {
	return fmt.Sprintf("%s/%s#%d", r.Owner, r.Repo, r.Number)
}

func (r AuthorPRRef) PRRef() PRRef {
	return PRRef{Number: r.Number, Title: r.Title, URL: r.URL}
}

// DiscoverPRsByAuthor searches GitHub for PRs this person reviewed (and/or commented on).
// Does not require a repo list. Uses `gh search prs` (authenticated search quota).
func DiscoverPRsByAuthor(opts AuthorSearchOpts) ([]AuthorPRRef, error) {
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
	authors := cleanLogins(opts.Authors)
	if len(authors) == 0 {
		return nil, fmt.Errorf("authors required for author-based discovery")
	}
	roles := opts.Roles
	if len(roles) == 0 {
		roles = []string{"reviewed-by"}
	}
	if opts.Limit <= 0 {
		opts.Limit = 30
	}
	if opts.ListLimit <= 0 {
		opts.ListLimit = opts.Limit * 3
		if opts.ListLimit < 50 {
			opts.ListLimit = 50
		}
		if opts.ListLimit > 200 {
			opts.ListLimit = 200
		}
	}
	if opts.Skip == nil {
		opts.Skip = map[string]bool{}
	}
	seen := map[string]bool{}
	var out []AuthorPRRef

	for _, author := range authors {
		for _, role := range roles {
			role = strings.ToLower(strings.TrimSpace(role))
			if role == "" {
				continue
			}
			if err := ctx.Err(); err != nil {
				return nil, fmt.Errorf("discover interrupted: %w", err)
			}
			hits, err := searchPRsForAuthor(ctx, author, role, opts)
			if err != nil {
				return nil, err
			}
			for _, h := range hits {
				key := h.SkipKey()
				if opts.Skip[key] || seen[key] {
					continue
				}
				seen[key] = true
				out = append(out, h)
				if len(out) >= opts.Limit {
					return out, nil
				}
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no PRs found for authors %v (roles %v); try different logins or drop org filters", authors, roles)
	}
	return out, nil
}

func searchPRsForAuthor(ctx context.Context, author, role string, opts AuthorSearchOpts) ([]AuthorPRRef, error) {
	args := []string{"search", "prs", "--json", "number,title,url,repository", "-L", fmt.Sprintf("%d", opts.ListLimit)}
	switch role {
	case "reviewed-by", "reviewer", "reviews":
		args = append(args, "--reviewed-by", author)
	case "commenter", "comments":
		args = append(args, "--commenter", author)
	case "author":
		// PRs they authored — usually not what we want for "review like X", but supported.
		args = append(args, "--author", author)
	default:
		return nil, fmt.Errorf("unknown author role %q (want reviewed-by, commenter, author)", role)
	}
	// Merged PRs for reconstructable history.
	args = append(args, "--merged")
	if opts.Language != "" {
		args = append(args, "--language", opts.Language)
	}
	if opts.Since != "" {
		// GitHub search: merged:>=DATE
		args = append(args, "--merged-at", ">="+strings.TrimSpace(opts.Since))
	}
	for _, org := range opts.Orgs {
		org = strings.TrimSpace(org)
		if org != "" {
			args = append(args, "--owner", org)
		}
	}

	out, err := ghRun(ctx, args...)
	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("discover interrupted: %w", ctx.Err())
		}
		return nil, err
	}

	var rows []struct {
		Number     int    `json:"number"`
		Title      string `json:"title"`
		URL        string `json:"url"`
		Repository struct {
			Name          string `json:"name"`
			NameWithOwner string `json:"nameWithOwner"`
		} `json:"repository"`
	}
	if err := json.Unmarshal(out, &rows); err != nil {
		return nil, fmt.Errorf("parse gh search prs: %w", err)
	}

	var hits []AuthorPRRef
	for _, r := range rows {
		owner, name := splitOwnerRepo(r.Repository.NameWithOwner, r.Repository.Name, r.URL)
		if owner == "" || name == "" || r.Number <= 0 {
			continue
		}
		hits = append(hits, AuthorPRRef{
			Owner:  owner,
			Repo:   name,
			Number: r.Number,
			Title:  r.Title,
			URL:    r.URL,
		})
	}
	return hits, nil
}

func splitOwnerRepo(nameWithOwner, name, url string) (owner, repo string) {
	if nameWithOwner != "" {
		parts := strings.SplitN(nameWithOwner, "/", 2)
		if len(parts) == 2 {
			return parts[0], parts[1]
		}
	}
	// https://github.com/owner/repo/pull/1
	if strings.Contains(url, "github.com/") {
		rest := url
		if i := strings.Index(rest, "github.com/"); i >= 0 {
			rest = rest[i+len("github.com/"):]
		}
		parts := strings.Split(rest, "/")
		if len(parts) >= 2 {
			return parts[0], parts[1]
		}
	}
	return "", name
}

func cleanLogins(in []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, a := range in {
		a = strings.TrimSpace(strings.TrimPrefix(a, "@"))
		if a == "" {
			continue
		}
		key := strings.ToLower(a)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, a)
	}
	return out
}

// BuildAuthorSkipSet flattens per-repo discovery stores into search skip keys.
// Caller may also pass an empty map and filter after LoadDiscovery per hit.
func BuildAuthorSkipSet(keys []string) map[string]bool {
	m := map[string]bool{}
	for _, k := range keys {
		m[k] = true
	}
	return m
}
