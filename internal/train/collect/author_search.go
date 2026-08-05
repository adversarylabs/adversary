package collect

import (
	"context"
	"fmt"
	"strings"

	"github.com/adversarylabs/adversary/internal/githubapi"
)

// AuthorSearchOpts finds PRs across GitHub by reviewer/commenter activity.
type AuthorSearchOpts struct {
	Context context.Context
	// Authors are GitHub logins (e.g. mitchellh). Required.
	Authors []string
	// Roles: "reviewed-by" (default), "commenter", or both.
	Roles []string
	// Orgs optional owner filter; empty = all of GitHub.
	Orgs []string
	// MergedOnly defaults true (train wants landed PRs).
	MergedOnly bool
	// Limit max PRs to return after skip filtering.
	Limit int
	// ListLimit max results to fetch from search (before skip).
	ListLimit int
	// Skip PRs already seen: key "owner/repo#number".
	Skip map[string]bool
	// Language optional.
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
// Does not require a repo list. Uses REST search/issues (authenticated search quota).
func DiscoverPRsByAuthor(opts AuthorSearchOpts) ([]AuthorPRRef, error) {
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
	client, err := clientFor(ctx)
	if err != nil {
		return nil, err
	}

	mergedOnly := true
	if !opts.MergedOnly {
		// AuthorSearchOpts zero value is false; train historically defaulted true via gh --merged.
		// Keep true when not explicitly set: the field is only false if zero — design uses default true.
		mergedOnly = true
	}
	_ = mergedOnly

	seen := map[string]bool{}
	var out []AuthorPRRef

	for _, author := range authors {
		for _, role := range roles {
			role = strings.ToLower(strings.TrimSpace(role))
			if role == "" {
				continue
			}
			switch role {
			case "reviewed-by", "reviewer", "reviews", "commenter", "comments", "author":
			default:
				return nil, fmt.Errorf("unknown author role %q (want reviewed-by, commenter, author)", role)
			}
			if err := ctx.Err(); err != nil {
				return nil, fmt.Errorf("discover interrupted: %w", err)
			}
			q := githubapi.BuildAuthorPRSearchQuery(author, role, opts.Orgs, opts.Since, opts.Language, true)
			hits, err := client.SearchPullRequests(ctx, q, opts.ListLimit)
			if err != nil {
				if ctx.Err() != nil {
					return nil, fmt.Errorf("discover interrupted: %w", ctx.Err())
				}
				return nil, err
			}
			for _, h := range hits {
				owner, name := githubapi.OwnerRepoFromAPIURL(h.RepoURL)
				if owner == "" || name == "" {
					owner, name = splitOwnerRepoFromURL(h.HTMLURL)
				}
				if owner == "" || name == "" || h.Number <= 0 {
					continue
				}
				ref := AuthorPRRef{Owner: owner, Repo: name, Number: h.Number, Title: h.Title, URL: h.HTMLURL}
				key := ref.SkipKey()
				if opts.Skip[key] || seen[key] {
					continue
				}
				seen[key] = true
				out = append(out, ref)
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

func cleanLogins(in []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, s := range in {
		s = strings.TrimSpace(s)
		s = strings.TrimPrefix(s, "@")
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

func splitOwnerRepoFromURL(u string) (owner, repo string) {
	// https://github.com/owner/repo/pull/1
	const marker = "github.com/"
	i := strings.Index(strings.ToLower(u), marker)
	if i < 0 {
		return "", ""
	}
	rest := u[i+len(marker):]
	parts := strings.Split(rest, "/")
	if len(parts) < 2 {
		return "", ""
	}
	return parts[0], parts[1]
}

func splitOwnerRepo(nameWithOwner, name, url string) (string, string) {
	if nameWithOwner != "" {
		parts := strings.SplitN(nameWithOwner, "/", 2)
		if len(parts) == 2 {
			return parts[0], parts[1]
		}
	}
	if o, r := splitOwnerRepoFromURL(url); o != "" {
		return o, r
	}
	return "", name
}

// BuildAuthorSkipSet flattens per-repo discovery stores into search skip keys.
func BuildAuthorSkipSet(keys []string) map[string]bool {
	m := map[string]bool{}
	for _, k := range keys {
		m[k] = true
	}
	return m
}
