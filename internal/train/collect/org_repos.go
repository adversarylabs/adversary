package collect

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/adversarylabs/adversary/internal/githubapi"
)

// OrgRepo is one repository listed under a GitHub organization (or user).
type OrgRepo struct {
	Owner string
	Name  string
}

// FullName returns owner/name.
func (r OrgRepo) FullName() string {
	return r.Owner + "/" + r.Name
}

// ListOrgRepos lists non-archived repositories for a GitHub org (or user) via HTTP.
// When allowlist is non-empty, only repos whose name matches (case-insensitive)
// are returned. names in allowlist may be bare ("payments-api") or full
// ("acme/payments-api").
func ListOrgRepos(ctx context.Context, org string, allowlist []string) ([]OrgRepo, error) {
	org = strings.TrimSpace(org)
	if org == "" {
		return nil, fmt.Errorf("org is empty")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("list org repos interrupted: %w", err)
	}
	client, err := clientFor(ctx)
	if err != nil {
		return nil, err
	}

	// Prefer organization endpoint; fall back to user repos for personal accounts.
	raw, err := client.RESTGetPaginated(ctx, fmt.Sprintf("/orgs/%s/repos?per_page=100&type=all", org))
	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("list org repos interrupted: %w", ctx.Err())
		}
		raw2, err2 := client.RESTGetPaginated(ctx, fmt.Sprintf("/users/%s/repos?per_page=100&type=all", org))
		if err2 != nil {
			if ctx.Err() != nil {
				return nil, fmt.Errorf("list org repos interrupted: %w", ctx.Err())
			}
			return nil, fmt.Errorf("list repos for %q: org: %v; user: %w", org, err, err2)
		}
		raw = raw2
	}

	repos, err := parseOrgReposJSON(raw)
	if err != nil {
		return nil, err
	}
	return filterOrgRepos(repos, allowlist), nil
}

// parseOrgReposJSON decodes a GitHub repos list payload.
func parseOrgReposJSON(raw []byte) ([]OrgRepo, error) {
	s := strings.TrimSpace(string(raw))
	if s == "" {
		return nil, nil
	}
	// Legacy concatenated pages from gh --paginate still supported for tests.
	if strings.Contains(s, "][") {
		s = "[" + strings.ReplaceAll(strings.TrimPrefix(strings.TrimSuffix(s, "]"), "["), "][", ",") + "]"
	}
	var rows []struct {
		Name     string `json:"name"`
		FullName string `json:"full_name"`
		Archived bool   `json:"archived"`
		Owner    struct {
			Login string `json:"login"`
		} `json:"owner"`
	}
	if err := json.Unmarshal([]byte(s), &rows); err != nil {
		return nil, fmt.Errorf("parse org repos JSON: %w", err)
	}
	var out []OrgRepo
	for _, r := range rows {
		if r.Archived {
			continue
		}
		owner := strings.TrimSpace(r.Owner.Login)
		name := strings.TrimSpace(r.Name)
		if owner == "" || name == "" {
			if parts := strings.SplitN(strings.TrimSpace(r.FullName), "/", 2); len(parts) == 2 {
				owner, name = parts[0], parts[1]
			}
		}
		if owner == "" || name == "" {
			continue
		}
		out = append(out, OrgRepo{Owner: owner, Name: name})
	}
	return out, nil
}

// filterOrgRepos applies an optional name allowlist.
func filterOrgRepos(repos []OrgRepo, allowlist []string) []OrgRepo {
	if len(allowlist) == 0 {
		return repos
	}
	want := map[string]bool{}
	for _, a := range allowlist {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		// Accept bare name or owner/name.
		if i := strings.Index(a, "/"); i >= 0 {
			a = a[i+1:]
		}
		want[strings.ToLower(a)] = true
	}
	if len(want) == 0 {
		return repos
	}
	var out []OrgRepo
	for _, r := range repos {
		if want[strings.ToLower(r.Name)] {
			out = append(out, r)
		}
	}
	return out
}

// Ensure githubapi is referenced for clients.
var _ = githubapi.DefaultRESTBase
