package githubapi

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// PullRequest is a subset of the REST pull object.
type PullRequest struct {
	Number  int    `json:"number"`
	Title   string `json:"title"`
	HTMLURL string `json:"html_url"`
	State   string `json:"state"`
	Merged  bool   `json:"merged"`
	Base    struct {
		Ref  string `json:"ref"`
		SHA  string `json:"sha"`
		Repo struct {
			FullName string `json:"full_name"`
			CloneURL string `json:"clone_url"`
			Owner    struct {
				Login string `json:"login"`
			} `json:"owner"`
			Name string `json:"name"`
		} `json:"repo"`
	} `json:"base"`
	Head struct {
		Ref  string `json:"ref"`
		SHA  string `json:"sha"`
		Repo *struct {
			FullName string `json:"full_name"`
			CloneURL string `json:"clone_url"`
			Owner    struct {
				Login string `json:"login"`
			} `json:"owner"`
			Name string `json:"name"`
		} `json:"repo"`
	} `json:"head"`
}

// GetPullRequest fetches one PR.
func (c *Client) GetPullRequest(ctx context.Context, owner, repo string, number int) (*PullRequest, error) {
	path := fmt.Sprintf("/repos/%s/%s/pulls/%d", owner, repo, number)
	var pr PullRequest
	if err := c.RESTGetJSON(ctx, path, &pr); err != nil {
		return nil, err
	}
	return &pr, nil
}

// PRFile is one changed file with optional unified patch.
type PRFile struct {
	Filename         string `json:"filename"`
	PreviousFilename string `json:"previous_filename"`
	Status           string `json:"status"`
	Patch            string `json:"patch"`
}

// ListPullRequestFiles returns all files for a PR (paginated).
func (c *Client) ListPullRequestFiles(ctx context.Context, owner, repo string, number int) ([]PRFile, error) {
	path := fmt.Sprintf("/repos/%s/%s/pulls/%d/files?per_page=100", owner, repo, number)
	raw, err := c.RESTGetPaginated(ctx, path)
	if err != nil {
		return nil, err
	}
	var files []PRFile
	if err := json.Unmarshal(raw, &files); err != nil {
		return nil, fmt.Errorf("decode pr files: %w", err)
	}
	return files, nil
}

// OwnerRepo returns owner, name from full_name or base.
func (p *PullRequest) OwnerRepo() (owner, repo string) {
	if p == nil {
		return "", ""
	}
	if fn := strings.TrimSpace(p.Base.Repo.FullName); fn != "" {
		parts := strings.SplitN(fn, "/", 2)
		if len(parts) == 2 {
			return parts[0], parts[1]
		}
	}
	return p.Base.Repo.Owner.Login, p.Base.Repo.Name
}
