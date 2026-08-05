package githubapi

import (
	"fmt"
	"net/url"
	"os/exec"
	"path/filepath"
	"strings"
)

// RepoRef is owner/name for a GitHub repository.
type RepoRef struct {
	Owner string
	Name  string
	Host  string // e.g. github.com
}

// ParseGitRemoteURL extracts owner/repo from common git remote URL forms.
// Supports https://github.com/o/r.git, git@github.com:o/r.git, ssh://git@github.com/o/r.git.
func ParseGitRemoteURL(raw string) (RepoRef, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return RepoRef{}, fmt.Errorf("empty git remote")
	}
	// scp-like: git@host:owner/repo.git
	if strings.Contains(raw, "@") && strings.Contains(raw, ":") && !strings.Contains(raw, "://") {
		// user@host:path
		at := strings.LastIndex(raw, "@")
		rest := raw[at+1:]
		host, path, ok := strings.Cut(rest, ":")
		if !ok || path == "" {
			return RepoRef{}, fmt.Errorf("unrecognized git remote %q", raw)
		}
		return repoRefFromHostPath(host, path)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return RepoRef{}, fmt.Errorf("parse git remote: %w", err)
	}
	host := u.Host
	if h, _, ok := strings.Cut(host, ":"); ok {
		host = h
	}
	path := strings.TrimPrefix(u.Path, "/")
	return repoRefFromHostPath(host, path)
}

func repoRefFromHostPath(host, path string) (RepoRef, error) {
	path = strings.TrimSuffix(path, ".git")
	path = strings.Trim(path, "/")
	parts := strings.Split(path, "/")
	if len(parts) < 2 {
		return RepoRef{}, fmt.Errorf("git remote path %q is not owner/repo", path)
	}
	owner, name := parts[len(parts)-2], parts[len(parts)-1]
	if owner == "" || name == "" {
		return RepoRef{}, fmt.Errorf("git remote path %q is not owner/repo", path)
	}
	host = strings.TrimSpace(host)
	if host == "" {
		host = "github.com"
	}
	return RepoRef{Owner: owner, Name: name, Host: host}, nil
}

// ResolvePackageGitHubRepo finds the GitHub owner/repo for a local package path
// via `git remote get-url origin` (or the first available remote).
func ResolvePackageGitHubRepo(packagePath string) (RepoRef, error) {
	abs, err := filepath.Abs(packagePath)
	if err != nil {
		return RepoRef{}, err
	}
	if _, err := exec.LookPath("git"); err != nil {
		return RepoRef{}, fmt.Errorf("git not found: resolve package GitHub remote")
	}
	// Prefer origin, then any remote.
	for _, name := range []string{"origin", ""} {
		args := []string{"-C", abs, "remote", "get-url"}
		if name != "" {
			args = append(args, name)
		} else {
			// list remotes and take first
			out, err := exec.Command("git", "-C", abs, "remote").Output()
			if err != nil {
				return RepoRef{}, fmt.Errorf("git remote: %w", err)
			}
			lines := strings.Fields(string(out))
			if len(lines) == 0 {
				return RepoRef{}, fmt.Errorf("no git remotes in %s", abs)
			}
			args = append(args, lines[0])
		}
		out, err := exec.Command("git", args...).Output()
		if err != nil {
			if name == "origin" {
				continue
			}
			return RepoRef{}, fmt.Errorf("git remote get-url: %w", err)
		}
		ref, err := ParseGitRemoteURL(strings.TrimSpace(string(out)))
		if err != nil {
			return RepoRef{}, err
		}
		if !strings.EqualFold(ref.Host, "github.com") && !strings.HasSuffix(strings.ToLower(ref.Host), ".github.com") {
			// Still allow github enterprise-ish hosts that look like github; otherwise reject for v1 REST default.
			if !strings.Contains(strings.ToLower(ref.Host), "github") {
				return RepoRef{}, fmt.Errorf("package remote is %s (only GitHub remotes supported for issue apply)", ref.Host)
			}
		}
		return ref, nil
	}
	return RepoRef{}, fmt.Errorf("no usable git remote in %s", abs)
}
