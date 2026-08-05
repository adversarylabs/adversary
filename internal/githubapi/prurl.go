package githubapi

import (
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

var prURLPath = regexp.MustCompile(`(?i)^/([^/]+)/([^/]+)/pull/(\d+)(?:/.*)?$`)

// PRRef is a parsed GitHub pull request locator.
type PRRef struct {
	Owner  string
	Repo   string
	Number int
}

// ParseGitHubPRURL parses https://github.com/owner/repo/pull/N forms.
// Returns ok=false when s is not a PR URL (caller should treat as non-PR arg).
func ParseGitHubPRURL(s string) (PRRef, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return PRRef{}, false
	}
	// Allow host without scheme.
	if strings.HasPrefix(strings.ToLower(s), "github.com/") {
		s = "https://" + s
	}
	if strings.HasPrefix(strings.ToLower(s), "www.github.com/") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return PRRef{}, false
	}
	host := strings.ToLower(u.Host)
	if host != "github.com" && host != "www.github.com" {
		return PRRef{}, false
	}
	m := prURLPath.FindStringSubmatch(u.Path)
	if m == nil {
		return PRRef{}, false
	}
	n, err := strconv.Atoi(m[3])
	if err != nil || n <= 0 {
		return PRRef{}, false
	}
	return PRRef{Owner: m[1], Repo: m[2], Number: n}, true
}

// Format returns owner/repo#N.
func (p PRRef) Format() string {
	return fmt.Sprintf("%s/%s#%d", p.Owner, p.Repo, p.Number)
}
