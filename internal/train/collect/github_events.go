package collect

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	DefaultGitHubEventsURL = "https://sql-clickhouse.clickhouse.com/"
	defaultEventsPerRepo   = 40
	maxEventsPerRepo       = 100
	maxEventsResponseBytes = 16 << 20
)

var githubRepoPart = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$`)

// GitHubEventsOpts controls discovery through ClickHouse's public GH Archive
// mirror. The mirror supplies candidate identities only; CollectPRWithOptions
// still hydrates canonical review evidence from GitHub before a case is built.
type GitHubEventsOpts struct {
	Context context.Context
	// Endpoint defaults to ClickHouse's public, read-only SQL playground.
	Endpoint string
	// Since is an inclusive YYYY-MM-DD event bound. Empty defaults to one year.
	Since string
	// PerRepoLimit bounds returned candidates for each requested repository.
	PerRepoLimit int
	// Client is injectable for tests. Production defaults to a bounded client.
	Client *http.Client
	// Now makes the default one-year lookback deterministic in tests.
	Now func() time.Time
}

type githubEventsRow struct {
	RepoName string `json:"repo_name"`
	Number   int    `json:"number"`
	Title    string `json:"title"`
}

// DiscoverPRsFromGitHubEvents returns recently merged, reviewed PR identities
// for a whole repository window with one read-only HTTP query. It deliberately
// does not return comment bodies as training evidence: the ordinary GitHub
// collector must retrieve the complete, canonical PR snapshot afterward.
func DiscoverPRsFromGitHubEvents(repoNames []string, opts GitHubEventsOpts) (map[string][]PRRef, error) {
	ctx := opts.Context
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("github events discovery interrupted: %w", err)
	}

	requested, canonical, err := normalizeGitHubEventRepos(repoNames)
	if err != nil {
		return nil, err
	}
	if len(requested) == 0 {
		return map[string][]PRRef{}, nil
	}

	endpoint, err := normalizeGitHubEventsEndpoint(opts.Endpoint)
	if err != nil {
		return nil, err
	}
	since, err := normalizeGitHubEventsSince(opts.Since, opts.Now)
	if err != nil {
		return nil, err
	}
	perRepo := opts.PerRepoLimit
	if perRepo <= 0 {
		perRepo = defaultEventsPerRepo
	}
	if perRepo > maxEventsPerRepo {
		return nil, fmt.Errorf("github events per-repo limit %d exceeds maximum %d", perRepo, maxEventsPerRepo)
	}

	query := githubEventsQuery(requested, since, perRepo)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), strings.NewReader(query))
	if err != nil {
		return nil, fmt.Errorf("build github events request: %w", err)
	}
	req.Header.Set("Content-Type", "text/plain; charset=utf-8")
	req.Header.Set("User-Agent", "adversary-train-github-events/1")

	client := opts.Client
	if client == nil {
		client = &http.Client{Timeout: 60 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("github events discovery interrupted: %w", ctx.Err())
		}
		return nil, fmt.Errorf("query github events mirror: %w", err)
	}
	defer resp.Body.Close()

	body, err := readBoundedEventsResponse(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("github events mirror returned HTTP %d: %s", resp.StatusCode, sanitizedResponse(body))
	}

	out := make(map[string][]PRRef, len(requested))
	seen := map[string]map[int]bool{}
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 64*1024), 1<<20)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var row githubEventsRow
		if err := json.Unmarshal(line, &row); err != nil {
			return nil, fmt.Errorf("parse github events row: %w", err)
		}
		key := strings.ToLower(strings.TrimSpace(row.RepoName))
		name, ok := canonical[key]
		if !ok {
			return nil, fmt.Errorf("github events mirror returned unrequested repository %q", row.RepoName)
		}
		if row.Number <= 0 {
			return nil, fmt.Errorf("github events mirror returned invalid PR number %d for %s", row.Number, name)
		}
		if seen[key] == nil {
			seen[key] = map[int]bool{}
		}
		if seen[key][row.Number] {
			continue
		}
		seen[key][row.Number] = true
		if len(out[name]) >= perRepo {
			return nil, fmt.Errorf("github events mirror exceeded per-repository result bound for %s", name)
		}
		out[name] = append(out[name], PRRef{
			Number: row.Number,
			Title:  strings.TrimSpace(row.Title),
			URL:    fmt.Sprintf("https://github.com/%s/pull/%d", name, row.Number),
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan github events response: %w", err)
	}
	return out, nil
}

func normalizeGitHubEventRepos(repoNames []string) ([]string, map[string]string, error) {
	canonical := map[string]string{}
	for _, raw := range repoNames {
		name := strings.TrimSpace(raw)
		parts := strings.Split(name, "/")
		if len(parts) != 2 || !githubRepoPart.MatchString(parts[0]) || !githubRepoPart.MatchString(parts[1]) {
			return nil, nil, fmt.Errorf("invalid GitHub repository %q for events discovery", raw)
		}
		key := strings.ToLower(name)
		if _, exists := canonical[key]; !exists {
			canonical[key] = name
		}
	}
	requested := make([]string, 0, len(canonical))
	for _, name := range canonical {
		requested = append(requested, name)
	}
	sort.Strings(requested)
	return requested, canonical, nil
}

func normalizeGitHubEventsEndpoint(raw string) (*url.URL, error) {
	if strings.TrimSpace(raw) == "" {
		raw = DefaultGitHubEventsURL
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse github events endpoint: %w", err)
	}
	if u.Scheme != "https" || u.Host == "" || u.User != nil {
		return nil, fmt.Errorf("github events endpoint must be an HTTPS URL without embedded credentials")
	}
	q := u.Query()
	if q.Get("user") == "" {
		q.Set("user", "demo")
	}
	u.RawQuery = q.Encode()
	return u, nil
}

func normalizeGitHubEventsSince(raw string, now func() time.Time) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		if now == nil {
			now = time.Now
		}
		value = now().UTC().AddDate(-1, 0, 0).Format("2006-01-02")
	}
	parsed, err := time.Parse("2006-01-02", value)
	if err != nil {
		return "", fmt.Errorf("sources.since must be YYYY-MM-DD for github_events discovery: %w", err)
	}
	return parsed.Format("2006-01-02"), nil
}

func githubEventsQuery(repoNames []string, since string, perRepo int) string {
	quoted := make([]string, 0, len(repoNames))
	for _, name := range repoNames {
		// normalizeGitHubEventRepos restricts names to an injection-safe alphabet.
		quoted = append(quoted, "'"+name+"'")
	}
	return fmt.Sprintf(`SELECT repo_name, number, title
FROM
(
    SELECT
        repo_name,
        number,
        argMax(title, created_at) AS title,
        maxIf(created_at, event_type IN ('PullRequestReviewCommentEvent', 'PullRequestReviewEvent')) AS reviewed_at,
        row_number() OVER (PARTITION BY repo_name ORDER BY reviewed_at DESC, number DESC) AS repo_rank
    FROM github.events
    PREWHERE repo_name IN (%s)
    WHERE number > 0
      AND created_at >= toDateTime('%s')
      AND event_type IN ('PullRequestEvent', 'PullRequestReviewCommentEvent', 'PullRequestReviewEvent')
    GROUP BY repo_name, number
	HAVING countIf(event_type = 'PullRequestEvent' AND (action = 'merged' OR (action = 'closed' AND merged = 1))) > 0
       AND countIf(event_type IN ('PullRequestReviewCommentEvent', 'PullRequestReviewEvent')) > 0
)
WHERE repo_rank <= %d
ORDER BY repo_name ASC, reviewed_at DESC, number DESC
FORMAT JSONEachRow
SETTINGS max_execution_time = 55, timeout_overflow_mode = 'throw'`, strings.Join(quoted, ", "), since, perRepo)
}

func readBoundedEventsResponse(r io.Reader) ([]byte, error) {
	limited := io.LimitReader(r, maxEventsResponseBytes+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("read github events response: %w", err)
	}
	if len(body) > maxEventsResponseBytes {
		return nil, fmt.Errorf("github events response exceeds %d bytes", maxEventsResponseBytes)
	}
	return body, nil
}

func sanitizedResponse(body []byte) string {
	text := strings.Join(strings.Fields(string(body)), " ")
	if len(text) > 300 {
		text = text[:300] + "…"
	}
	if text == "" {
		return "empty response"
	}
	return text
}
