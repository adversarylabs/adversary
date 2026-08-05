package collect

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/adversarylabs/adversary/internal/train/cases"
	"github.com/adversarylabs/adversary/internal/train/dataroot"
	"github.com/adversarylabs/adversary/internal/train/scope"
)

// Result of a collect operation.
type Result struct {
	Owner          string
	Repo           string
	PR             int
	CacheDir       string
	ExecutionClass dataroot.ExecutionClass
	CaseCandidates []*cases.Case
	Blocked        *dataroot.BlockedResult
}

// CollectOptions optional knobs for collect.
type CollectOptions struct {
	// Scope classifies human comments for a single adversary (legacy).
	Scope *scope.Classifier
	// Router picks the best sibling adversary (or none) per comment.
	// When set, takes precedence over Scope.
	Router *scope.Router
	// AuthorOK filters gold authors (train config authors_only / authors_ignore).
	AuthorOK AuthorFilter
}

// CollectPR fetches PR timeline/reviews/comments via gh and builds case candidates.
func CollectPR(dataRoot, owner, repo string, pr int) (*Result, error) {
	return CollectPRWithOptions(dataRoot, owner, repo, pr, CollectOptions{})
}

// CollectPRWithOptions is CollectPR with scope classification options.
func CollectPRWithOptions(dataRoot, owner, repo string, pr int, opts CollectOptions) (*Result, error) {
	cacheDir := filepath.Join(dataRoot, "github-cache", owner, repo, fmt.Sprintf("pr-%d", pr))
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return nil, err
	}
	res := &Result{Owner: owner, Repo: repo, PR: pr, CacheDir: cacheDir}

	if _, err := exec.LookPath("gh"); err != nil {
		res.ExecutionClass = dataroot.ClassPartial
		res.Blocked = &dataroot.BlockedResult{
			Dependency:     "gh",
			Operation:      "collect",
			Classification: "not-installed",
			SanitizedError: "gh CLI not found in PATH",
			StagesNotRun:   []string{"collect"},
			RetrySafe:      true,
			NextAction:     "install GitHub CLI (gh) and authenticate",
		}
		return res, nil
	}

	// PR metadata
	prJSON, err := ghJSON(owner, repo, fmt.Sprintf("repos/%s/%s/pulls/%d", owner, repo, pr))
	if err != nil {
		res.ExecutionClass = dataroot.ClassPartial
		res.Blocked = blockedFromErr("github-api", "collect-pr", err)
		return res, nil
	}
	_ = os.WriteFile(filepath.Join(cacheDir, "pull.json"), prJSON, 0o644)

	reviewsJSON, err := ghJSON(owner, repo, fmt.Sprintf("repos/%s/%s/pulls/%d/reviews", owner, repo, pr))
	if err != nil {
		res.Blocked = blockedFromErr("github-api", "collect-reviews", err)
		res.ExecutionClass = dataroot.ClassPartial
		return res, nil
	}
	_ = os.WriteFile(filepath.Join(cacheDir, "reviews.json"), reviewsJSON, 0o644)

	commentsJSON, err := ghJSON(owner, repo, fmt.Sprintf("repos/%s/%s/pulls/%d/comments", owner, repo, pr))
	if err != nil {
		res.Blocked = blockedFromErr("github-api", "collect-comments", err)
		res.ExecutionClass = dataroot.ClassPartial
		return res, nil
	}
	_ = os.WriteFile(filepath.Join(cacheDir, "review-comments.json"), commentsJSON, 0o644)

	res.ExecutionClass = dataroot.ClassReal
	built, err := BuildCasesFromCacheFiltered(owner, repo, pr, cacheDir, opts.Scope, opts.Router, opts.AuthorOK)
	if err != nil {
		return res, err
	}
	res.CaseCandidates = built
	return res, nil
}

func defaultScope() *scope.Classifier {
	return &scope.Classifier{
		AdversaryName: "engineering-review",
		UseLLM:        os.Getenv("OPENAI_API_KEY") != "",
	}
}

func ghJSON(owner, repo, apiPath string) ([]byte, error) {
	cmd := exec.Command("gh", "api", apiPath, "--paginate")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%w: %s", err, sanitize(string(out)))
	}
	return out, nil
}

func sanitize(s string) string {
	// Avoid leaking tokens if any appear.
	s = strings.ReplaceAll(s, os.Getenv("GITHUB_TOKEN"), "***")
	if len(s) > 500 {
		s = s[:500] + "…"
	}
	return strings.TrimSpace(s)
}

func blockedFromErr(dep, op string, err error) *dataroot.BlockedResult {
	class := "outage"
	msg := err.Error()
	if strings.Contains(msg, "401") || strings.Contains(msg, "403") {
		class = "auth"
	}
	if strings.Contains(msg, "404") {
		class = "missing-source"
	}
	return &dataroot.BlockedResult{
		Dependency:     dep,
		Operation:      op,
		Classification: class,
		SanitizedError: sanitize(msg),
		StagesNotRun:   []string{"collect"},
		RetrySafe:      true,
		NextAction:     "check gh auth and repository access",
		At:             time.Now().UTC(),
	}
}

// BuildCasesFromCache constructs case candidates from cached GitHub JSON.
func BuildCasesFromCache(owner, repo string, pr int, cacheDir string, clf *scope.Classifier, router *scope.Router) ([]*cases.Case, error) {
	return BuildCasesFromCacheFiltered(owner, repo, pr, cacheDir, clf, router, nil)
}

func BuildCasesFromCacheFiltered(owner, repo string, pr int, cacheDir string, clf *scope.Classifier, router *scope.Router, authorOK AuthorFilter) ([]*cases.Case, error) {
	if clf == nil && router == nil {
		clf = defaultScope()
	}
	prRaw, err := os.ReadFile(filepath.Join(cacheDir, "pull.json"))
	if err != nil {
		return nil, err
	}
	var prObj struct {
		Number  int    `json:"number"`
		Title   string `json:"title"`
		Base    struct {
			SHA string `json:"sha"`
		} `json:"base"`
		Head struct {
			SHA string `json:"sha"`
		} `json:"head"`
		HTMLURL string `json:"html_url"`
	}
	if err := json.Unmarshal(prRaw, &prObj); err != nil {
		return nil, err
	}

	reviewsRaw, err := os.ReadFile(filepath.Join(cacheDir, "reviews.json"))
	if err != nil {
		return nil, err
	}
	var reviews []struct {
		ID          int64  `json:"id"`
		Body        string `json:"body"`
		State       string `json:"state"`
		CommitID    string `json:"commit_id"`
		SubmittedAt string `json:"submitted_at"`
		User        struct {
			Login string `json:"login"`
		} `json:"user"`
	}
	if err := json.Unmarshal(reviewsRaw, &reviews); err != nil {
		return nil, err
	}

	commentsRaw, err := os.ReadFile(filepath.Join(cacheDir, "review-comments.json"))
	if err != nil {
		return nil, err
	}
	var comments []struct {
		ID               int64  `json:"id"`
		Body             string `json:"body"`
		Path             string `json:"path"`
		Line             int    `json:"line"`
		OriginalCommitID string `json:"original_commit_id"`
		CommitID         string `json:"commit_id"`
		CreatedAt        string `json:"created_at"`
		User             struct {
			Login string `json:"login"`
		} `json:"user"`
		PullRequestReviewID int64 `json:"pull_request_review_id"`
	}
	if err := json.Unmarshal(commentsRaw, &comments); err != nil {
		return nil, err
	}

	// Group by review for formal reviews with body or comments.
	repoSlug := repo // case id uses short repo name
	var out []*cases.Case
	round := 0
	for _, rev := range reviews {
		if rev.State == "PENDING" {
			continue
		}
		// Prefer substantive reviews
		hasBody := strings.TrimSpace(rev.Body) != ""
		var revComments []cases.Comment
		var origIDs []string
		for _, c := range comments {
			if c.PullRequestReviewID != 0 && c.PullRequestReviewID != rev.ID {
				continue
			}
			// If review id linkage missing, still collect comments with matching commit.
			if c.PullRequestReviewID == 0 && rev.CommitID != "" && c.OriginalCommitID != rev.CommitID && c.CommitID != rev.CommitID {
				continue
			}
			if c.PullRequestReviewID == rev.ID || (c.PullRequestReviewID == 0 && hasBody) {
				oc := c.OriginalCommitID
				if oc == "" {
					oc = c.CommitID
				}
				if oc != "" {
					origIDs = append(origIDs, oc)
				}
				created, _ := time.Parse(time.RFC3339, c.CreatedAt)
				revComments = append(revComments, cases.Comment{
					ID:               c.ID,
					Kind:             "review-comment",
					Author:           c.User.Login,
					Body:             c.Body,
					Path:             c.Path,
					Line:             c.Line,
					OriginalCommitID: oc,
					CreatedAt:        created,
					// Manual approval path: not auto-gold
					ApprovedAsLabel: false,
					Classification:  "unclear",
				})
			}
		}
		if !hasBody && len(revComments) == 0 {
			continue
		}
		round++
		sig := cases.ReviewSignal{
			ReviewCommitID:    rev.CommitID,
			OriginalCommitIDs: origIDs,
			PRHeadSHA:         prObj.Head.SHA,
		}
		sha, source, excl := cases.ReconstructReviewedSHA(sig)
		submitted, _ := time.Parse(time.RFC3339, rev.SubmittedAt)
		if hasBody {
			revComments = append([]cases.Comment{{
				ID:      rev.ID,
				Kind:    "review-body",
				Author:  rev.User.Login,
				Body:    rev.Body,
				CreatedAt: submitted,
				ApprovedAsLabel: false,
				Classification:  "unclear",
			}}, revComments...)
		}
		// Candidate labels, routed to best adversary (or none).
		labels := cases.CandidateLabelsFromComments(revComments)
		applyScopeFiltered(labels, revComments, clf, router, authorOK)
		c := &cases.Case{
			SchemaVersion: 4,
			ID:            cases.CaseID(repoSlug, pr, round),
			Repository: cases.Repository{
				Owner: owner,
				Name:  repo,
				URL:   prObj.HTMLURL,
			},
			PullRequest: cases.PullRequest{
				Number:         pr,
				BaseSHA:        prObj.Base.SHA,
				InitialHeadSHA: sha,
				FinalHeadSHA:   prObj.Head.SHA,
				Title:          prObj.Title,
			},
			ReviewEvent: cases.ReviewEvent{
				RoundIndex:        round,
				Kind:              "formal-review",
				GitHubReviewIDs:   []int64{rev.ID},
				ReviewedSHA:       sha,
				ReviewedSHASource: source,
				SubmittedAt:       submitted,
				Reviewers:         []string{rev.User.Login},
				Dismissed:         rev.State == "DISMISSED",
			},
			EvidenceWindow: cases.EvidenceWindow{
				OpensAt: submitted,
			},
			Comments: revComments,
			FollowUp: cases.FollowUp{},
			Labels: cases.Labels{
				ExpectedConcerns: labels,
			},
			Metadata: cases.Metadata{
				CreatedAt: time.Now().UTC(),
				Split:     "discovery",
			},
			Exclusion: excl,
		}
		// Cap at one high-quality round per PR for v1 when we already have one good case.
		out = append(out, c)
		if excl == nil && len(cases.ApprovedLabels(labels)) > 0 {
			break
		}
	}
	if len(out) == 0 {
		// Fallback: single case from PR head if we have comments with original_commit_id
		var origIDs []string
		var allComments []cases.Comment
		for _, c := range comments {
			oc := c.OriginalCommitID
			if oc == "" {
				oc = c.CommitID
			}
			if oc != "" {
				origIDs = append(origIDs, oc)
			}
			created, _ := time.Parse(time.RFC3339, c.CreatedAt)
			allComments = append(allComments, cases.Comment{
				ID: c.ID, Kind: "review-comment", Author: c.User.Login, Body: c.Body,
				Path: c.Path, Line: c.Line, OriginalCommitID: oc, CreatedAt: created,
			})
		}
		sha, source, excl := cases.ReconstructReviewedSHA(cases.ReviewSignal{OriginalCommitIDs: origIDs, PRHeadSHA: prObj.Head.SHA})
		labels := cases.CandidateLabelsFromComments(allComments)
		applyScopeFiltered(labels, allComments, clf, router, authorOK)
		out = append(out, &cases.Case{
			SchemaVersion: 4,
			ID:            cases.CaseID(repoSlug, pr, 1),
			Repository:    cases.Repository{Owner: owner, Name: repo, URL: prObj.HTMLURL},
			PullRequest:   cases.PullRequest{Number: pr, BaseSHA: prObj.Base.SHA, InitialHeadSHA: sha, FinalHeadSHA: prObj.Head.SHA, Title: prObj.Title},
			ReviewEvent:   cases.ReviewEvent{RoundIndex: 1, Kind: "inline-comment-cluster", ReviewedSHA: sha, ReviewedSHASource: source},
			Comments:      allComments,
			Labels:        cases.Labels{ExpectedConcerns: labels},
			Metadata:      cases.Metadata{CreatedAt: time.Now().UTC(), Split: "discovery"},
			Exclusion:     excl,
		})
	}
	return out, nil
}

// AuthorFilter decides if a comment author may count as gold (train config).
// nil = allow all (still subject to bot heuristics in scope).
type AuthorFilter func(login string) bool

// applyScope routes each label to the best adversary (or none).
func applyScope(labels []cases.ExpectedConcern, comments []cases.Comment, clf *scope.Classifier, router *scope.Router) {
	applyScopeFiltered(labels, comments, clf, router, nil)
}

func applyScopeFiltered(labels []cases.ExpectedConcern, comments []cases.Comment, clf *scope.Classifier, router *scope.Router, authorOK AuthorFilter) {
	if clf == nil && router == nil {
		clf = defaultScope()
	}
	for i := range labels {
		body := labels[i].Summary
		path := labels[i].File
		author := ""
		for _, c := range comments {
			if c.ID > 0 && strings.Contains(labels[i].ID, fmt.Sprintf("%d", c.ID)) {
				author, body, path = c.Author, c.Body, c.Path
				break
			}
		}
		if author == "" {
			for _, c := range comments {
				if c.Body != "" && (c.Body == labels[i].Summary || strings.Contains(c.Body, labels[i].Summary) ||
					strings.Contains(labels[i].Summary, truncateRunes(c.Body, 60))) {
					author, body = c.Author, c.Body
					if c.Path != "" {
						path = c.Path
					}
					break
				}
			}
		}
		if authorOK != nil && !authorOK(author) {
			labels[i].Scope = string(scope.OutOfScope)
			labels[i].Approved = false
			labels[i].OwnerAdversary = ""
			labels[i].ScopeReason = "author filtered by train config"
			labels[i].ScopeMethod = "config"
			continue
		}
		if router != nil {
			route := router.RouteComment(body, path, author)
			labels[i].OwnerAdversary = route.OwnerID
			labels[i].ScopeReason = route.Reason
			labels[i].ScopeMethod = route.Method
			if route.OwnerID != "" && route.Decision == scope.InScope && len(strings.TrimSpace(labels[i].Summary)) > 20 {
				labels[i].Scope = string(scope.InScope)
				labels[i].Approved = true
				labels[i].Confidence = "medium"
			} else {
				labels[i].Scope = string(scope.OutOfScope)
				labels[i].Approved = false
				if labels[i].ScopeReason == "" {
					labels[i].ScopeReason = "no adversary claimed this comment"
				}
			}
			continue
		}
		r := clf.Classify(body, path, author)
		labels[i].Scope = string(r.Decision)
		labels[i].ScopeReason = r.Reason
		labels[i].ScopeMethod = r.Method
		labels[i].OwnerAdversary = ""
		if r.Decision == scope.InScope && len(strings.TrimSpace(labels[i].Summary)) > 20 {
			labels[i].Approved = true
			labels[i].Confidence = "medium"
			labels[i].OwnerAdversary = "engineering-review"
		} else {
			labels[i].Approved = false
		}
	}
}

func truncateRunes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
