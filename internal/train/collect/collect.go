package collect

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/adversarylabs/adversary/internal/githubapi"
	"github.com/adversarylabs/adversary/internal/train/cases"
	"github.com/adversarylabs/adversary/internal/train/dataroot"
	"github.com/adversarylabs/adversary/internal/train/scope"
	"github.com/adversarylabs/adversary/internal/train/securefs"
)

// Result of a collect operation.
type Result struct {
	Owner          string
	Repo           string
	PR             int
	CacheDir       string
	ExecutionClass dataroot.ExecutionClass
	CacheReused    bool
	CaseCandidates []*cases.Case
	Blocked        *dataroot.BlockedResult
}

// CollectOptions optional knobs for collect.
type CollectOptions struct {
	// Context cancels GitHub API calls (Ctrl+C).
	Context context.Context
	// Scope classifies human comments for a single adversary (legacy).
	Scope *scope.Classifier
	// Router picks the best sibling adversary (or none) per comment.
	// When set, takes precedence over Scope.
	Router *scope.Router
	// AuthorOK filters gold authors (train config authors_only / authors_ignore).
	AuthorOK AuthorFilter
	// Client optional injected GitHub client (tests).
	Client *githubapi.Client
}

type rawReviewComment struct {
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
	InReplyToID         int64 `json:"in_reply_to_id"`
	PullRequestReviewID int64 `json:"pull_request_review_id"`
}

// CollectPR fetches PR timeline/reviews/comments via GitHub HTTP and builds case candidates.
func CollectPR(dataRoot, owner, repo string, pr int) (*Result, error) {
	return CollectPRWithOptions(dataRoot, owner, repo, pr, CollectOptions{})
}

// CollectPRWithOptions is CollectPR with scope classification options.
func CollectPRWithOptions(dataRoot, owner, repo string, pr int, opts CollectOptions) (*Result, error) {
	cacheDir := filepath.Join(dataRoot, "github-cache", owner, repo, fmt.Sprintf("pr-%d", pr))
	if err := securefs.MkdirAll(cacheDir); err != nil {
		return nil, err
	}
	res := &Result{Owner: owner, Repo: repo, PR: pr, CacheDir: cacheDir}

	ctx := opts.Context
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return res, fmt.Errorf("collect interrupted: %w", err)
	}

	client := opts.Client
	if client == nil {
		var err error
		client, err = clientFor(ctx)
		if err != nil {
			res.ExecutionClass = dataroot.ClassPartial
			res.Blocked = &dataroot.BlockedResult{
				Dependency:     "github-token",
				Operation:      "collect",
				Classification: "not-configured",
				SanitizedError: err.Error(),
				StagesNotRun:   []string{"collect"},
				RetrySafe:      true,
				NextAction:     "set ADVERSARY_GITHUB_TOKEN, GITHUB_TOKEN, or GH_TOKEN",
			}
			return res, nil
		}
	}
	if resetAt, limited := githubapi.ActiveRateLimit(); limited {
		gateErr := &RateLimitError{ResetAt: resetAt}
		if replayCachedCases(res, gateErr, opts) {
			return res, nil
		}
		res.ExecutionClass = dataroot.ClassPartial
		res.Blocked = blockedFromErr("github-api", "collect-rate-gate", gateErr)
		return res, nil
	}

	prJSON, _, err := client.RESTGet(ctx, fmt.Sprintf("/repos/%s/%s/pulls/%d", owner, repo, pr))
	if err != nil {
		if replayCachedCases(res, err, opts) {
			return res, nil
		}
		res.ExecutionClass = dataroot.ClassPartial
		res.Blocked = blockedFromErr("github-api", "collect-pr", err)
		return res, nil
	}
	reviewsJSON, err := client.RESTGetPaginated(ctx, fmt.Sprintf("/repos/%s/%s/pulls/%d/reviews?per_page=100", owner, repo, pr))
	if err != nil {
		if replayCachedCases(res, err, opts) {
			return res, nil
		}
		res.Blocked = blockedFromErr("github-api", "collect-reviews", err)
		res.ExecutionClass = dataroot.ClassPartial
		return res, nil
	}
	commentsJSON, err := client.RESTGetPaginated(ctx, fmt.Sprintf("/repos/%s/%s/pulls/%d/comments?per_page=100", owner, repo, pr))
	if err != nil {
		if replayCachedCases(res, err, opts) {
			return res, nil
		}
		res.Blocked = blockedFromErr("github-api", "collect-comments", err)
		res.ExecutionClass = dataroot.ClassPartial
		return res, nil
	}
	// Replace the cache only after collecting a coherent snapshot. This avoids
	// mixing a fresh pull object with stale reviews or comments if GitHub rate
	// limits one of the later endpoints.
	_ = securefs.WriteFile(filepath.Join(cacheDir, "pull.json"), prJSON)
	_ = securefs.WriteFile(filepath.Join(cacheDir, "reviews.json"), reviewsJSON)
	_ = securefs.WriteFile(filepath.Join(cacheDir, "review-comments.json"), commentsJSON)

	res.ExecutionClass = dataroot.ClassReal
	built, err := BuildCasesFromCacheFiltered(owner, repo, pr, cacheDir, opts.Scope, opts.Router, opts.AuthorOK)
	if err != nil {
		return res, err
	}
	res.CaseCandidates = built
	return res, nil
}

// replayCachedCases keeps long-running training useful through GitHub's
// secondary rate limits. It is deliberately limited to rate-limit failures and
// requires a complete, parseable cache snapshot; auth and missing-source errors
// remain first-class blocked results.
func replayCachedCases(res *Result, collectErr error, opts CollectOptions) bool {
	if !IsRateLimit(collectErr) {
		return false
	}
	built, err := BuildCasesFromCacheFiltered(res.Owner, res.Repo, res.PR, res.CacheDir, opts.Scope, opts.Router, opts.AuthorOK)
	if err != nil {
		return false
	}
	res.ExecutionClass = dataroot.ClassReplayed
	res.CacheReused = true
	res.CaseCandidates = built
	return true
}

func defaultScope() *scope.Classifier {
	return &scope.Classifier{
		AdversaryName: "engineering-review",
		UseLLM:        os.Getenv("OPENAI_API_KEY") != "",
	}
}

func sanitize(s string) string {
	s = strings.ReplaceAll(s, os.Getenv("GITHUB_TOKEN"), "***")
	s = strings.ReplaceAll(s, os.Getenv("GH_TOKEN"), "***")
	s = strings.ReplaceAll(s, os.Getenv("ADVERSARY_GITHUB_TOKEN"), "***")
	if len(s) > 500 {
		s = s[:500] + "…"
	}
	return strings.TrimSpace(s)
}

func blockedFromErr(dep, op string, err error) *dataroot.BlockedResult {
	class := "outage"
	msg := err.Error()
	next := "check GitHub token and repository access (ADVERSARY_GITHUB_TOKEN / GITHUB_TOKEN / GH_TOKEN)"
	if IsRateLimit(err) {
		class = "rate-limit"
		next = "wait for GitHub rate limit reset, lower run.concurrency (e.g. 1–2), then train run again; partial results stay in results.db"
	} else if strings.Contains(msg, "401") || strings.Contains(msg, "403") || strings.Contains(msg, "auth") {
		class = "auth"
	} else if strings.Contains(msg, "404") {
		class = "missing-source"
	}
	return &dataroot.BlockedResult{
		Dependency:     dep,
		Operation:      op,
		Classification: class,
		SanitizedError: sanitize(msg),
		StagesNotRun:   []string{"collect"},
		RetrySafe:      true,
		NextAction:     next,
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
		Number int    `json:"number"`
		Title  string `json:"title"`
		Base   struct {
			SHA string `json:"sha"`
		} `json:"base"`
		Head struct {
			SHA string `json:"sha"`
		} `json:"head"`
		HTMLURL  string `json:"html_url"`
		MergedAt string `json:"merged_at"`
		User     struct {
			Login string `json:"login"`
		} `json:"user"`
	}
	if err := json.Unmarshal(prRaw, &prObj); err != nil {
		return nil, err
	}
	mergedAt, _ := time.Parse(time.RFC3339, prObj.MergedAt)

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
	if !mergedAt.IsZero() {
		kept := reviews[:0]
		for _, review := range reviews {
			submitted, err := time.Parse(time.RFC3339, review.SubmittedAt)
			if err == nil && submitted.After(mergedAt) {
				continue
			}
			kept = append(kept, review)
		}
		reviews = kept
	}
	// The REST endpoint returns reviews oldest-first. Training stops once it has
	// one reconstructable in-scope round, so inspect the latest maintainer
	// judgment first; otherwise an early superficial comment can permanently hide
	// a later security or correctness review on a long-lived PR.
	sort.SliceStable(reviews, func(i, j int) bool {
		if reviews[i].SubmittedAt == reviews[j].SubmittedAt {
			return reviews[i].ID > reviews[j].ID
		}
		return reviews[i].SubmittedAt > reviews[j].SubmittedAt
	})

	commentsRaw, err := os.ReadFile(filepath.Join(cacheDir, "review-comments.json"))
	if err != nil {
		return nil, err
	}
	var comments []rawReviewComment
	if err := json.Unmarshal(commentsRaw, &comments); err != nil {
		return nil, err
	}
	if !mergedAt.IsZero() {
		kept := comments[:0]
		for _, comment := range comments {
			created, err := time.Parse(time.RFC3339, comment.CreatedAt)
			if err == nil && created.After(mergedAt) {
				// A post-merge suggestion cannot describe a change required for the
				// accepted PR, so it is discussion rather than human gold.
				continue
			}
			kept = append(kept, comment)
		}
		comments = kept
	}

	// Group by review for formal reviews with body or comments.
	repoSlug := repo // case id uses short repo name
	var out []*cases.Case
	round := 0
	byReviewedSHA := make(map[string]*cases.Case)
	commentContext := make(map[commentKey]reviewCommentContext, len(reviews)+len(comments))
	threadContext := buildReviewThreadContext(comments, prObj.User.Login)
	automatedReviews := make(map[int64]bool, len(reviews))
	for _, rev := range reviews {
		commentContext[commentKey{kind: "review-body", id: rev.ID}] = reviewCommentContext{}
		automatedReviews[rev.ID] = scope.IsAutomatedReviewArtifact(rev.Body)
	}
	for _, comment := range comments {
		commentContext[commentKey{kind: "review-comment", id: comment.ID}] = reviewCommentContext{
			inReplyToID:     comment.InReplyToID,
			automatedParent: automatedReviews[comment.PullRequestReviewID],
			threadContext:   threadContext[comment.ID],
		}
	}
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
				ID:              rev.ID,
				Kind:            "review-body",
				Author:          rev.User.Login,
				Body:            rev.Body,
				CreatedAt:       submitted,
				ApprovedAsLabel: false,
				Classification:  "unclear",
			}}, revComments...)
		}
		// Candidate labels, routed to best adversary (or none).
		labels := cases.CandidateLabelsFromComments(revComments)
		applyScopeFilteredWithContext(labels, revComments, clf, router, authorOK, prObj.User.Login, commentContext)
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
		// Keep each independently reviewed code state. Reviews are newest-first, but
		// a later in-scope concern must not hide an earlier concern attached to a
		// different reviewed SHA.
		if sha != "" {
			if existing := byReviewedSHA[sha]; existing != nil {
				existing.ReviewEvent.GitHubReviewIDs = append(existing.ReviewEvent.GitHubReviewIDs, c.ReviewEvent.GitHubReviewIDs...)
				existing.ReviewEvent.Reviewers = append(existing.ReviewEvent.Reviewers, c.ReviewEvent.Reviewers...)
				existing.ReviewEvent.Dismissed = existing.ReviewEvent.Dismissed && c.ReviewEvent.Dismissed
				if existing.ReviewEvent.SubmittedAt.IsZero() || (!c.ReviewEvent.SubmittedAt.IsZero() && c.ReviewEvent.SubmittedAt.Before(existing.ReviewEvent.SubmittedAt)) {
					existing.ReviewEvent.SubmittedAt = c.ReviewEvent.SubmittedAt
					existing.EvidenceWindow.OpensAt = c.EvidenceWindow.OpensAt
				}
				existing.Comments = append(existing.Comments, c.Comments...)
				existing.Labels.ExpectedConcerns = append(existing.Labels.ExpectedConcerns, c.Labels.ExpectedConcerns...)
				continue
			}
			byReviewedSHA[sha] = c
		}
		out = append(out, c)
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
		applyScopeFilteredWithContext(labels, allComments, clf, router, authorOK, prObj.User.Login, commentContext)
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

type commentKey struct {
	kind string
	id   int64
}

type reviewCommentContext struct {
	inReplyToID     int64
	automatedParent bool
	threadContext   []cases.ReviewThreadContext
}

// applyScope routes each label to the best adversary (or none).
func applyScope(labels []cases.ExpectedConcern, comments []cases.Comment, clf *scope.Classifier, router *scope.Router) {
	applyScopeFiltered(labels, comments, clf, router, nil)
}

func applyScopeFiltered(labels []cases.ExpectedConcern, comments []cases.Comment, clf *scope.Classifier, router *scope.Router, authorOK AuthorFilter) {
	applyScopeFilteredWithContext(labels, comments, clf, router, authorOK, "", nil)
}

func applyScopeFilteredWithContext(labels []cases.ExpectedConcern, comments []cases.Comment, clf *scope.Classifier, router *scope.Router, authorOK AuthorFilter, pullAuthor string, commentContext map[commentKey]reviewCommentContext) {
	if clf == nil && router == nil {
		clf = defaultScope()
	}
	for i := range labels {
		body := labels[i].Summary
		path := labels[i].File
		author := ""
		var matched *cases.Comment
		for _, c := range comments {
			if c.ID > 0 && strings.HasPrefix(labels[i].ID, fmt.Sprintf("c-%d-", c.ID)) {
				author, body, path = c.Author, c.Body, c.Path
				matched = &c
				break
			}
		}
		if author == "" {
			for _, c := range comments {
				if c.Body != "" && (c.Body == labels[i].Summary || strings.Contains(c.Body, labels[i].Summary) ||
					strings.Contains(labels[i].Summary, truncateRunes(c.Body, 60))) {
					author, body = c.Author, c.Body
					matched = &c
					if c.Path != "" {
						path = c.Path
					}
					break
				}
			}
		}
		body = scope.NormalizeReviewComment(body)
		labels[i].Summary = body
		if matched != nil {
			labels[i].ThreadContext = append([]cases.ReviewThreadContext(nil), commentContext[commentKey{kind: matched.Kind, id: matched.ID}].threadContext...)
		}
		if authorOK != nil && !authorOK(author) {
			labels[i].Scope = string(scope.OutOfScope)
			labels[i].Approved = false
			labels[i].OwnerAdversary = ""
			labels[i].ScopeReason = "author filtered by train config"
			labels[i].ScopeMethod = "config"
			continue
		}
		if matched != nil {
			ctx := commentContext[commentKey{kind: matched.Kind, id: matched.ID}]
			if ctx.automatedParent {
				labels[i].Scope = string(scope.OutOfScope)
				labels[i].Approved = false
				labels[i].OwnerAdversary = ""
				labels[i].ScopeReason = "inline comment belongs to an automated parent review"
				labels[i].ScopeMethod = "thread-metadata"
				continue
			}
			isPullAuthor := pullAuthor != "" && strings.EqualFold(author, pullAuthor)
			if isPullAuthor {
				labels[i].Scope = string(scope.OutOfScope)
				labels[i].Approved = false
				labels[i].OwnerAdversary = ""
				labels[i].ScopeReason = "pull request author replies are context, not reviewer gold"
				labels[i].ScopeMethod = "thread-metadata"
				continue
			}
			if ctx.inReplyToID != 0 {
				if reason, ok := scope.NonActionableReply(body); ok {
					labels[i].Scope = string(scope.OutOfScope)
					labels[i].Approved = false
					labels[i].OwnerAdversary = ""
					labels[i].ScopeReason = reason
					labels[i].ScopeMethod = "thread-metadata"
					continue
				}
			}
		}
		if router != nil {
			route := router.RouteCommentWithContext(body, path, author, routeThreadContext(labels[i].ThreadContext))
			labels[i].OwnerAdversary = route.OwnerID
			labels[i].ScopeReason = route.Reason
			labels[i].ScopeMethod = route.Method
			// Broad generalists keep short comments (LGTM, "why?", etc.); specialists
			// still require a minimal summary so empty stubs are not gold.
			minLen := 20
			if route.OwnerID != "" && scope.BroadScopeMission(route.OwnerID, "") {
				minLen = 1
			}
			if route.OwnerID != "" && route.Decision == scope.InScope && len(strings.TrimSpace(labels[i].Summary)) >= minLen {
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
		minLen := 20
		if clf != nil && scope.BroadScopeMission(clf.AdversaryName, clf.MissionMarkdown) {
			minLen = 1
		}
		if r.Decision == scope.InScope && len(strings.TrimSpace(labels[i].Summary)) >= minLen {
			labels[i].Approved = true
			labels[i].Confidence = "medium"
			if clf != nil && clf.AdversaryName != "" {
				labels[i].OwnerAdversary = clf.AdversaryName
			} else {
				labels[i].OwnerAdversary = "engineering-review"
			}
		} else {
			labels[i].Approved = false
		}
	}
}

const (
	maxThreadContextMessages = 4
	maxThreadContextRunes    = 1_200
	maxThreadMessageRunes    = 400
)

// buildReviewThreadContext retains only nearby messages from the same inline
// review thread. Context is attached to an existing comment candidate; this
// function cannot create a label or make any message gold.
func buildReviewThreadContext(comments []rawReviewComment, pullAuthor string) map[int64][]cases.ReviewThreadContext {
	byID := make(map[int64]rawReviewComment, len(comments))
	for _, comment := range comments {
		byID[comment.ID] = comment
	}
	rootID := func(id int64) int64 {
		seen := map[int64]bool{}
		for id != 0 && !seen[id] {
			seen[id] = true
			comment, ok := byID[id]
			if !ok || comment.InReplyToID == 0 {
				return id
			}
			id = comment.InReplyToID
		}
		return id
	}
	threads := map[int64][]rawReviewComment{}
	for _, comment := range comments {
		root := rootID(comment.ID)
		if root == 0 {
			continue
		}
		threads[root] = append(threads[root], comment)
	}
	for root := range threads {
		sort.SliceStable(threads[root], func(i, j int) bool {
			return threads[root][i].CreatedAt < threads[root][j].CreatedAt
		})
	}

	out := make(map[int64][]cases.ReviewThreadContext, len(comments))
	for _, target := range comments {
		thread := threads[rootID(target.ID)]
		if len(thread) < 2 {
			continue
		}
		// Keep the nearest messages when a long thread exceeds the bound, then
		// restore chronological order for model readability.
		type neighbor struct {
			comment  rawReviewComment
			distance time.Duration
		}
		targetAt, _ := time.Parse(time.RFC3339, target.CreatedAt)
		var neighbors []neighbor
		for _, message := range thread {
			if message.ID == target.ID || strings.TrimSpace(message.Body) == "" {
				continue
			}
			createdAt, _ := time.Parse(time.RFC3339, message.CreatedAt)
			distance := createdAt.Sub(targetAt)
			if distance < 0 {
				distance = -distance
			}
			neighbors = append(neighbors, neighbor{comment: message, distance: distance})
		}
		sort.SliceStable(neighbors, func(i, j int) bool {
			if neighbors[i].distance == neighbors[j].distance {
				return neighbors[i].comment.CreatedAt < neighbors[j].comment.CreatedAt
			}
			return neighbors[i].distance < neighbors[j].distance
		})
		if len(neighbors) > maxThreadContextMessages {
			neighbors = neighbors[:maxThreadContextMessages]
		}
		sort.SliceStable(neighbors, func(i, j int) bool {
			return neighbors[i].comment.CreatedAt < neighbors[j].comment.CreatedAt
		})
		remaining := maxThreadContextRunes
		for _, item := range neighbors {
			if remaining == 0 {
				break
			}
			body := truncateContextRunes(strings.TrimSpace(item.comment.Body), min(maxThreadMessageRunes, remaining))
			if body == "" {
				continue
			}
			role := "reviewer"
			if pullAuthor != "" && strings.EqualFold(item.comment.User.Login, pullAuthor) {
				role = "pull_request_author"
			}
			createdAt, _ := time.Parse(time.RFC3339, item.comment.CreatedAt)
			out[target.ID] = append(out[target.ID], cases.ReviewThreadContext{
				CommentID: item.comment.ID,
				Author:    item.comment.User.Login,
				Role:      role,
				Body:      body,
				CreatedAt: createdAt,
			})
			remaining -= len([]rune(body))
		}
	}
	return out
}

func truncateContextRunes(value string, limit int) string {
	if limit <= 0 {
		return ""
	}
	runes := []rune(value)
	if len(runes) <= limit {
		return value
	}
	if limit == 1 {
		return "…"
	}
	return string(runes[:limit-1]) + "…"
}

func routeThreadContext(context []cases.ReviewThreadContext) []scope.ReviewThreadContext {
	out := make([]scope.ReviewThreadContext, 0, len(context))
	for _, message := range context {
		out = append(out, scope.ReviewThreadContext{
			Author: message.Author,
			Role:   message.Role,
			Body:   message.Body,
		})
	}
	return out
}

func truncateRunes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
