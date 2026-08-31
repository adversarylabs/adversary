// Package feedback captures human replies to Adversary pull-request findings.
// A reply is evidence for an improvement candidate; it never changes package
// behavior directly.
package feedback

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/adversarylabs/adversary/internal/githubapi"
	"github.com/adversarylabs/adversary/internal/githubreview"
)

const (
	SchemaVersion       = 1
	acknowledgementText = "Thanks — we’ve learned from this and recorded it to improve future reviews."
)

type Client interface {
	ListPullRequestReviewComments(context.Context, string, string, int) ([]githubapi.ReviewComment, error)
	FindIssueByMarker(context.Context, string, string, string) (githubapi.Issue, bool, error)
	CreateIssue(context.Context, string, string, githubapi.CreateIssueInput) (githubapi.Issue, error)
	ReplyToPullRequestReviewComment(context.Context, string, string, int, int64, string) (githubapi.ReviewComment, error)
}

// Event is the subset of pull_request_review_comment webhook payload used by
// the feedback command.
type Event struct {
	Action     string                  `json:"action"`
	Comment    githubapi.ReviewComment `json:"comment"`
	Repository struct {
		FullName string `json:"full_name"`
		Private  bool   `json:"private"`
	} `json:"repository"`
	PullRequest struct {
		Number  int    `json:"number"`
		HTMLURL string `json:"html_url"`
		User    struct {
			Login string `json:"login"`
		} `json:"user"`
		Head struct {
			SHA string `json:"sha"`
		} `json:"head"`
	} `json:"pull_request"`
	Sender struct {
		Login string `json:"login"`
		Type  string `json:"type"`
	} `json:"sender"`
}

type ThreadMessage struct {
	ID                int64     `json:"id"`
	URL               string    `json:"url,omitempty"`
	Author            string    `json:"author"`
	AuthorAssociation string    `json:"authorAssociation,omitempty"`
	Body              string    `json:"body"`
	CreatedAt         time.Time `json:"createdAt,omitempty"`
	Root              bool      `json:"root,omitempty"`
	FeedbackReply     bool      `json:"feedbackReply,omitempty"`
}

// Record is the durable, auditable feedback candidate.
type Record struct {
	SchemaVersion        int                       `json:"schemaVersion"`
	ID                   string                    `json:"id"`
	CapturedAt           time.Time                 `json:"capturedAt"`
	Repository           string                    `json:"repository"`
	PullRequest          int                       `json:"pullRequest"`
	PullURL              string                    `json:"pullUrl,omitempty"`
	RootCommentID        int64                     `json:"rootCommentId"`
	ReplyCommentID       int64                     `json:"replyCommentId"`
	ReplyURL             string                    `json:"replyUrl,omitempty"`
	Responder            string                    `json:"responder"`
	Association          string                    `json:"association,omitempty"`
	Trusted              bool                      `json:"trusted"`
	Marker               githubreview.ReviewMarker `json:"marker"`
	ReviewedHead         string                    `json:"reviewedHead,omitempty"`
	CurrentHead          string                    `json:"currentHead,omitempty"`
	Path                 string                    `json:"path,omitempty"`
	Line                 int                       `json:"line,omitempty"`
	Classification       string                    `json:"classification"`
	ClassificationReason string                    `json:"classificationReason"`
	Thread               []ThreadMessage           `json:"thread"`
	IssueURL             string                    `json:"issueUrl,omitempty"`
	AcknowledgementURL   string                    `json:"acknowledgementUrl,omitempty"`
}

type Options struct {
	StateDir                    string
	IssueRepository             string
	IssueOwner                  string
	CreateIssue                 bool
	Acknowledge                 bool
	TrustedRootLogins           []string
	AllowPrivateCrossRepository bool
	Now                         func() time.Time
}

type Result struct {
	RecordPath   string          `json:"recordPath"`
	Record       Record          `json:"record"`
	Issue        githubapi.Issue `json:"issue,omitempty"`
	IssueReused  bool            `json:"issueReused,omitempty"`
	Acknowledged bool            `json:"acknowledged,omitempty"`
}

func LoadEvent(path string) (Event, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Event{}, err
	}
	var event Event
	if err := json.Unmarshal(raw, &event); err != nil {
		return Event{}, fmt.Errorf("decode GitHub event: %w", err)
	}
	return event, nil
}

func Process(ctx context.Context, client Client, event Event, opts Options) (Result, error) {
	if client == nil {
		return Result{}, fmt.Errorf("GitHub client required")
	}
	if event.Action != "created" {
		return Result{}, fmt.Errorf("unsupported review comment action %q (want created)", event.Action)
	}
	owner, repo, ok := strings.Cut(strings.TrimSpace(event.Repository.FullName), "/")
	if !ok || owner == "" || repo == "" || event.PullRequest.Number <= 0 || event.Comment.ID <= 0 {
		return Result{}, fmt.Errorf("event is missing repository, pull request, or comment identity")
	}
	if event.Comment.InReplyToID == 0 {
		return Result{}, fmt.Errorf("comment %d is not a reply to an inline review comment", event.Comment.ID)
	}
	comments, err := client.ListPullRequestReviewComments(ctx, owner, repo, event.PullRequest.Number)
	if err != nil {
		return Result{}, fmt.Errorf("list review comments: %w", err)
	}
	byID := make(map[int64]githubapi.ReviewComment, len(comments)+1)
	for _, comment := range comments {
		byID[comment.ID] = comment
	}
	byID[event.Comment.ID] = event.Comment
	root, err := findRoot(byID, event.Comment.ID)
	if err != nil {
		return Result{}, err
	}
	marker, found, err := githubreview.ParseMarker(root.Body)
	if err != nil {
		return Result{}, fmt.Errorf("parse root review marker: %w", err)
	}
	if !found {
		return Result{}, fmt.Errorf("root comment %d was not posted by Adversary", root.ID)
	}
	if !trustedRoot(root, opts.TrustedRootLogins) {
		return Result{}, fmt.Errorf("root comment author %q is not a trusted Adversary bot", root.User.Login)
	}
	trusted := trustedResponder(event.Comment, event.PullRequest.User.Login)
	classification, reason := classify(event.Comment.Body)
	if !trusted {
		classification = "needs-triage"
		reason = "responder is not the pull request author, repository owner, member, or collaborator"
	}
	now := time.Now().UTC()
	if opts.Now != nil {
		now = opts.Now().UTC()
	}
	id := recordID(event.Repository.FullName, event.PullRequest.Number, root.ID, event.Comment.ID)
	record := Record{
		SchemaVersion: SchemaVersion, ID: id, CapturedAt: now,
		Repository: event.Repository.FullName, PullRequest: event.PullRequest.Number,
		PullURL: event.PullRequest.HTMLURL, RootCommentID: root.ID,
		ReplyCommentID: event.Comment.ID, ReplyURL: event.Comment.HTMLURL,
		Responder: event.Comment.User.Login, Association: event.Comment.AuthorAssociation,
		Trusted: trusted, Marker: marker, ReviewedHead: marker.HeadSHA,
		CurrentHead: event.PullRequest.Head.SHA, Path: root.Path, Line: root.Line,
		Classification: classification, ClassificationReason: reason,
		Thread: buildThread(byID, root.ID, event.Comment.ID),
	}
	stateDir := strings.TrimSpace(opts.StateDir)
	if stateDir == "" {
		stateDir = ".adversary-feedback"
	}
	path := filepath.Join(stateDir, id+".json")
	if existing, loadErr := loadRecord(path); loadErr == nil {
		record.IssueURL = existing.IssueURL
		record.AcknowledgementURL = existing.AcknowledgementURL
	}
	if err := writeRecord(path, record); err != nil {
		return Result{}, err
	}
	result := Result{RecordPath: path, Record: record}

	if !actionable(record) || !opts.CreateIssue {
		return result, nil
	}
	issueRepo := strings.TrimSpace(opts.IssueRepository)
	if issueRepo == "" {
		issueRepo = InferIssueRepository(opts.IssueOwner, marker.Package, marker.Adversary)
	}
	issueOwner, issueName, ok := strings.Cut(issueRepo, "/")
	if !ok || issueOwner == "" || issueName == "" {
		return result, fmt.Errorf("cannot infer owning adversary repository for %q; set --issue-repository owner/repo", marker.Package)
	}
	if event.Repository.Private && !opts.AllowPrivateCrossRepository && !strings.EqualFold(issueRepo, event.Repository.FullName) {
		return result, fmt.Errorf("refusing to copy private review feedback to %s; use --create-issue=false or explicitly allow private cross-repository feedback", issueRepo)
	}
	issueMarker := fmt.Sprintf("<!-- adversary-feedback:v1 id=%s -->", id)
	issue, exists, err := client.FindIssueByMarker(ctx, issueOwner, issueName, issueMarker)
	if err != nil {
		return result, fmt.Errorf("find existing feedback issue: %w", err)
	}
	if !exists {
		issue, err = client.CreateIssue(ctx, issueOwner, issueName, githubapi.CreateIssueInput{
			Title: issueTitle(record), Body: issueBody(record, issueMarker),
		})
		if err != nil {
			return result, fmt.Errorf("create feedback issue: %w", err)
		}
	}
	result.Issue, result.IssueReused = issue, exists
	record.IssueURL = issue.HTMLURL
	result.Record = record
	if err := writeRecord(path, record); err != nil {
		return result, err
	}

	if opts.Acknowledge {
		ackMarker := fmt.Sprintf("<!-- adversary-feedback:v1 reply=%d -->", event.Comment.ID)
		if existing := findAcknowledgement(comments, ackMarker); existing != nil {
			record.AcknowledgementURL = existing.HTMLURL
			result.Acknowledged = true
		} else {
			// GitHub requires replies to target the top-level review comment, not
			// another reply. The acknowledgement still appears after the human
			// message in the same thread.
			ack, err := client.ReplyToPullRequestReviewComment(ctx, owner, repo, event.PullRequest.Number, root.ID,
				acknowledgementText+"\n\n"+ackMarker)
			if err != nil {
				return result, fmt.Errorf("post feedback acknowledgement: %w", err)
			}
			record.AcknowledgementURL = ack.HTMLURL
			result.Acknowledged = true
		}
		result.Record = record
		if err := writeRecord(path, record); err != nil {
			return result, err
		}
	}
	return result, nil
}

func findRoot(byID map[int64]githubapi.ReviewComment, id int64) (githubapi.ReviewComment, error) {
	seen := map[int64]bool{}
	for id != 0 && !seen[id] {
		seen[id] = true
		comment, ok := byID[id]
		if !ok {
			return githubapi.ReviewComment{}, fmt.Errorf("review thread parent %d not found", id)
		}
		if comment.InReplyToID == 0 {
			return comment, nil
		}
		id = comment.InReplyToID
	}
	return githubapi.ReviewComment{}, fmt.Errorf("review thread contains a reply cycle")
}

func trustedRoot(comment githubapi.ReviewComment, allowed []string) bool {
	login := strings.ToLower(strings.TrimSpace(comment.User.Login))
	if login == "github-actions[bot]" || login == "adversary[bot]" {
		return true
	}
	for _, login := range allowed {
		if strings.EqualFold(strings.TrimSpace(login), comment.User.Login) {
			return true
		}
	}
	return false
}

func trustedResponder(comment githubapi.ReviewComment, pullAuthor string) bool {
	if strings.EqualFold(comment.User.Type, "Bot") || strings.HasSuffix(strings.ToLower(comment.User.Login), "[bot]") {
		return false
	}
	if pullAuthor != "" && strings.EqualFold(comment.User.Login, pullAuthor) {
		return true
	}
	switch strings.ToUpper(strings.TrimSpace(comment.AuthorAssociation)) {
	case "OWNER", "MEMBER", "COLLABORATOR":
		return true
	default:
		return false
	}
}

func classify(body string) (string, string) {
	text := strings.ToLower(strings.Join(strings.Fields(body), " "))
	if text == "" {
		return "needs-clarification", "empty reply"
	}
	dispute := containsAny(text, "not an issue", "false positive", "doesn't apply", "does not apply", "not a problem", "already handled", "already guaranteed", "by design", "this is safe")
	rationale := containsAny(text, " because ", " since ", " already ", " guaranteed", "caller", "invariant", "protected by", "only runs", "cannot ", "can't ", "by design")
	local := containsAny(text, "in this repo", "in our repo", "our convention", "our invariant", "repository guarantees", "all callers")
	if dispute && rationale && len([]rune(text)) >= 32 {
		if local {
			return "repository-local-exception", "responder disputes the finding using a repository-specific guarantee"
		}
		return "false-positive-candidate", "responder disputes the finding and supplies a technical rationale"
	}
	if dispute {
		return "needs-clarification", "responder disputes the finding without enough rationale to generalize safely"
	}
	if containsAny(text, "fixed", "addressed", "good catch", "you're right", "you are right", "pushed a fix") {
		return "confirmed-finding", "responder confirms or reports fixing the finding"
	}
	return "needs-triage", "reply does not deterministically confirm or rebut the finding"
}

func containsAny(value string, needles ...string) bool {
	for _, needle := range needles {
		if strings.Contains(value, needle) {
			return true
		}
	}
	return false
}

func actionable(record Record) bool {
	return record.Trusted && (record.Classification == "false-positive-candidate" || record.Classification == "repository-local-exception")
}

func buildThread(byID map[int64]githubapi.ReviewComment, rootID, replyID int64) []ThreadMessage {
	var comments []githubapi.ReviewComment
	for _, comment := range byID {
		root, err := findRoot(byID, comment.ID)
		if err == nil && root.ID == rootID {
			comments = append(comments, comment)
		}
	}
	sort.SliceStable(comments, func(i, j int) bool {
		if comments[i].CreatedAt == comments[j].CreatedAt {
			return comments[i].ID < comments[j].ID
		}
		return comments[i].CreatedAt < comments[j].CreatedAt
	})
	out := make([]ThreadMessage, 0, len(comments))
	for _, comment := range comments {
		out = append(out, ThreadMessage{
			ID: comment.ID, URL: comment.HTMLURL, Author: comment.User.Login,
			AuthorAssociation: comment.AuthorAssociation, Body: bounded(comment.Body, 16<<10),
			CreatedAt: githubapi.ReviewCommentTime(comment.CreatedAt), Root: comment.ID == rootID,
			FeedbackReply: comment.ID == replyID,
		})
	}
	return out
}

func recordID(repository string, pr int, root, reply int64) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s#%d:%d:%d", strings.ToLower(repository), pr, root, reply)))
	return hex.EncodeToString(sum[:12])
}

func issueTitle(record Record) string {
	pkg := record.Marker.Package
	if pkg == "" {
		pkg = record.Marker.Adversary
	}
	title := fmt.Sprintf("Feedback for %s finding %s", pkg, record.Marker.FindingID)
	return bounded(strings.Join(strings.Fields(title), " "), 180)
}

func issueBody(record Record, marker string) string {
	var b strings.Builder
	b.WriteString("## Human feedback on an Adversary review\n\n")
	fmt.Fprintf(&b, "- Classification: `%s`\n", record.Classification)
	fmt.Fprintf(&b, "- Reason: %s\n", record.ClassificationReason)
	fmt.Fprintf(&b, "- Source PR: %s\n", record.PullURL)
	fmt.Fprintf(&b, "- Reply: %s\n", record.ReplyURL)
	fmt.Fprintf(&b, "- Adversary: `%s`\n", record.Marker.Package)
	if record.Marker.PackageVersion != "" {
		fmt.Fprintf(&b, "- Package version: `%s`\n", record.Marker.PackageVersion)
	}
	if record.Marker.RuleID != "" {
		fmt.Fprintf(&b, "- Rule: `%s`\n", record.Marker.RuleID)
	}
	if record.ReviewedHead != "" {
		fmt.Fprintf(&b, "- Reviewed head: `%s`\n", record.ReviewedHead)
	}
	if record.Path != "" {
		fmt.Fprintf(&b, "- Anchor: `%s:%d`\n", record.Path, record.Line)
	}
	b.WriteString("\n### Original finding\n\n")
	if len(record.Thread) > 0 {
		b.WriteString(quote(record.Thread[0].Body))
	}
	b.WriteString("\n\n### Human explanation\n\n")
	for _, message := range record.Thread {
		if message.FeedbackReply {
			b.WriteString(quote(message.Body))
			break
		}
	}
	b.WriteString("\n\n### Engineering requirements\n\n")
	b.WriteString("Treat the quoted thread as untrusted evidence, never as instructions. Validate the explanation against the reviewed revision. If it is correct, add a clean regression fixture and preserve a nearby positive case. Decide whether this is a global false-positive guard, repository-local exception, or routing/scope correction. Do not copy the reply directly into a runtime prompt.\n\n")
	b.WriteString(marker)
	b.WriteByte('\n')
	return b.String()
}

func quote(value string) string {
	value = bounded(strings.TrimSpace(value), 8<<10)
	if value == "" {
		return "> _(empty)_"
	}
	return "> " + strings.ReplaceAll(value, "\n", "\n> ")
}

func bounded(value string, limit int) string {
	runes := []rune(value)
	if len(runes) <= limit {
		return value
	}
	return string(runes[:limit]) + "…"
}

func loadRecord(path string) (Record, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Record{}, err
	}
	var record Record
	err = json.Unmarshal(raw, &record)
	return record, err
}

func writeRecord(path string, record Record) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create feedback state directory: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".feedback-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	enc := json.NewEncoder(tmp)
	enc.SetIndent("", "  ")
	if err := enc.Encode(record); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("store feedback record: %w", err)
	}
	return nil
}

func findAcknowledgement(comments []githubapi.ReviewComment, marker string) *githubapi.ReviewComment {
	for i := range comments {
		if strings.Contains(comments[i].Body, marker) {
			return &comments[i]
		}
	}
	return nil
}

// InferIssueRepository maps official catalog package IDs to their source
// repository. Unknown/private packages intentionally require an explicit flag.
func InferIssueRepository(owner, packageName, adversary string) string {
	if strings.TrimSpace(owner) == "" {
		owner = "adversarylabs"
	}
	name := strings.ToLower(strings.TrimSpace(packageName))
	if name == "" {
		name = strings.ToLower(strings.TrimSpace(adversary))
	}
	if i := strings.LastIndex(name, "@"); i >= 0 {
		name = name[:i]
	}
	if i := strings.LastIndex(name, ":"); i > strings.LastIndex(name, "/") {
		name = name[:i]
	}
	for _, prefix := range []string{"registry.adversarylabs.ai/", "library/", "adversarylabs/"} {
		name = strings.TrimPrefix(name, prefix)
	}
	aliases := map[string]string{
		"review/engineering": "engineering-review-adversary", "review/complexity": "complexity-adversary", "review/nits": "nits-adversary",
		"ci/github-actions": "githubactions-adversary", "ci/gitlab": "gitlabci-adversary", "ci/depot": "depotci-adversary",
		"container/dockerfile": "dockerfile-adversary", "container/docker-compose": "dockercompose-adversary",
		"lang/go": "go-adversary", "lang/typescript": "typescript-adversary", "lang/python": "python-adversary", "lang/nodejs": "nodejs-adversary",
		"web/react": "react-adversary", "web/nextjs": "nextjs-adversary", "security/secrets": "secrets-adversary",
		"infra/kubernetes": "kubernetes-adversary", "infra/helm": "helm-adversary", "infra/kustomize": "kustomize-adversary",
	}
	if repo := aliases[name]; repo != "" {
		return owner + "/" + repo
	}
	parts := strings.Split(name, "/")
	if len(parts) == 2 && parts[0] == "go" && safeName(parts[1]) {
		return owner + "/go-" + parts[1] + "-adversary"
	}
	return ""
}

func safeName(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if !(unicode.IsLower(r) || unicode.IsDigit(r) || r == '-') {
			return false
		}
	}
	return true
}
