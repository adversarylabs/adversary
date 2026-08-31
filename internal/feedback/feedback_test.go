package feedback

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/adversarylabs/adversary/internal/githubapi"
	"github.com/adversarylabs/adversary/internal/githubreview"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

type fakeClient struct {
	comments     []githubapi.ReviewComment
	issues       []githubapi.Issue
	replies      []githubapi.ReviewComment
	replyTargets []int64
}

func (f *fakeClient) ListPullRequestReviewComments(context.Context, string, string, int) ([]githubapi.ReviewComment, error) {
	out := append([]githubapi.ReviewComment{}, f.comments...)
	out = append(out, f.replies...)
	return out, nil
}

func (f *fakeClient) FindIssueByMarker(_ context.Context, _, _, marker string) (githubapi.Issue, bool, error) {
	for _, issue := range f.issues {
		if strings.Contains(issue.Body, marker) {
			return issue, true, nil
		}
	}
	return githubapi.Issue{}, false, nil
}

func (f *fakeClient) CreateIssue(_ context.Context, owner, repo string, input githubapi.CreateIssueInput) (githubapi.Issue, error) {
	issue := githubapi.Issue{Number: len(f.issues) + 1, HTMLURL: "https://github.com/" + owner + "/" + repo + "/issues/1", Title: input.Title, Body: input.Body, State: "open"}
	f.issues = append(f.issues, issue)
	return issue, nil
}

func (f *fakeClient) ReplyToPullRequestReviewComment(_ context.Context, owner, repo string, pr int, commentID int64, body string) (githubapi.ReviewComment, error) {
	comment := reviewComment(99, commentID, "github-actions[bot]", "Bot", body, "MEMBER")
	comment.HTMLURL = "https://github.com/acme/app/pull/7#discussion_r99"
	f.replies = append(f.replies, comment)
	f.replyTargets = append(f.replyTargets, commentID)
	return comment, nil
}

func TestProcessCreatesCandidateIssueAndAcknowledgesOnce(t *testing.T) {
	root := reviewComment(11, 0, "github-actions[bot]", "Bot", "finding", "NONE")
	root.Path, root.Line = "worker.go", 10
	root.Body = githubreview.EnsurePlannedMarker("This can race.", githubreview.PlannedComment{
		Adversary: "library/go/concurrency", Package: "go/concurrency", PackageVersion: "1.2.3",
		FindingID: "race-1", RuleID: "map-race", HeadSHA: "abc123",
		Anchor: githubreview.Anchor{Path: root.Path, Line: intPtr(10)},
	})
	reply := reviewComment(12, 11, "author", "User", "This is not an issue because all callers already hold the worker mutex.", "CONTRIBUTOR")
	event := eventFor(reply, "author")
	client := &fakeClient{comments: []githubapi.ReviewComment{root, reply}}
	dir := t.TempDir()
	opts := Options{StateDir: dir, CreateIssue: true, Acknowledge: true, Now: func() time.Time { return time.Unix(10, 0) }}

	first, err := Process(context.Background(), client, event, opts)
	if err != nil {
		t.Fatal(err)
	}
	if first.Record.Classification != "repository-local-exception" || !first.Record.Trusted {
		t.Fatalf("record=%+v", first.Record)
	}
	if len(client.issues) != 1 || len(client.replies) != 1 || len(client.replyTargets) != 1 || client.replyTargets[0] != root.ID || !first.Acknowledged {
		t.Fatalf("issues=%d replies=%d result=%+v", len(client.issues), len(client.replies), first)
	}
	if !strings.Contains(client.replies[0].Body, "we’ve learned from this") {
		t.Fatalf("ack=%q", client.replies[0].Body)
	}
	validateRecordSchema(t, first.Record)
	raw, err := os.ReadFile(first.RecordPath)
	if err != nil || !strings.Contains(string(raw), client.issues[0].HTMLURL) {
		t.Fatalf("stored=%q err=%v", raw, err)
	}

	second, err := Process(context.Background(), client, event, opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(client.issues) != 1 || len(client.replies) != 1 || !second.IssueReused || !second.Acknowledged {
		t.Fatalf("retry duplicated side effects: issues=%d replies=%d result=%+v", len(client.issues), len(client.replies), second)
	}
}

func TestProcessClassifiesRepliesWithoutSideEffectsInCaptureOnlyMode(t *testing.T) {
	root := reviewComment(11, 0, "github-actions[bot]", "Bot", "Finding\n\n<!-- adversary-review:v1 adversary=go-concurrency finding=f1 loc=a.go:1 -->", "NONE")
	tests := []struct {
		name, author, association, pullAuthor, body, want string
	}{
		{"untrusted", "outsider", "NONE", "author", "This is not an issue because callers hold the mutex.", "needs-triage"},
		{"confirmed", "author", "CONTRIBUTOR", "author", "Good catch, fixed in the latest commit.", "confirmed-finding"},
		{"dispute beats fixed word", "author", "CONTRIBUTOR", "author", "This is not an issue because the caller already fixed the value before this function.", "false-positive-candidate"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reply := reviewComment(12, 11, tc.author, "User", tc.body, tc.association)
			client := &fakeClient{comments: []githubapi.ReviewComment{root, reply}}
			result, err := Process(context.Background(), client, eventFor(reply, tc.pullAuthor), Options{StateDir: t.TempDir(), CreateIssue: false, Acknowledge: false})
			if err != nil {
				t.Fatal(err)
			}
			if result.Record.Classification != tc.want || len(client.issues) != 0 || len(client.replies) != 0 {
				t.Fatalf("record=%+v issues=%d replies=%d", result.Record, len(client.issues), len(client.replies))
			}
		})
	}
}

func TestProcessRejectsUnmarkedRoot(t *testing.T) {
	root := reviewComment(11, 0, "github-actions[bot]", "Bot", "ordinary review", "NONE")
	reply := reviewComment(12, 11, "author", "User", "not an issue because x", "CONTRIBUTOR")
	_, err := Process(context.Background(), &fakeClient{comments: []githubapi.ReviewComment{root, reply}}, eventFor(reply, "author"), Options{StateDir: t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "not posted by Adversary") {
		t.Fatalf("err=%v", err)
	}
}

func TestProcessRefusesPrivateCrossRepositoryIssue(t *testing.T) {
	root := reviewComment(11, 0, "github-actions[bot]", "Bot", "Finding\n\n<!-- adversary-review:v1 adversary=go-concurrency finding=f1 loc=a.go:1 -->", "NONE")
	reply := reviewComment(12, 11, "author", "User", "This is not an issue because the caller already holds the mutex.", "CONTRIBUTOR")
	event := eventFor(reply, "author")
	event.Repository.Private = true
	dir := t.TempDir()
	_, err := Process(context.Background(), &fakeClient{comments: []githubapi.ReviewComment{root, reply}}, event, Options{StateDir: dir, IssueRepository: "adversarylabs/go-concurrency-adversary", CreateIssue: true, Acknowledge: true})
	if err == nil || !strings.Contains(err.Error(), "refusing to copy private review feedback") {
		t.Fatalf("err=%v", err)
	}
	entries, readErr := os.ReadDir(dir)
	if readErr != nil || len(entries) != 1 {
		t.Fatalf("private feedback was not retained locally: entries=%v err=%v", entries, readErr)
	}
}

func TestInferIssueRepository(t *testing.T) {
	tests := map[string]string{
		"review/engineering":           "adversarylabs/engineering-review-adversary",
		"library/go/concurrency:1.2.3": "adversarylabs/go-concurrency-adversary",
		"private/custom":               "",
	}
	for input, want := range tests {
		if got := InferIssueRepository("", input, ""); got != want {
			t.Errorf("InferIssueRepository(%q)=%q want %q", input, got, want)
		}
	}
}

func reviewComment(id, parent int64, login, userType, body, association string) githubapi.ReviewComment {
	c := githubapi.ReviewComment{ID: id, InReplyToID: parent, Body: body, AuthorAssociation: association, CreatedAt: "2026-08-31T12:00:00Z"}
	c.User.Login, c.User.Type = login, userType
	c.HTMLURL = "https://github.com/acme/app/pull/7#discussion_r" + strconv.FormatInt(id, 10)
	return c
}

func eventFor(comment githubapi.ReviewComment, pullAuthor string) Event {
	var event Event
	event.Action = "created"
	event.Comment = comment
	event.Repository.FullName = "acme/app"
	event.PullRequest.Number = 7
	event.PullRequest.HTMLURL = "https://github.com/acme/app/pull/7"
	event.PullRequest.User.Login = pullAuthor
	event.PullRequest.Head.SHA = "def456"
	event.Sender.Login, event.Sender.Type = comment.User.Login, comment.User.Type
	return event
}

func intPtr(value int) *int { return &value }

func TestLoadEvent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "event.json")
	if err := os.WriteFile(path, []byte(`{"action":"created","repository":{"full_name":"acme/app"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	event, err := LoadEvent(path)
	if err != nil || event.Repository.FullName != "acme/app" {
		t.Fatalf("event=%+v err=%v", event, err)
	}
}

func validateRecordSchema(t *testing.T, record Record) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "schema", "adversary.feedback.v1.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var document any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	const schemaURL = "https://adversarylabs.dev/schemas/adversary.feedback.v1.schema.json"
	if err := compiler.AddResource(schemaURL, document); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile(schemaURL)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	var value any
	if err := json.Unmarshal(encoded, &value); err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(value); err != nil {
		t.Fatalf("record does not match schema: %v\n%s", err, encoded)
	}
}
