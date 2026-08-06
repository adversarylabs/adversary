package githubreview

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/adversarylabs/adversary/internal/githubapi"
)

func TestPostDryRunNoop(t *testing.T) {
	res, err := Post(context.Background(), CommentPlan{Comments: []PlannedComment{{FindingID: "x"}}}, PostOptions{DryRun: true})
	if err != nil || res == nil {
		t.Fatalf("%v %#v", err, res)
	}
}

func TestPostNothingToPost(t *testing.T) {
	var msgs []string
	res, err := Post(context.Background(), CommentPlan{}, PostOptions{
		Client: githubapi.NewClient("t"),
		Owner:  "o", Repo: "r", Number: 1,
		Progress: func(s string) { msgs = append(msgs, s) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if res == nil {
		t.Fatal("nil result")
	}
	if len(msgs) == 0 || !strings.Contains(msgs[0], "nothing to post") {
		t.Fatalf("%v", msgs)
	}
}

func TestPostCreatesPendingReview(t *testing.T) {
	var gqlBodies []string
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// GraphQL endpoint is absolute URL set on client
		if r.Method == http.MethodPost {
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			q, _ := body["query"].(string)
			gqlBodies = append(gqlBodies, q)
			if strings.Contains(q, "pullRequest(number") {
				_, _ = w.Write([]byte(`{"data":{"repository":{"pullRequest":{"id":"PR_1","headRefOid":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","url":"https://github.com/o/r/pull/1"}}}}`))
				return
			}
			if strings.Contains(q, "addPullRequestReview") {
				_, _ = w.Write([]byte(`{"data":{"addPullRequestReview":{"pullRequestReview":{"id":"RV_1","url":"https://github.com/o/r/pull/1#pullrequestreview-1","state":"PENDING"}}}}`))
				return
			}
			if strings.Contains(q, "submitPullRequestReview") {
				_, _ = w.Write([]byte(`{"data":{"submitPullRequestReview":{"pullRequestReview":{"id":"RV_1","url":"https://github.com/o/r/pull/1#pullrequestreview-1","state":"COMMENTED"}}}}`))
				return
			}
		}
		if strings.Contains(r.URL.Path, "/files") {
			_, _ = w.Write([]byte(`[{"filename":"a.go","patch":"@@ -1,1 +1,2 @@\n keep\n+added\n"}]`))
			return
		}
		w.WriteHeader(404)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := githubapi.NewClient("tok")
	c.HTTP = srv.Client()
	c.RESTBase = srv.URL
	c.GQLURL = srv.URL + "/"

	line := 2
	plan := CommentPlan{
		ReviewBody: "overall",
		Comments: []PlannedComment{{
			FindingID: "f1", Title: "T", Severity: "high", Body: "body text", BodySource: "template",
			Placement: "inline", Anchor: Anchor{Path: "a.go", Line: &line},
		}},
	}
	res, err := Post(context.Background(), plan, PostOptions{
		Client: c, Owner: "o", Repo: "r", Number: 1, Submit: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.ReviewID != "RV_1" || res.State != "COMMENTED" {
		t.Fatalf("%#v gql=%v", res, gqlBodies)
	}
}

func TestWritePlanFile(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/plan.json"
	if err := WritePlanFile(path, CommentPlan{SchemaVersion: 1, Source: "adversary.review.v1"}); err != nil {
		t.Fatal(err)
	}
}
