package adversarylabs

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRegisterReviewWatchPostsComments(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/reviews/watches" || r.Header.Get("Authorization") != "Bearer ci-token" {
			t.Fatalf("request = %s auth=%q", r.URL.Path, r.Header.Get("Authorization"))
		}
		var watch ReviewWatch
		if err := json.NewDecoder(r.Body).Decode(&watch); err != nil {
			t.Fatal(err)
		}
		if watch.Repository != "adversarylabs/adversary" || watch.ReviewNodeID != "review-1" || len(watch.Comments) != 1 {
			t.Fatalf("watch = %#v", watch)
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	client := Client{BaseURL: server.URL, HTTP: server.Client()}
	err := client.RegisterReviewWatch(context.Background(), "ci-token", ReviewWatch{
		Repository: "adversarylabs/adversary", PullRequest: 185, ReviewNodeID: "review-1",
		Comments: []ReviewWatchComment{{
			Adversary: "review/engineering", PackageName: "review/engineering",
			FindingID: "finding-1", Body: "Finding body",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestReviewFeedbackMemoryAndPrompt(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("repository") != "adversarylabs/adversary" {
			t.Fatalf("query = %s", r.URL.RawQuery)
		}
		_, _ = w.Write([]byte(`{"memories":[{"id":"f-1","adversary":"review/engineering","package_name":"review/engineering","original_comment":"May race","feedback":"Not an issue because the lock is held","guidance":"The caller holds the lock"}]}`))
	}))
	defer server.Close()

	client := Client{BaseURL: server.URL, HTTP: server.Client()}
	memories, err := client.ReviewFeedbackMemory(context.Background(), "ci-token", "adversarylabs/adversary", nil)
	if err != nil || len(memories) != 1 {
		t.Fatalf("memories=%#v err=%v", memories, err)
	}
	prompt := BuildReviewFeedbackPrompt(memories)
	if !strings.Contains(prompt, "caller holds the lock") || !strings.Contains(prompt, "untrusted quoted data") {
		t.Fatal(prompt)
	}
}
