package githubapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestReviewCommentListAndReply(t *testing.T) {
	var replyBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/acme/app/pulls/7/comments":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[{"id":11,"body":"root"},{"id":12,"in_reply_to_id":11,"body":"reply"}]`))
		case "/repos/acme/app/pulls/7/comments/12/replies":
			var payload map[string]string
			_ = json.NewDecoder(r.Body).Decode(&payload)
			replyBody = payload["body"]
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":13,"body":"ack"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c := NewClient("token")
	c.RESTBase = srv.URL
	comments, err := c.ListPullRequestReviewComments(context.Background(), "acme", "app", 7)
	if err != nil || len(comments) != 2 || comments[1].InReplyToID != 11 {
		t.Fatalf("comments=%+v err=%v", comments, err)
	}
	got, err := c.ReplyToPullRequestReviewComment(context.Background(), "acme", "app", 7, 12, "thanks")
	if err != nil || got.ID != 13 || replyBody != "thanks" {
		t.Fatalf("reply=%+v body=%q err=%v", got, replyBody, err)
	}
}
