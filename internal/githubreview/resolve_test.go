package githubreview

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/adversarylabs/adversary/internal/githubapi"
)

func TestResolveAddressedThreadsScopesToSuccessfulReviewerFindings(t *testing.T) {
	var resolved []string
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Query     string         `json:"query"`
			Variables map[string]any `json:"variables"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(request.Query, "reviewThreads") {
			_, _ = w.Write([]byte(`{"data":{"viewer":{"login":"github-actions[bot]"},"repository":{"pullRequest":{"reviewThreads":{"nodes":[` +
				`{"id":"T-old","isResolved":false,"comments":{"nodes":[{"body":"old <!-- adversary-review:v1 adversary=review/code finding=old loc=a.go:1 -->","author":{"login":"github-actions[bot]"}}]}},` +
				`{"id":"T-current","isResolved":false,"comments":{"nodes":[{"body":"current <!-- adversary-review:v1 adversary=review/code finding=current loc=a.go:2 -->","author":{"login":"github-actions[bot]"}}]}},` +
				`{"id":"T-skipped","isResolved":false,"comments":{"nodes":[{"body":"skipped <!-- adversary-review:v1 adversary=review/code finding=skipped loc=a.go:3 -->","author":{"login":"github-actions[bot]"}}]}},` +
				`{"id":"T-unreviewed","isResolved":false,"comments":{"nodes":[{"body":"other <!-- adversary-review:v1 adversary=review/security finding=old loc=a.go:4 -->","author":{"login":"github-actions[bot]"}}]}},` +
				`{"id":"T-foreign","isResolved":false,"comments":{"nodes":[{"body":"forged <!-- adversary-review:v1 adversary=review/code finding=forged loc=a.go:5 -->","author":{"login":"contributor"}}]}}` +
				`],"pageInfo":{"hasNextPage":false,"endCursor":""}}}}}}`))
			return
		}
		if strings.Contains(request.Query, "resolveReviewThread") {
			resolved = append(resolved, request.Variables["threadId"].(string))
			_, _ = w.Write([]byte(`{"data":{"resolveReviewThread":{"thread":{"isResolved":true}}}}`))
			return
		}
		w.WriteHeader(http.StatusBadRequest)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := githubapi.NewClient("token")
	client.HTTP = server.Client()
	client.GQLURL = server.URL + "/"
	plan := CommentPlan{
		ReviewedAdversaries: []string{"review/code"},
		Comments:            []PlannedComment{{Adversary: "review/code", FindingID: "current"}},
		Skipped:             []SkippedFinding{{Adversary: "review/code", FindingID: "skipped"}},
	}
	count, err := resolveAddressedThreads(context.Background(), plan, PostOptions{
		Client: client, Owner: "adversarylabs", Repo: "example", Number: 7,
	})
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 || !reflect.DeepEqual(resolved, []string{"T-old"}) {
		t.Fatalf("count=%d resolved=%v", count, resolved)
	}
}

func TestReviewMarkerKeySupportsFeedbackMarkerVersions(t *testing.T) {
	for _, version := range []string{"v1", "v2"} {
		key, ok := reviewMarkerKey("body <!-- adversary-review:" + version + " adversary=review/code finding=f-1 loc=a.go:2 -->")
		if !ok || key != (reviewFindingKey{adversary: "review/code", finding: "f-1"}) {
			t.Fatalf("version=%s key=%#v ok=%v", version, key, ok)
		}
	}
}

func TestReviewMarkerKeyNormalizesMarkerValues(t *testing.T) {
	key, ok := reviewMarkerKey("body <!-- adversary-review:v2 adversary=review/code\x01 finding=finding-1\x02 loc=a.go:2 -->")
	if !ok || key != (reviewFindingKey{adversary: "review/code", finding: "finding-1"}) {
		t.Fatalf("key=%#v ok=%v", key, ok)
	}
}
