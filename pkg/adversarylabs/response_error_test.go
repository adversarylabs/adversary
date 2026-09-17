package adversarylabs

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRegisterReviewWatchSafeDiagnostics(t *testing.T) {
	const requestID = "b67c9d88-8b52-40f9-a49a-8f8fbaf16a9a"
	for _, tc := range []struct {
		name, body, requestID, want string
	}{
		{"validation", `{"error":"invalid_request","code":"duplicate_finding","field":"comments[1].finding_id","message":"Bearer ci-secret"}`, requestID, "finding_id must be unique per adversary and package in a review (comments[1].finding_id)"},
		{"legacy", `{"error":"invalid_request","message":"finding_id must be unique per review"}`, "", "finding_id must be unique per review"},
		{"body-request-id", `{"error":"invalid_json","request_id":"` + requestID + `"}`, "", "invalid_json [request_id=" + requestID + "]"},
		{"field", `{"error":"invalid_request","code":"required","field":"review_node_id"}`, "", "required field is missing or empty (review_node_id)"},
		{"arbitrary-json", `{"error":"ci-secret","code":"ci-secret","field":"ci-secret","message":"Bearer ci-secret","request_id":"ci-secret"}`, "ci-secret", "request failed: 400 Bad Request"},
		{"html", `<html>Authorization: Bearer ci-secret</html>`, requestID, "request_id=" + requestID},
		{"malformed", `{"message":"ci-secret"`, "", "request failed: 400 Bad Request"},
		{"oversized", `{"error":"invalid_request","message":"ci-secret` + strings.Repeat("x", 9000) + `"}`, "", "request failed: 400 Bad Request"},
		{"terminal-injection", `{"error":"invalid_request","code":"required","field":"comments[1].body\nci-secret\u001b[31m"}`, "", "required field is missing or empty"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-Request-ID", tc.requestID)
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			client := Client{BaseURL: server.URL, HTTP: server.Client()}
			err := client.RegisterReviewWatch(context.Background(), "ci-secret", ReviewWatch{})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
			if strings.Contains(err.Error(), "ci-secret") || strings.ContainsAny(err.Error(), "\n\r\x1b") || len(err.Error()) > 400 {
				t.Fatalf("unsafe diagnostic: %q", err.Error())
			}
		})
	}
}
