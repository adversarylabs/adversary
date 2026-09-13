package reviewui

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/adversarylabs/adversary/internal/train/results"
)

func TestHandlerRequiresTokenAndRendersLocalReviewPage(t *testing.T) {
	state := t.TempDir()
	saveCandidate(t, state)
	handler := NewHandler(state, []string{"operability"}, "secret", nil, nil, nil, nil, nil)

	unauthorized := httptest.NewRecorder()
	handler.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/", nil))
	if unauthorized.Code != http.StatusNotFound {
		t.Fatalf("unauthorized status=%d", unauthorized.Code)
	}

	page := httptest.NewRecorder()
	handler.ServeHTTP(page, httptest.NewRequest(http.MethodGet, "/?token=secret", nil))
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), "Adversary training workspace") {
		t.Fatalf("page status=%d body=%q", page.Code, page.Body.String())
	}
	for _, want := range []string{"5 earlier lines", "5 later lines", "repo-group", "repo-chevron", "Repositories ·", "Show all", "Hide all", "New adversary", "AI assist", "Create catalog PR", "Apply to working tree", "Approve for later", "View GitHub evidence", "findingFromURL", "pushState", "Run in background", "job-tray", "/api/jobs/"} {
		if !strings.Contains(page.Body.String(), want) {
			t.Fatalf("review page omitted %q", want)
		}
	}
	for _, want := range []string{"aside{border-right:1px solid var(--line);overflow:hidden", "#list{padding:8px;overflow:auto", ".repo-menu{position:static", ".repo-head{position:sticky;top:0"} {
		if !strings.Contains(page.Body.String(), want) {
			t.Fatalf("review page omitted contained repository navigation style %q", want)
		}
	}
	if got := page.Header().Get("Content-Security-Policy"); !strings.Contains(got, "default-src 'none'") {
		t.Fatalf("CSP=%q", got)
	}

	api := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/candidates", nil)
	req.Header.Set(tokenHeader, "secret")
	handler.ServeHTTP(api, req)
	if api.Code != http.StatusOK || !strings.Contains(api.Body.String(), "candidate-1") {
		t.Fatalf("API status=%d body=%q", api.Code, api.Body.String())
	}
}

func TestHandlerEditsAndDecidesCandidate(t *testing.T) {
	state := t.TempDir()
	saveCandidate(t, state)
	handler := NewHandler(state, []string{"operability", "compatibility"}, "secret", func(_ context.Context, request AssistRequest) (AssistResult, error) {
		return AssistResult{Adversary: "compatibility", ProposedRule: "Preserve the generated API contract.", Rationale: request.Evidence}, nil
	}, func(_ context.Context, request ContextRequest) (ContextResult, error) {
		return ContextResult{Lines: []ContextLine{{Number: 37, Text: "before()"}}, HasMore: request.Offset == 0}, nil
	}, func(_ context.Context, id string) error {
		row, err := results.Get(state, id)
		if err != nil {
			return err
		}
		row.Status = results.StatusApplied
		row.AppliedPath = "/catalog/adversaries/release-contracts/README.md"
		return results.SaveResult(state, row)
	}, func(_ context.Context, id string, report func(Progress)) error {
		report(Progress{Stage: "bootstrap", State: "complete", Detail: "ready"})
		row, err := results.Get(state, id)
		if err != nil {
			return err
		}
		row.Status = results.StatusProposed
		row.Branch = "adversary/train-release-contracts-candidate-1"
		row.CatalogPRURL = "https://github.com/acme/catalog/pull/7"
		return results.SaveResult(state, row)
	}, nil)

	body, _ := json.Marshal(map[string]string{
		"adversary": "release-contracts", "proposed_rule": "Preserve the private wire contract.",
		"adversary_mission": "Catch drift in private release contracts.",
	})
	edit := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPatch, "/api/candidates/candidate-1", bytes.NewReader(body))
	req.Header.Set(tokenHeader, "secret")
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(edit, req)
	if edit.Code != http.StatusOK {
		t.Fatalf("edit status=%d body=%q", edit.Code, edit.Body.String())
	}

	assist := httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/candidates/candidate-1/assist", nil)
	req.Header.Set(tokenHeader, "secret")
	handler.ServeHTTP(assist, req)
	if assist.Code != http.StatusOK || !strings.Contains(assist.Body.String(), "generated API contract") {
		t.Fatalf("assist status=%d body=%q", assist.Code, assist.Body.String())
	}
	contextResponse := httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/candidates/candidate-1/context?direction=up&offset=0", nil)
	req.Header.Set(tokenHeader, "secret")
	handler.ServeHTTP(contextResponse, req)
	if contextResponse.Code != http.StatusOK || !strings.Contains(contextResponse.Body.String(), "before()") {
		t.Fatalf("context status=%d body=%q", contextResponse.Code, contextResponse.Body.String())
	}
	apply := httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/candidates/candidate-1/apply", nil)
	req.Header.Set(tokenHeader, "secret")
	handler.ServeHTTP(apply, req)
	if apply.Code != http.StatusOK || !strings.Contains(apply.Body.String(), "release-contracts/README.md") {
		t.Fatalf("apply status=%d body=%q", apply.Code, apply.Body.String())
	}
	if err := results.Reopen(state, "candidate-1"); err != nil {
		t.Fatal(err)
	}
	pullRequest := httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/candidates/candidate-1/pull-request", nil)
	req.Header.Set(tokenHeader, "secret")
	handler.ServeHTTP(pullRequest, req)
	if pullRequest.Code != http.StatusAccepted {
		t.Fatalf("pull request status=%d body=%q", pullRequest.Code, pullRequest.Body.String())
	}
	var job progressJob
	if err := json.Unmarshal(pullRequest.Body.Bytes(), &job); err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 100; attempt++ {
		status := httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodGet, "/api/jobs/"+job.ID, nil)
		req.Header.Set(tokenHeader, "secret")
		handler.ServeHTTP(status, req)
		if err := json.Unmarshal(status.Body.Bytes(), &job); err != nil {
			t.Fatal(err)
		}
		if job.Done {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if !job.Done || job.Error != "" || job.Candidate == nil || job.Candidate.CatalogPRURL != "https://github.com/acme/catalog/pull/7" {
		t.Fatalf("pull request job=%+v", job)
	}
	if err := results.Reopen(state, "candidate-1"); err != nil {
		t.Fatal(err)
	}
	row, err := results.Get(state, "candidate-1")
	if err != nil {
		t.Fatal(err)
	}
	if row.Package != "release-contracts" || row.ProposedRule != "Preserve the private wire contract." || row.AdversaryMission != "Catch drift in private release contracts." {
		t.Fatalf("edited row=%+v", row)
	}

	for action, want := range map[string]string{"accept": results.StatusAccepted, "reopen": results.StatusNew, "dismiss": results.StatusDismissed} {
		response := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/candidates/candidate-1/"+action, nil)
		req.Header.Set(tokenHeader, "secret")
		handler.ServeHTTP(response, req)
		if response.Code != http.StatusOK {
			t.Fatalf("%s status=%d body=%q", action, response.Code, response.Body.String())
		}
		row, err = results.Get(state, "candidate-1")
		if err != nil || row.Status != want {
			t.Fatalf("%s row=%+v err=%v", action, row, err)
		}
	}
}

func saveCandidate(t *testing.T, state string) {
	t.Helper()
	if err := results.SaveResult(state, results.Result{
		ID: "candidate-1", Package: "operability", Kind: results.KindHuman,
		Status: results.StatusNew, Summary: "Log the private operation failure.",
		PRAuthor: "octocat", CommentAuthor: "reviewer", CommentURL: "https://github.com/acme/api/pull/1#discussion_r2",
		File: "internal/worker.go", Line: 42, DiffHunk: "@@ -40,2 +40,2 @@\n-old()\n+new()",
		ProposedRule: "Log operation failures.", CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
}
