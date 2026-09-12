package reviewui

import (
	"bytes"
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
	handler := NewHandler(state, []string{"operability"}, "secret", nil)

	unauthorized := httptest.NewRecorder()
	handler.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/", nil))
	if unauthorized.Code != http.StatusNotFound {
		t.Fatalf("unauthorized status=%d", unauthorized.Code)
	}

	page := httptest.NewRecorder()
	handler.ServeHTTP(page, httptest.NewRequest(http.MethodGet, "/?token=secret", nil))
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), "Catalog training") {
		t.Fatalf("page status=%d body=%q", page.Code, page.Body.String())
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
	handler := NewHandler(state, []string{"operability", "compatibility"}, "secret", nil)

	body, _ := json.Marshal(map[string]string{
		"adversary": "compatibility", "proposed_rule": "Preserve the private wire contract.",
	})
	edit := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPatch, "/api/candidates/candidate-1", bytes.NewReader(body))
	req.Header.Set(tokenHeader, "secret")
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(edit, req)
	if edit.Code != http.StatusOK {
		t.Fatalf("edit status=%d body=%q", edit.Code, edit.Body.String())
	}
	row, err := results.Get(state, "candidate-1")
	if err != nil {
		t.Fatal(err)
	}
	if row.Package != "compatibility" || row.ProposedRule != "Preserve the private wire contract." {
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
		ProposedRule: "Log operation failures.", CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
}
