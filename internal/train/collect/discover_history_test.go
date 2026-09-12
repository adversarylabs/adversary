package collect

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/adversarylabs/adversary/internal/githubapi"
)

func TestDiscoverHistoricalPRsPaginatesToUpdatedBoundary(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		if page == 1 {
			rows := make([]map[string]any, 100)
			for i := range rows {
				rows[i] = historicalPR(1000-i, "human", "2026-06-01T00:00:00Z", "2026-06-02T00:00:00Z")
			}
			rows[0] = historicalPR(1000, "dependabot[bot]", "2026-06-01T00:00:00Z", "2026-06-02T00:00:00Z")
			_ = json.NewEncoder(w).Encode(rows)
			return
		}
		_ = json.NewEncoder(w).Encode([]map[string]any{
			historicalPR(800, "human", "2024-01-01T00:00:00Z", "2024-01-02T00:00:00Z"),
		})
	}))
	defer server.Close()
	SetDefaultClient(&githubapi.Client{HTTP: server.Client(), RESTBase: server.URL})
	t.Cleanup(func() { SetDefaultClient(nil) })

	rows, err := DiscoverHistoricalPRs("acme", "api", HistoricalDiscoverOpts{
		Context: context.Background(), Since: time.Date(2025, 9, 12, 0, 0, 0, 0, time.UTC),
		Skip: map[int]bool{999: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if requests != 2 {
		t.Fatalf("requests=%d want 2", requests)
	}
	if len(rows) != 98 {
		t.Fatalf("rows=%d want 98 after bot and seen filtering", len(rows))
	}
	if rows[0].Number != 998 {
		t.Fatalf("first row=%+v", rows[0])
	}
}

func historicalPR(number int, login, merged, updated string) map[string]any {
	return map[string]any{
		"number": number, "title": fmt.Sprintf("PR %d", number),
		"html_url":  fmt.Sprintf("https://github.com/acme/api/pull/%d", number),
		"merged_at": merged, "updated_at": updated, "user": map[string]string{"login": login},
	}
}
