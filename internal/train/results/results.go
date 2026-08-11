// Package results is the train "inbox": actionable rows stored in SQLite.
// train run writes them; train results ls/inspect/apply consumes them.
//
// Storage: <state_root>/results.db (single file; not a JSON tree).
package results

import (
	"crypto/sha1"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/adversarylabs/adversary/internal/train/cases"
	"github.com/adversarylabs/adversary/internal/train/judge"
	"github.com/adversarylabs/adversary/internal/train/report"
)

const (
	// Status is the lifecycle of a result row.
	StatusNew       = "new"       // open / actionable
	StatusApplied   = "applied"   // user wrote draft into package
	StatusDismissed = "dismissed" // user rejected
	StatusCaught    = "caught"    // package matched the human concern (success)

	// Kind is what kind of evaluation signal this row is.
	// (Avoids opaque eval jargon like "gold".)
	//
	//   human          — human reviewer said this (in-scope); stored as soon as PR is kept
	//   miss           — we should have caught it; package did not match
	//   false-positive — we raised a finding the human review did not
	//   draft          — generalized package improvement suggestion
	KindHuman         = "human"
	KindMiss          = "miss"
	KindFalsePositive = "false-positive"
	KindDraft         = "draft"

	// KindExtra is a deprecated alias for KindFalsePositive (older rows).
	KindExtra = "false-positive"
	// KindGold is a deprecated alias for KindHuman (older rows / SQLite).
	KindGold = "human"
)

// Result is one actionable row in the train inbox.
type Result struct {
	ID          string    `json:"id"`
	RunID       string    `json:"run_id"`
	Package     string    `json:"package"`
	Kind        string    `json:"kind"` // human | miss | false-positive | draft
	Status      string    `json:"status"`
	Summary     string    `json:"summary"`
	Title       string    `json:"title,omitempty"`
	PRURL       string    `json:"pr_url,omitempty"`
	PRTitle     string    `json:"pr_title,omitempty"`
	CaseID      string    `json:"case_id,omitempty"`
	ConcernID   string    `json:"concern_id,omitempty"`
	DraftBody   string    `json:"draft_body,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	AppliedAt   time.Time `json:"applied_at,omitempty"`
	AppliedPath string    `json:"applied_path,omitempty"`
	Branch      string    `json:"branch,omitempty"`
	IssueURL    string    `json:"issue_url,omitempty"`
}

// normalizeKind maps legacy stored values to current vocabulary.
func normalizeKind(k string) string {
	switch strings.ToLower(strings.TrimSpace(k)) {
	case "gold", "expected", "label":
		return KindHuman
	case "extra", "fp", "false_positive":
		return KindFalsePositive
	case "miss", "missed", "missed-concern":
		return KindMiss
	case "draft", "issue":
		return KindDraft
	case "human", "false-positive":
		return strings.ToLower(k)
	default:
		return k
	}
}

// KindLabel is a short CLI column for kind.
func KindLabel(k string) string {
	switch normalizeKind(k) {
	case KindHuman:
		return "human"
	case KindMiss:
		return "miss"
	case KindFalsePositive:
		return "false+"
	case KindDraft:
		return "draft"
	default:
		return trunc(k, 8)
	}
}

// KindExplain is one plain sentence for inspect.
func KindExplain(k, status string) string {
	k = normalizeKind(k)
	switch {
	case k == KindMiss:
		return "Should have caught — human raised this; the package did not match it."
	case k == KindFalsePositive:
		return "False positive — package raised this; the human review did not."
	case k == KindDraft:
		return "Draft improvement — suggested package change from one or more misses."
	case k == KindHuman && status == StatusCaught:
		return "Caught — human raised this and the package matched it."
	case k == KindHuman:
		return "Human concern — in-scope review comment; waiting for (or mid) grade."
	case status == StatusCaught:
		return "Caught — package matched the human concern."
	default:
		return k
	}
}

// Get loads one result by id from SQLite.
func Get(stateRoot, id string) (Result, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return Result{}, fmt.Errorf("result id required")
	}
	db, err := openDB(stateRoot)
	if err != nil {
		return Result{}, err
	}
	defer db.Close()

	// One-time import of legacy JSON inbox if present and table empty.
	_ = maybeMigrateLegacyJSON(db, stateRoot)

	r, err := getResultDB(db, id)
	if err == sql.ErrNoRows {
		return Result{}, fmt.Errorf("result %q not found (run: adversary train results ls)", id)
	}
	if err != nil {
		return Result{}, err
	}
	return r, nil
}

func getResultDB(db *sql.DB, id string) (Result, error) {
	row := db.QueryRow(`SELECT `+resultCols+` FROM results WHERE id = ?`, id)
	return scanResult(row)
}

// Exists reports whether an id is already in the database.
func Exists(stateRoot, id string) (bool, error) {
	db, err := openDB(stateRoot)
	if err != nil {
		return false, err
	}
	defer db.Close()
	var n int
	err = db.QueryRow(`SELECT COUNT(1) FROM results WHERE id = ?`, id).Scan(&n)
	return n > 0, err
}

// List returns results, newest first, optional filters.
func List(stateRoot string, packageFilter, statusFilter string) ([]Result, error) {
	db, err := openDB(stateRoot)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	_ = maybeMigrateLegacyJSON(db, stateRoot)

	pkg := strings.TrimSpace(packageFilter)
	st := strings.TrimSpace(statusFilter)
	q := `SELECT ` + resultCols + ` FROM results WHERE 1=1`
	var args []any
	if pkg != "" {
		q += ` AND lower(package) = lower(?)`
		args = append(args, pkg)
	}
	if st != "" {
		q += ` AND lower(status) = lower(?)`
		args = append(args, st)
	}
	q += ` ORDER BY created_at DESC`

	rows, err := db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Result
	for rows.Next() {
		r, err := scanResult(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func isVoicePackage(owner string) bool {
	o := strings.ToLower(strings.TrimSpace(owner))
	return strings.Contains(o, "torvalds") || strings.Contains(o, "persona") ||
		strings.HasPrefix(o, "person-") || strings.HasPrefix(o, "person/")
}

func missTitle(owner, summary string) string {
	spirit := ClassifyCommentSpirit(summary)
	pkg := owner
	if pkg == "" {
		pkg = "package"
	}
	switch spirit {
	case SpiritShip:
		return soft(fmt.Sprintf("%s: ship/OK signal when change is landable", pkg), 80)
	case SpiritStyle:
		return soft(fmt.Sprintf("%s: style/nit judgment in persona voice", pkg), 80)
	case SpiritDefect:
		return soft(fmt.Sprintf("%s: catch defect class — %s", pkg, summary), 80)
	default:
		return soft(fmt.Sprintf("%s: technical judgment — %s", pkg, summary), 80)
	}
}

// SaveResult upserts one result into SQLite.
func SaveResult(stateRoot string, r Result) error {
	db, err := openDB(stateRoot)
	if err != nil {
		return err
	}
	defer db.Close()
	if r.CreatedAt.IsZero() {
		r.CreatedAt = time.Now().UTC()
	}
	return upsertResult(db, r)
}

// CountByRun returns the number of unique inbox rows owned by runID.
// Progressive training writes may insert a row and later update that same row,
// so counting write operations does not accurately describe the inbox.
func CountByRun(stateRoot, runID string) (int, error) {
	if strings.TrimSpace(runID) == "" {
		return 0, fmt.Errorf("run id required")
	}
	db, err := openDB(stateRoot)
	if err != nil {
		return 0, err
	}
	defer db.Close()

	var n int
	if err := db.QueryRow(`SELECT COUNT(1) FROM results WHERE run_id = ?`, runID).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

// WriteInput is enough of a finished grade run to build inbox rows.
type WriteInput struct {
	RunID    string
	Cases    []*cases.Case
	Failures []judge.Failure
	Issues   []report.SuggestedIssue
}

// concernID builds a stable primary key for one gold concern in a run.
// Same id is used for gold → miss upgrade so interrupt-safe progressive writes
// do not duplicate rows.
func concernResultID(runID, owner, caseID, concernID string) string {
	return shortID(runID, "concern", owner, caseID, concernID)
}

// WriteKeptCase persists in-scope gold as soon as a PR is kept during hunt.
// Safe to call from concurrent hunt workers (SQLite single-conn + busy timeout).
// Returns how many rows were newly inserted (not updated).
func WriteKeptCase(stateRoot, runID string, c *cases.Case) (int, error) {
	if stateRoot == "" || c == nil {
		return 0, nil
	}
	db, err := openDB(stateRoot)
	if err != nil {
		return 0, err
	}
	defer db.Close()

	now := time.Now().UTC()
	prURL := c.Repository.URL
	if c.PullRequest.Number > 0 && !strings.Contains(prURL, "/pull/") {
		prURL = fmt.Sprintf("https://github.com/%s/%s/pull/%d", c.Repository.Owner, c.Repository.Name, c.PullRequest.Number)
	}
	n := 0
	for _, e := range cases.ApprovedLabels(c.Labels.ExpectedConcerns) {
		owner := e.OwnerAdversary
		if owner == "" {
			owner = "unknown"
		}
		id := concernResultID(runID, owner, c.ID, e.ID)
		var existing string
		err := db.QueryRow(`SELECT status FROM results WHERE id = ?`, id).Scan(&existing)
		if err == nil {
			// Already graded or kept — leave status alone.
			continue
		}
		if err != sql.ErrNoRows {
			return n, err
		}
		body := fmt.Sprintf("## Human concern (awaiting grade)\n\nPackage: `%s`\n\n%s\n\n", owner, e.Summary)
		if prURL != "" {
			body += fmt.Sprintf("PR: %s\n", prURL)
		}
		if e.File != "" {
			body += fmt.Sprintf("File: `%s`\n", e.File)
		}
		r := Result{
			ID:        id,
			RunID:     runID,
			Package:   owner,
			Kind:      KindHuman,
			Status:    StatusNew,
			Summary:   strings.TrimSpace(e.Summary),
			Title:     soft(e.Summary, 80),
			PRURL:     prURL,
			PRTitle:   c.PullRequest.Title,
			CaseID:    c.ID,
			ConcernID: e.ID,
			DraftBody: body,
			CreatedAt: now,
		}
		if err := upsertResult(db, r); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// WriteGradedCase updates gold rows after a case is judged.
// Misses become kind=miss with a richer draft; matched concerns become status=caught.
func WriteGradedCase(stateRoot, runID string, c *cases.Case, fails []judge.Failure) (int, error) {
	if stateRoot == "" || c == nil {
		return 0, nil
	}
	db, err := openDB(stateRoot)
	if err != nil {
		return 0, err
	}
	defer db.Close()

	now := time.Now().UTC()
	prURL := c.Repository.URL
	if c.PullRequest.Number > 0 && !strings.Contains(prURL, "/pull/") {
		prURL = fmt.Sprintf("https://github.com/%s/%s/pull/%d", c.Repository.Owner, c.Repository.Name, c.PullRequest.Number)
	}

	// Index failures by concern id
	missed := map[string]judge.Failure{}
	for _, f := range fails {
		if f.Kind == "missed-concern" && f.ConcernID != "" {
			missed[f.ConcernID] = f
		}
	}

	n := 0
	for _, e := range cases.ApprovedLabels(c.Labels.ExpectedConcerns) {
		owner := e.OwnerAdversary
		if owner == "" {
			if f, ok := missed[e.ID]; ok && f.ReviewerID != "" && f.ReviewerID != "multi" {
				owner = f.ReviewerID
			} else {
				owner = "unknown"
			}
		}
		id := concernResultID(runID, owner, c.ID, e.ID)
		if _, isMiss := missed[e.ID]; isMiss {
			body := BuildMissDraft(MissDraftInput{
				Package:  owner,
				Summary:  e.Summary,
				PRURL:    prURL,
				PRTitle:  c.PullRequest.Title,
				CaseID:   c.ID,
				File:     e.File,
				VoicePkg: isVoicePackage(owner),
			})
			r := Result{
				ID:        id,
				RunID:     runID,
				Package:   owner,
				Kind:      KindMiss,
				Status:    StatusNew,
				Summary:   strings.TrimSpace(e.Summary),
				Title:     missTitle(owner, e.Summary),
				PRURL:     prURL,
				PRTitle:   c.PullRequest.Title,
				CaseID:    c.ID,
				ConcernID: e.ID,
				DraftBody: body,
				CreatedAt: now,
			}
			// Preserve user lifecycle (applied/dismissed) across re-grades so
			// results ls does not flip applied rows back to new.
			if prev, err := getResultDB(db, id); err == nil {
				r.CreatedAt = prev.CreatedAt
				if prev.Status == StatusApplied || prev.Status == StatusDismissed {
					r.Status = prev.Status
					r.AppliedAt = prev.AppliedAt
					r.AppliedPath = prev.AppliedPath
					r.Branch = prev.Branch
					r.IssueURL = prev.IssueURL
				}
			}
			if err := upsertResult(db, r); err != nil {
				return n, err
			}
			n++
			continue
		}
		// Matched (or no failure recorded for this gold) → mark caught if present or insert as caught
		var status, kind string
		err := db.QueryRow(`SELECT status, kind FROM results WHERE id = ?`, id).Scan(&status, &kind)
		if err == sql.ErrNoRows {
			// Never stored as human-row but matched — record as caught.
			r := Result{
				ID: id, RunID: runID, Package: owner, Kind: KindHuman, Status: StatusCaught,
				Summary: strings.TrimSpace(e.Summary), Title: soft(e.Summary, 80),
				PRURL: prURL, PRTitle: c.PullRequest.Title, CaseID: c.ID, ConcernID: e.ID,
				DraftBody: fmt.Sprintf("## Caught\n\nPackage matched this human concern:\n\n%s\n", e.Summary),
				CreatedAt: now,
			}
			if err := upsertResult(db, r); err != nil {
				return n, err
			}
			n++
			continue
		}
		if err != nil {
			return n, err
		}
		if status == StatusApplied || status == StatusDismissed {
			continue
		}
		_, err = db.Exec(`UPDATE results SET kind = ?, status = ?, summary = ? WHERE id = ?`,
			KindHuman, StatusCaught, strings.TrimSpace(e.Summary), id)
		if err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// WriteFromRun appends new result rows for this run. Returns how many new rows.
// Prefer progressive WriteKeptCase / WriteGradedCase during the run; this is the
// end-of-run draft aggregation + any misses not yet written.
func WriteFromRun(stateRoot string, in WriteInput) (int, error) {
	if stateRoot == "" {
		return 0, fmt.Errorf("state root required")
	}
	db, err := openDB(stateRoot)
	if err != nil {
		return 0, err
	}
	defer db.Close()
	_ = maybeMigrateLegacyJSON(db, stateRoot)

	now := time.Now().UTC()
	caseByID := map[string]*cases.Case{}
	for _, c := range in.Cases {
		if c != nil {
			caseByID[c.ID] = c
		}
	}

	var added []Result

	for _, iss := range in.Issues {
		pkg := packageFromLabels(iss.Labels)
		if pkg == "" {
			pkg = packageFromTitle(iss.Title)
		}
		identity := strings.TrimSpace(iss.Key)
		if identity == "" {
			identity = iss.Title
		}
		id := shortID(in.RunID, KindDraft, pkg, identity)
		added = append(added, Result{
			ID:        id,
			RunID:     in.RunID,
			Package:   pkg,
			Kind:      KindDraft,
			Status:    StatusNew,
			Summary:   soft(iss.Title, 100),
			Title:     iss.Title,
			ConcernID: iss.Key,
			DraftBody: iss.Body,
			CreatedAt: now,
		})
	}

	draftedKeys := map[string]bool{}
	for _, r := range added {
		draftedKeys[strings.ToLower(r.Package)+"|"+strings.ToLower(r.Summary)] = true
	}
	for _, f := range in.Failures {
		if f.Kind != "missed-concern" {
			continue
		}
		c := caseByID[f.CaseID]
		summary := f.ConcernID
		pkg := f.ReviewerID
		prURL, prTitle := "", ""
		if c != nil {
			prURL = c.Repository.URL
			if c.PullRequest.Number > 0 && !strings.Contains(prURL, "/pull/") {
				prURL = fmt.Sprintf("https://github.com/%s/%s/pull/%d", c.Repository.Owner, c.Repository.Name, c.PullRequest.Number)
			}
			prTitle = c.PullRequest.Title
			for _, e := range c.Labels.ExpectedConcerns {
				if e.ID == f.ConcernID {
					summary = e.Summary
					if e.OwnerAdversary != "" {
						pkg = e.OwnerAdversary
					}
					break
				}
			}
		}
		if pkg == "" || pkg == "multi" {
			pkg = "unknown"
		}
		key := strings.ToLower(pkg) + "|" + strings.ToLower(soft(summary, 100))
		if draftedKeys[key] {
			continue
		}
		// Same id as progressive WriteKeptCase/WriteGradedCase so end-of-run is idempotent.
		id := concernResultID(in.RunID, pkg, f.CaseID, f.ConcernID)
		body := fmt.Sprintf("## Miss\n\nPackage: `%s`\n\n%s\n\n", pkg, summary)
		if prURL != "" {
			body += fmt.Sprintf("PR: %s\n", prURL)
		}
		added = append(added, Result{
			ID:        id,
			RunID:     in.RunID,
			Package:   pkg,
			Kind:      KindMiss,
			Status:    StatusNew,
			Summary:   strings.TrimSpace(summary),
			Title:     soft(summary, 80),
			PRURL:     prURL,
			PRTitle:   prTitle,
			CaseID:    f.CaseID,
			ConcernID: f.ConcernID,
			DraftBody: body,
			CreatedAt: now,
		})
	}

	n := 0
	for _, r := range added {
		var count int
		if err := db.QueryRow(`SELECT COUNT(1) FROM results WHERE id = ?`, r.ID).Scan(&count); err != nil {
			return n, err
		}
		if count > 0 {
			continue
		}
		if err := upsertResult(db, r); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// FormatListTable returns a fixed-width table for CLI.
func FormatListTable(rows []Result) string {
	if len(rows) == 0 {
		return "No results. Run: adversary train run\n"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%-10s %-10s %-18s %-8s %s\n", "ID", "STATUS", "PACKAGE", "KIND", "SUMMARY")
	fmt.Fprintf(&b, "%s\n", strings.Repeat("-", 100))
	for _, r := range rows {
		fmt.Fprintf(&b, "%-10s %-10s %-18s %-8s %s\n",
			trunc(r.ID, 10),
			trunc(r.Status, 10),
			trunc(r.Package, 18),
			trunc(KindLabel(r.Kind), 8),
			soft(r.Summary, 68),
		)
	}
	fmt.Fprintf(&b, "\n%d result(s). Inspect: adversary train results inspect <id>\n", len(rows))
	fmt.Fprintf(&b, "Apply:   adversary train results apply <id>\n")
	fmt.Fprintf(&b, "Kinds:   human = human said it · miss = should have caught · false+ = we over-fired · draft = package fix idea\n")
	fmt.Fprintf(&b, "Store:   SQLite results.db\n")
	return b.String()
}

// FormatInspect returns a human detail view.
func FormatInspect(r Result) string {
	var b strings.Builder
	fmt.Fprintf(&b, "ID:      %s\n", r.ID)
	fmt.Fprintf(&b, "Status:  %s\n", r.Status)
	fmt.Fprintf(&b, "Package: %s\n", r.Package)
	fmt.Fprintf(&b, "Kind:    %s\n", KindLabel(r.Kind))
	fmt.Fprintf(&b, "Meaning: %s\n", KindExplain(r.Kind, r.Status))
	fmt.Fprintf(&b, "Run:     %s\n", r.RunID)
	fmt.Fprintf(&b, "Summary: %s\n", r.Summary)
	if r.Title != "" && r.Title != r.Summary {
		fmt.Fprintf(&b, "Title:   %s\n", r.Title)
	}
	if r.PRURL != "" {
		fmt.Fprintf(&b, "PR:      %s\n", r.PRURL)
	}
	if r.PRTitle != "" {
		fmt.Fprintf(&b, "PR title:%s\n", r.PRTitle)
	}
	if r.CaseID != "" {
		fmt.Fprintf(&b, "Case:    %s\n", r.CaseID)
	}
	if r.AppliedPath != "" {
		fmt.Fprintf(&b, "Applied: %s\n", r.AppliedPath)
	}
	if r.Branch != "" {
		fmt.Fprintf(&b, "Branch:  %s\n", r.Branch)
	}
	if r.IssueURL != "" {
		fmt.Fprintf(&b, "Issue:   %s\n", r.IssueURL)
	}
	fmt.Fprintf(&b, "Created: %s\n", r.CreatedAt.Format(time.RFC3339))
	if r.DraftBody != "" {
		fmt.Fprintf(&b, "\n--- draft ---\n\n%s\n", strings.TrimSpace(r.DraftBody))
	}
	return b.String()
}

func shortID(parts ...string) string {
	h := sha1.Sum([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(h[:])[:8]
}

func soft(s string, n int) string {
	s = strings.Join(strings.Fields(strings.ReplaceAll(s, "\n", " ")), " ")
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func packageFromLabels(labels []string) string {
	for _, l := range labels {
		if strings.HasPrefix(l, "adversary:") {
			return strings.TrimPrefix(l, "adversary:")
		}
	}
	return ""
}

func packageFromTitle(title string) string {
	if i := strings.Index(title, ":"); i > 0 {
		return strings.TrimSpace(title[:i])
	}
	return ""
}

// maybeMigrateLegacyJSON imports old results/*.json + index.json once if DB empty.
func maybeMigrateLegacyJSON(db *sql.DB, stateRoot string) error {
	var n int
	if err := db.QueryRow(`SELECT COUNT(1) FROM results`).Scan(&n); err != nil || n > 0 {
		return err
	}
	legacyDir := filepath.Join(stateRoot, "results")
	indexPath := filepath.Join(legacyDir, "index.json")
	raw, err := os.ReadFile(indexPath)
	if err != nil {
		// try individual json files
		entries, err2 := os.ReadDir(legacyDir)
		if err2 != nil {
			return nil
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") || e.Name() == "index.json" {
				continue
			}
			b, err := os.ReadFile(filepath.Join(legacyDir, e.Name()))
			if err != nil {
				continue
			}
			var r Result
			if json.Unmarshal(b, &r) != nil || r.ID == "" {
				continue
			}
			_ = upsertResult(db, r)
		}
		return nil
	}
	var idx struct {
		Results []Result `json:"results"`
	}
	if json.Unmarshal(raw, &idx) != nil {
		return nil
	}
	for _, r := range idx.Results {
		if r.ID == "" {
			continue
		}
		_ = upsertResult(db, r)
	}
	return nil
}
