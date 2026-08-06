package results

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/adversarylabs/adversary/internal/train/securefs"
	_ "modernc.org/sqlite"
)

// DBPath is the SQLite file under the train state root.
func DBPath(stateRoot string) string {
	return filepath.Join(stateRoot, "results.db")
}

// openDB opens (or creates) the results database and ensures schema.
func openDB(stateRoot string) (*sql.DB, error) {
	if stateRoot == "" {
		return nil, fmt.Errorf("state root required")
	}
	if err := securefs.MkdirAll(stateRoot); err != nil {
		return nil, err
	}
	path := DBPath(stateRoot)
	// busy_timeout helps concurrent train CLI + long run
	dsn := path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // SQLite write serialization is simplest single-conn
	if err := migrate(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

func migrate(db *sql.DB) error {
	_, err := db.Exec(`
CREATE TABLE IF NOT EXISTS results (
  id            TEXT PRIMARY KEY,
  run_id        TEXT NOT NULL,
  package       TEXT NOT NULL DEFAULT '',
  kind          TEXT NOT NULL,
  status        TEXT NOT NULL,
  summary       TEXT NOT NULL DEFAULT '',
  title         TEXT NOT NULL DEFAULT '',
  pr_url        TEXT NOT NULL DEFAULT '',
  pr_title      TEXT NOT NULL DEFAULT '',
  case_id       TEXT NOT NULL DEFAULT '',
  concern_id    TEXT NOT NULL DEFAULT '',
  draft_body    TEXT NOT NULL DEFAULT '',
  created_at    TEXT NOT NULL,
  applied_at    TEXT NOT NULL DEFAULT '',
  applied_path  TEXT NOT NULL DEFAULT '',
  branch        TEXT NOT NULL DEFAULT '',
  issue_url     TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_results_status ON results(status);
CREATE INDEX IF NOT EXISTS idx_results_package ON results(package);
CREATE INDEX IF NOT EXISTS idx_results_created ON results(created_at);
CREATE INDEX IF NOT EXISTS idx_results_run ON results(run_id);
`)
	if err != nil {
		return err
	}
	// Rename legacy jargon in place (idempotent).
	_, _ = db.Exec(`UPDATE results SET kind = 'human' WHERE kind IN ('gold', 'expected', 'label')`)
	_, _ = db.Exec(`UPDATE results SET kind = 'false-positive' WHERE kind IN ('extra', 'fp', 'false_positive')`)
	// Additive columns for older DBs.
	_, _ = db.Exec(`ALTER TABLE results ADD COLUMN issue_url TEXT NOT NULL DEFAULT ''`)
	return nil
}

const resultCols = `id, run_id, package, kind, status, summary, title, pr_url, pr_title,
	case_id, concern_id, draft_body, created_at, applied_at, applied_path, branch, issue_url`

func scanResult(row interface {
	Scan(dest ...any) error
}) (Result, error) {
	var r Result
	var created, applied string
	err := row.Scan(
		&r.ID, &r.RunID, &r.Package, &r.Kind, &r.Status, &r.Summary, &r.Title,
		&r.PRURL, &r.PRTitle, &r.CaseID, &r.ConcernID, &r.DraftBody,
		&created, &applied, &r.AppliedPath, &r.Branch, &r.IssueURL,
	)
	if err != nil {
		return Result{}, err
	}
	r.CreatedAt = parseTime(created)
	if applied != "" {
		r.AppliedAt = parseTime(applied)
	}
	r.Kind = normalizeKind(r.Kind)
	return r, nil
}

func parseTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t
	}
	return time.Time{}
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

// upsertResult inserts or replaces a row.
func upsertResult(db *sql.DB, r Result) error {
	_, err := db.Exec(`
INSERT INTO results (
  id, run_id, package, kind, status, summary, title, pr_url, pr_title,
  case_id, concern_id, draft_body, created_at, applied_at, applied_path, branch, issue_url
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
  run_id=excluded.run_id,
  package=excluded.package,
  kind=excluded.kind,
  status=excluded.status,
  summary=excluded.summary,
  title=excluded.title,
  pr_url=excluded.pr_url,
  pr_title=excluded.pr_title,
  case_id=excluded.case_id,
  concern_id=excluded.concern_id,
  draft_body=excluded.draft_body,
  created_at=excluded.created_at,
  applied_at=excluded.applied_at,
  applied_path=excluded.applied_path,
  branch=excluded.branch,
  issue_url=excluded.issue_url
`,
		r.ID, r.RunID, r.Package, r.Kind, r.Status, r.Summary, r.Title,
		r.PRURL, r.PRTitle, r.CaseID, r.ConcernID, r.DraftBody,
		formatTime(r.CreatedAt), formatTime(r.AppliedAt), r.AppliedPath, r.Branch, r.IssueURL,
	)
	return err
}
