// Package inbox indexes local catalog training databases so every interactive
// adversary command can surface pending review work without copying its data.
package inbox

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/adversarylabs/adversary/internal/train/results"
	"github.com/adversarylabs/adversary/internal/train/securefs"
	_ "modernc.org/sqlite"
)

type Catalog struct {
	ConfigPath string
	StateRoot  string
	Pending    int
}

func registryPath(dataRoot string) string {
	return filepath.Join(dataRoot, "training", "catalogs.db")
}

func openRegistry(dataRoot string) (*sql.DB, error) {
	if strings.TrimSpace(dataRoot) == "" {
		return nil, fmt.Errorf("data root required")
	}
	path := registryPath(dataRoot)
	if err := securefs.MkdirAll(filepath.Dir(path)); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`
CREATE TABLE IF NOT EXISTS catalogs (
  config_path TEXT PRIMARY KEY,
  state_root  TEXT NOT NULL,
  seen_at     TEXT NOT NULL
);`); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := os.Chmod(path, securefs.FileMode); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

// Register records where one catalog keeps its local results database. The
// registry contains paths only; comments, diffs, and result bodies stay in the
// catalog's private state directory.
func Register(dataRoot, configPath, stateRoot string) error {
	configPath, err := filepath.Abs(strings.TrimSpace(configPath))
	if err != nil {
		return err
	}
	stateRoot, err = filepath.Abs(strings.TrimSpace(stateRoot))
	if err != nil {
		return err
	}
	db, err := openRegistry(dataRoot)
	if err != nil {
		return err
	}
	defer db.Close()
	_, err = db.Exec(`
INSERT INTO catalogs (config_path, state_root, seen_at) VALUES (?, ?, ?)
ON CONFLICT(config_path) DO UPDATE SET state_root=excluded.state_root, seen_at=excluded.seen_at
`, configPath, stateRoot, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

// Pending returns registered catalogs with unreviewed local results.
func Pending(dataRoot string) ([]Catalog, error) {
	path := registryPath(dataRoot)
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	db, err := sql.Open("sqlite", path+"?mode=ro&_pragma=busy_timeout(25)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	defer db.Close()
	rows, err := db.Query(`SELECT config_path, state_root FROM catalogs ORDER BY seen_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var catalogs []Catalog
	for rows.Next() {
		var catalog Catalog
		if err := rows.Scan(&catalog.ConfigPath, &catalog.StateRoot); err != nil {
			return nil, err
		}
		if _, err := os.Stat(results.DBPath(catalog.StateRoot)); err != nil {
			continue
		}
		catalog.Pending, err = results.CountStatusReadOnly(catalog.StateRoot, results.StatusNew)
		if err != nil || catalog.Pending == 0 {
			continue
		}
		catalogs = append(catalogs, catalog)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.Slice(catalogs, func(i, j int) bool {
		return catalogs[i].ConfigPath < catalogs[j].ConfigPath
	})
	return catalogs, nil
}
