package results

import (
	"fmt"
	"os"
	"path/filepath"
)

// ResetDiscovery clears seen-PR memory so train run will re-hunt repos.
// Does not delete results.db, github-cache, or run artifacts.
func ResetDiscovery(stateRoot string) (removed int, err error) {
	dir := filepath.Join(stateRoot, "state", "discovery")
	err = filepath.WalkDir(dir, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			return nil
		}
		removed++
		return nil
	})
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	if err := os.RemoveAll(dir); err != nil {
		return 0, err
	}
	return removed, nil
}

// ResetResults clears the results inbox (SQLite DB + any legacy JSON dir).
func ResetResults(stateRoot string) (removed int, err error) {
	// Prefer SQL DELETE so WAL companions stay consistent; fall back to remove file.
	if _, statErr := os.Stat(DBPath(stateRoot)); statErr == nil {
		db, err := openDB(stateRoot)
		if err != nil {
			return 0, err
		}
		var n int
		_ = db.QueryRow(`SELECT COUNT(1) FROM results`).Scan(&n)
		_, err = db.Exec(`DELETE FROM results`)
		_ = db.Close()
		if err != nil {
			return 0, err
		}
		removed += n
		// Also remove db file for a clean slate (and -wal/-shm)
		for _, p := range []string{DBPath(stateRoot), DBPath(stateRoot) + "-wal", DBPath(stateRoot) + "-shm"} {
			if err := os.Remove(p); err == nil {
				// counted rows already
			}
		}
	}

	// Legacy JSON tree
	legacy := filepath.Join(stateRoot, "results")
	entries, err := os.ReadDir(legacy)
	if err != nil {
		if os.IsNotExist(err) {
			return removed, nil
		}
		return removed, err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if err := os.Remove(filepath.Join(legacy, e.Name())); err != nil {
			return removed, err
		}
		removed++
	}
	return removed, nil
}

// ResetAll clears discovery + results (keeps github-cache by default).
func ResetAll(stateRoot string) (string, error) {
	d, err := ResetDiscovery(stateRoot)
	if err != nil {
		return "", err
	}
	r, err := ResetResults(stateRoot)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("cleared %d discovery file(s), %d result row(s)/file(s)", d, r), nil
}
