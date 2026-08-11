package state

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/adversarylabs/adversary/internal/publock"
	"github.com/adversarylabs/adversary/internal/train/securefs"
)

// CatalogCursorState persists the next repository window used by live train
// discovery. It is shared across targeted adversaries so sequential training
// runs do not refresh the entire catalog from the beginning each time.
type CatalogCursorState struct {
	SchemaVersion int `json:"schema_version"`
	Next          int `json:"next"`
	path          string
}

// CatalogCursorPath is the durable repository-window cursor path.
func CatalogCursorPath(dataRoot string) string {
	return filepath.Join(dataRoot, "state", "catalog-cursor.json")
}

// TakeCatalogWindow reserves up to limit repositories from a catalog of total
// entries and advances the durable cursor. A window stops at the end of the
// catalog instead of wrapping and re-probing repositories in the same coverage
// cycle. Reset starts again at catalog index zero before reserving the window.
func TakeCatalogWindow(dataRoot string, total, limit int, reset bool) (start, count int, err error) {
	if total <= 0 || limit <= 0 {
		return 0, 0, nil
	}
	if limit > total {
		limit = total
	}

	lock, err := publock.Acquire(dataRoot, "adversary-train-catalog-cursor")
	if err != nil {
		return 0, 0, fmt.Errorf("lock catalog cursor state: %w", err)
	}
	defer lock.Close()

	state, err := loadCatalogCursorUnlocked(dataRoot)
	if err != nil {
		return 0, 0, err
	}
	if reset {
		state.Next = 0
	}
	if state.Next < 0 || state.Next >= total {
		state.Next = 0
	}

	start = state.Next
	count = limit
	if remaining := total - start; count > remaining {
		count = remaining
	}
	state.Next = (start + count) % total
	if err := state.saveUnlocked(); err != nil {
		return 0, 0, err
	}
	return start, count, nil
}

func loadCatalogCursorUnlocked(dataRoot string) (*CatalogCursorState, error) {
	path := CatalogCursorPath(dataRoot)
	state := &CatalogCursorState{SchemaVersion: 1, path: path}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return state, nil
		}
		return nil, err
	}
	if err := json.Unmarshal(raw, state); err != nil {
		return nil, fmt.Errorf("parse catalog cursor state: %w", err)
	}
	state.path = path
	return state, nil
}

func (s *CatalogCursorState) saveUnlocked() error {
	if s == nil || s.path == "" {
		return fmt.Errorf("nil catalog cursor state")
	}
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return securefs.WriteFile(s.path, raw)
}
