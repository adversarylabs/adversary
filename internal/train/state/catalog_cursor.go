package state

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/adversarylabs/adversary/internal/publock"
	"github.com/adversarylabs/adversary/internal/train/securefs"
)

// CatalogCursorState persists the next repository window used by live train
// discovery. Each target advances independently, while NextSeed staggers the
// first window assigned to a newly seen target.
type CatalogCursorState struct {
	SchemaVersion int            `json:"schema_version"`
	NextSeed      int            `json:"next_seed"`
	NextByTarget  map[string]int `json:"next_by_target"`
	path          string
}

// CatalogCursorPath is the durable repository-window cursor path.
func CatalogCursorPath(dataRoot string) string {
	return filepath.Join(dataRoot, "state", "discovery", "catalog-cursor.json")
}

// TakeCatalogWindow reserves up to limit repositories from a catalog of total
// entries and advances the durable cursor. A window stops at the end of the
// catalog instead of wrapping and re-probing repositories in the same coverage
// cycle. Each target advances independently; a shared seed distributes the
// first window of newly seen targets across the catalog.
func TakeCatalogWindow(dataRoot, target string, total, limit int) (start, count int, err error) {
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
	target = strings.TrimSpace(target)
	if target == "" {
		target = "workspace"
	}
	start, exists := state.NextByTarget[target]
	if !exists {
		start = state.NextSeed
	}
	if start < 0 || start >= total {
		start = 0
	}

	count = limit
	if remaining := total - start; count > remaining {
		count = remaining
	}
	next := (start + count) % total
	state.NextByTarget[target] = next
	if !exists {
		state.NextSeed = next
	}
	if err := state.saveUnlocked(); err != nil {
		return 0, 0, err
	}
	return start, count, nil
}

func loadCatalogCursorUnlocked(dataRoot string) (*CatalogCursorState, error) {
	path := CatalogCursorPath(dataRoot)
	state := &CatalogCursorState{SchemaVersion: 2, NextByTarget: map[string]int{}, path: path}
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
	if state.NextByTarget == nil {
		state.NextByTarget = map[string]int{}
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
