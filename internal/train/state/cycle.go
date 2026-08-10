package state

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/adversarylabs/adversary/internal/train/securefs"
)

// AdversaryCycleTarget records durable round-robin coverage for one package.
type AdversaryCycleTarget struct {
	Selections   int       `json:"selections"`
	LastSelected time.Time `json:"last_selected,omitempty"`
	LastRun      string    `json:"last_run,omitempty"`
}

// AdversaryCycleState persists fair target selection across train invocations.
type AdversaryCycleState struct {
	SchemaVersion int                             `json:"schema_version"`
	LastTarget    string                          `json:"last_target,omitempty"`
	Targets       map[string]AdversaryCycleTarget `json:"targets"`
	path          string                          `json:"-"`
}

// AdversaryCyclePath is the durable scheduler state path.
func AdversaryCyclePath(dataRoot string) string {
	return filepath.Join(dataRoot, "state", "adversary-cycle.json")
}

// LoadAdversaryCycle loads or initializes the durable target scheduler.
func LoadAdversaryCycle(dataRoot string) (*AdversaryCycleState, error) {
	path := AdversaryCyclePath(dataRoot)
	state := &AdversaryCycleState{
		SchemaVersion: 1,
		Targets:       map[string]AdversaryCycleTarget{},
		path:          path,
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return state, nil
		}
		return nil, err
	}
	if err := json.Unmarshal(raw, state); err != nil {
		return nil, fmt.Errorf("parse adversary cycle state: %w", err)
	}
	if state.Targets == nil {
		state.Targets = map[string]AdversaryCycleTarget{}
	}
	state.path = path
	return state, nil
}

// Peek returns the next least-selected package without changing state.
func (s *AdversaryCycleState) Peek(ids []string) string {
	eligible := normalizedTargetIDs(ids)
	if len(eligible) == 0 {
		return ""
	}
	minSelections := -1
	for _, id := range eligible {
		count := s.Targets[id].Selections
		if minSelections < 0 || count < minSelections {
			minSelections = count
		}
	}
	var tied []string
	for _, id := range eligible {
		if s.Targets[id].Selections == minSelections {
			tied = append(tied, id)
		}
	}
	if len(tied) == 1 || s.LastTarget == "" {
		return tied[0]
	}
	for _, id := range tied {
		if id > s.LastTarget {
			return id
		}
	}
	return tied[0]
}

// Select records and returns the next least-selected package.
func (s *AdversaryCycleState) Select(ids []string, runID string) (string, error) {
	id := s.Peek(ids)
	if id == "" {
		return "", fmt.Errorf("no adversaries available for round-robin training")
	}
	record := s.Targets[id]
	record.Selections++
	record.LastSelected = time.Now().UTC()
	record.LastRun = runID
	s.Targets[id] = record
	s.LastTarget = id
	if err := s.Save(); err != nil {
		return "", err
	}
	return id, nil
}

// Save persists the scheduler with private train-state permissions.
func (s *AdversaryCycleState) Save() error {
	if s == nil || s.path == "" {
		return fmt.Errorf("nil adversary cycle state")
	}
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return securefs.WriteFile(s.path, raw)
}

func normalizedTargetIDs(ids []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}
