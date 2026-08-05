package state

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/adversarylabs/adversary/internal/train/securefs"
)

// PROutcome records what happened when we last looked at a PR.
type PROutcome string

const (
	OutcomeAttempted PROutcome = "attempted"
	OutcomeGraded    PROutcome = "graded"      // had in-scope gold and ran review path
	OutcomeNoInScope PROutcome = "no_in_scope" // collected but nothing in mission scope
	OutcomeNoCases   PROutcome = "no_cases"    // no reconstructable review rounds
	OutcomeBlocked   PROutcome = "blocked"     // collect/review blocked
	OutcomeExcluded  PROutcome = "excluded"    // SHA unrecoverable etc.
	OutcomePinned    PROutcome = "pinned"      // user forced --pr
)

// PRRecord is per-PR discovery memory.
type PRRecord struct {
	Number      int       `json:"number"`
	Title       string    `json:"title,omitempty"`
	URL         string    `json:"url,omitempty"`
	FirstSeen   time.Time `json:"first_seen"`
	LastAttempt time.Time `json:"last_attempt"`
	Attempts    int       `json:"attempts"`
	Outcome     PROutcome `json:"outcome"`
	Note        string    `json:"note,omitempty"`
}

// DiscoveryStore remembers which PRs we already tried for a repo.
// Methods are safe for concurrent use (parallel hunt workers).
type DiscoveryStore struct {
	mu            sync.Mutex
	SchemaVersion int                 `json:"schema_version"`
	Owner         string              `json:"owner"`
	Repo          string              `json:"repo"`
	PRs           map[string]PRRecord `json:"prs"`
	path          string              `json:"-"`
}

// PathFor returns the state file path under the data root.
func PathFor(dataRoot, owner, repo string) string {
	return filepath.Join(dataRoot, "state", "discovery", owner+"__"+repo+".json")
}

// LoadDiscovery loads or creates an empty store for owner/repo.
func LoadDiscovery(dataRoot, owner, repo string) (*DiscoveryStore, error) {
	path := PathFor(dataRoot, owner, repo)
	s := &DiscoveryStore{
		SchemaVersion: 1,
		Owner:         owner,
		Repo:          repo,
		PRs:           map[string]PRRecord{},
		path:          path,
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, err
	}
	if err := json.Unmarshal(raw, s); err != nil {
		return nil, err
	}
	if s.PRs == nil {
		s.PRs = map[string]PRRecord{}
	}
	s.path = path
	s.Owner = owner
	s.Repo = repo
	return s, nil
}

// Seen returns true if we should skip this PR in normal discovery.
func (s *DiscoveryStore) Seen(pr int) bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.PRs[strconv.Itoa(pr)]
	return ok
}

// SeenSet returns all PR numbers already in state.
func (s *DiscoveryStore) SeenSet() map[int]bool {
	out := map[int]bool{}
	if s == nil {
		return out
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for k := range s.PRs {
		n, err := strconv.Atoi(k)
		if err == nil {
			out[n] = true
		}
	}
	return out
}

// Record upserts a PR attempt outcome.
func (s *DiscoveryStore) Record(pr int, title, url string, outcome PROutcome, note string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.PRs == nil {
		s.PRs = map[string]PRRecord{}
	}
	key := strconv.Itoa(pr)
	now := time.Now().UTC()
	rec, ok := s.PRs[key]
	if !ok {
		rec = PRRecord{Number: pr, FirstSeen: now}
	}
	rec.Title = title
	rec.URL = url
	rec.LastAttempt = now
	rec.Attempts++
	rec.Outcome = outcome
	rec.Note = note
	s.PRs[key] = rec
}

// Save writes the store to disk.
func (s *DiscoveryStore) Save() error {
	if s == nil {
		return fmt.Errorf("nil discovery store")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.path == "" {
		return fmt.Errorf("nil discovery store")
	}
	// Marshal only JSON-serializable fields (avoid copying the mutex).
	snap := struct {
		SchemaVersion int                 `json:"schema_version"`
		Owner         string              `json:"owner"`
		Repo          string              `json:"repo"`
		PRs           map[string]PRRecord `json:"prs"`
	}{
		SchemaVersion: s.SchemaVersion,
		Owner:         s.Owner,
		Repo:          s.Repo,
		PRs:           s.PRs,
	}
	raw, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	return securefs.WriteFile(s.path, raw)
}

// Summary is a short human line about memory size.
func (s *DiscoveryStore) Summary() string {
	if s == nil {
		return "no discovery state"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return fmt.Sprintf("%d previously seen PR(s) in %s", len(s.PRs), s.path)
}

// ListNumbers returns sorted PR numbers in state (for tests/debug).
func (s *DiscoveryStore) ListNumbers() []int {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []int
	for k := range s.PRs {
		n, err := strconv.Atoi(k)
		if err == nil {
			out = append(out, n)
		}
	}
	sort.Ints(out)
	return out
}
