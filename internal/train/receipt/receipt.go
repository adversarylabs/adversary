package receipt

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"time"

	"github.com/adversarylabs/adversary/internal/train/dataroot"
	"github.com/adversarylabs/adversary/internal/train/securefs"
)

// Receipt is the durable proof of a factory run.
type Receipt struct {
	SchemaVersion int                                `json:"schema_version"`
	RunID         string                             `json:"run_id"`
	RunClass      dataroot.ExecutionClass            `json:"run_class"`
	CaseIDs       []string                           `json:"case_ids,omitempty"`
	Stages        map[string]dataroot.ExecutionClass `json:"stages"`
	Reviewers     []ReviewerReceipt                  `json:"reviewers,omitempty"`
	Totals        Totals                             `json:"totals"`
	Timestamps    Timestamps                         `json:"timestamps"`
	FinalStatus   string                             `json:"final_status"` // success | partial | blocked | failed
	Notes         string                             `json:"notes,omitempty"`
}

type ReviewerReceipt struct {
	Identity       string                  `json:"identity"`
	Kind           string                  `json:"kind"`
	ExecutionClass dataroot.ExecutionClass `json:"execution_class"`
	ExitCode       int                     `json:"exit_code,omitempty"`
	CostUSD        float64                 `json:"cost_usd,omitempty"`
	LatencyMS      int64                   `json:"latency_ms,omitempty"`
	Artifact       string                  `json:"artifact,omitempty"`
}

type Totals struct {
	CostUSD float64 `json:"cost_usd"`
	WallMS  int64   `json:"wall_ms"`
}

type Timestamps struct {
	Started  time.Time `json:"started"`
	Finished time.Time `json:"finished"`
}

// New starts a receipt.
func New(runID string) *Receipt {
	return &Receipt{
		SchemaVersion: 2,
		RunID:         runID,
		Stages:        map[string]dataroot.ExecutionClass{},
		Timestamps:    Timestamps{Started: time.Now().UTC()},
		FinalStatus:   "running",
	}
}

// SetStage records a stage class and updates run-level class to the weakest.
func (r *Receipt) SetStage(name string, class dataroot.ExecutionClass) {
	r.Stages[name] = class
	r.RunClass = weakest(r.RunClass, class)
}

func weakest(a, b dataroot.ExecutionClass) dataroot.ExecutionClass {
	rank := func(c dataroot.ExecutionClass) int {
		switch c {
		case dataroot.ClassReal:
			return 5
		case dataroot.ClassReplayed:
			return 4
		case dataroot.ClassFixture:
			return 3
		case dataroot.ClassPartial:
			return 2
		case dataroot.ClassMock:
			return 1
		case "":
			return 6 // unset — treat as max so first set wins weakly
		default:
			return 0
		}
	}
	if a == "" {
		return b
	}
	if rank(b) < rank(a) {
		return b
	}
	return a
}

// Finish sets final status and timestamps.
func (r *Receipt) Finish(status string) {
	r.FinalStatus = status
	r.Timestamps.Finished = time.Now().UTC()
	if r.Timestamps.Started.IsZero() {
		r.Timestamps.Started = r.Timestamps.Finished
	}
	r.Totals.WallMS = r.Timestamps.Finished.Sub(r.Timestamps.Started).Milliseconds()
}

// Save writes receipt.json under runs/<id>/.
func Save(dataRoot string, r *Receipt) (string, error) {
	dir := filepath.Join(dataRoot, "runs", r.RunID)
	if err := securefs.MkdirAll(dir); err != nil {
		return "", err
	}
	path := filepath.Join(dir, "receipt.json")
	raw, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", err
	}
	if err := securefs.WriteFile(path, raw); err != nil {
		return "", err
	}
	return path, nil
}

// Verify checks internal consistency of a receipt.
func Verify(r *Receipt) error {
	if r.RunID == "" {
		return fmt.Errorf("missing run_id")
	}
	if r.FinalStatus == "success" {
		for stage, class := range r.Stages {
			if class == dataroot.ClassMock {
				return fmt.Errorf("success receipt cannot have mock stage %s", stage)
			}
		}
		if r.RunClass == dataroot.ClassMock {
			return fmt.Errorf("success receipt cannot be mock run_class")
		}
	}
	return nil
}
