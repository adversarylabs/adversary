package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/adversarylabs/adversary/internal/train/bundle"
	"github.com/adversarylabs/adversary/internal/train/dataroot"
	"github.com/adversarylabs/adversary/internal/train/securefs"
)

// localPackageLocks serializes runs against the same local package directory.
// Hunt/collect may run in parallel, but reading or patching a package while
// another goroutine is `adversary run`-ing it races (draft apply, remeasure,
// concurrent grade). OCI refs and non-dirs skip the lock.
var localPackageLocks sync.Map // abs path -> *sync.Mutex

// LockLocalPackage holds an exclusive lock for a local package directory.
// Use around copy/patch of a package source while another goroutine might
// `adversary run` the same path. Returns an unlock func (always non-nil; no-op
// when the ref is not a local directory).
func LockLocalPackage(adversaryRef string) (unlock func()) {
	return lockLocalPackage(adversaryRef)
}

// lockLocalPackage holds an exclusive lock for a local package directory.
// Returns an unlock func (always non-nil; no-op when lock is not needed).
func lockLocalPackage(adversaryRef string) (unlock func()) {
	unlock = func() {}
	if adversaryRef == "" {
		return unlock
	}
	// Bare catalog names (engineering-review) are not local paths.
	if !strings.Contains(adversaryRef, string(filepath.Separator)) && !filepath.IsAbs(adversaryRef) {
		// Still allow "./foo" and "foo-adversary" relative dirs if they exist.
		if st, err := os.Stat(adversaryRef); err != nil || !st.IsDir() {
			return unlock
		}
	}
	abs, err := filepath.Abs(adversaryRef)
	if err != nil {
		return unlock
	}
	st, err := os.Stat(abs)
	if err != nil || !st.IsDir() {
		return unlock
	}
	v, _ := localPackageLocks.LoadOrStore(abs, &sync.Mutex{})
	mu := v.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}

// Result of running a reviewer.
type Result struct {
	ReviewerID     string
	Kind           string // baseline | adversary
	ExecutionClass dataroot.ExecutionClass
	RawJSON        []byte
	ExitCode       int
	LatencyMS      int64
	ArtifactPath   string
	Blocked        *dataroot.BlockedResult
}

// RunBaseline produces a generic baseline review from the reviewer projection only.
// In fixture mode, loads fixture path. Live mode uses a simple heuristic baseline
// (no external model required for first slice honesty) labeled as fixture/heuristic
// unless FACTORY_BASELINE_MODEL is set and a provider is available.
func RunBaseline(proj *bundle.Projection, outDir string, fixturePath string) (*Result, error) {
	if err := securefs.MkdirAll(outDir); err != nil {
		return nil, err
	}
	if err := bundle.AssertReviewerIsolation(proj); err != nil {
		return nil, fmt.Errorf("baseline refused non-isolated projection: %w", err)
	}
	start := time.Now()
	if fixturePath != "" {
		raw, err := os.ReadFile(fixturePath)
		if err != nil {
			return nil, err
		}
		path := filepath.Join(outDir, "baseline.raw.json")
		_ = securefs.WriteFile(path, raw)
		return &Result{
			ReviewerID:     "generic-baseline",
			Kind:           "baseline",
			ExecutionClass: dataroot.ClassFixture,
			RawJSON:        raw,
			ExitCode:       0,
			LatencyMS:      time.Since(start).Milliseconds(),
			ArtifactPath:   path,
		}, nil
	}
	// Heuristic baseline from projection checkout/diff only (no labels).
	raw, err := heuristicBaseline(proj)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(outDir, "baseline.raw.json")
	if err := securefs.WriteFile(path, raw); err != nil {
		return nil, err
	}
	return &Result{
		ReviewerID:     "generic-baseline",
		Kind:           "baseline",
		ExecutionClass: dataroot.ClassFixture, // honest: not a live model call
		RawJSON:        raw,
		ExitCode:       0,
		LatencyMS:      time.Since(start).Milliseconds(),
		ArtifactPath:   path,
	}, nil
}

func heuristicBaseline(proj *bundle.Projection) ([]byte, error) {
	// Produce a minimal structured baseline without seeing labels.
	type finding struct {
		ID, File, Severity, Category, Claim, Evidence, Fix string
		Line                                               int
	}
	out := struct {
		Summary  string    `json:"summary"`
		Findings []finding `json:"findings"`
	}{
		Summary: "Generic baseline heuristic review of prepared change context.",
		Findings: []finding{
			{
				ID:       "baseline-1",
				Severity: "medium",
				Category: "correctness",
				Claim:    "Verify error handling and resource lifecycle on the changed code paths.",
				Evidence: "Derived from diff metadata only; full model baseline not configured.",
				Fix:      "Ensure errors are checked and resources are released on all paths.",
			},
		},
	}
	if sec, ok := proj.Sections[bundle.SectionCheckout]; ok && len(sec.Payload) > 0 {
		var checkout map[string]string
		_ = json.Unmarshal(sec.Payload, &checkout)
		if checkout["head_sha"] != "" {
			out.Findings[0].Evidence = "Reviewed head " + checkout["head_sha"][:min(12, len(checkout["head_sha"]))] + "; confirm invariants around concurrency and cancellation."
		}
	}
	return json.MarshalIndent(out, "", "  ")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// RunEngineeringReview invokes the real adversary CLI when available.
func RunEngineeringReview(proj *bundle.Projection, outDir, repoPath, baseSHA, headSHA, adversaryRef string, fixturePath string) (*Result, error) {
	return RunEngineeringReviewContext(context.Background(), proj, outDir, repoPath, baseSHA, headSHA, adversaryRef, fixturePath)
}

// RunEngineeringReviewContext is RunEngineeringReview with cancelable context (Ctrl+C).
// Local package directories are locked for the duration of the run so concurrent
// train workers never execute the same package while another goroutine patches it.
func RunEngineeringReviewContext(ctx context.Context, proj *bundle.Projection, outDir, repoPath, baseSHA, headSHA, adversaryRef string, fixturePath string) (*Result, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("adversary run interrupted: %w", err)
	}
	// Prefer absolute local path early so the lock keys match across callers.
	if adversaryRef != "" {
		if abs, err := filepath.Abs(adversaryRef); err == nil {
			if st, err := os.Stat(abs); err == nil && st.IsDir() {
				adversaryRef = abs
			}
		}
	}
	unlock := lockLocalPackage(adversaryRef)
	defer unlock()

	if err := securefs.MkdirAll(outDir); err != nil {
		return nil, err
	}
	if err := bundle.AssertReviewerIsolation(proj); err != nil {
		return nil, fmt.Errorf("adversary refused non-isolated projection: %w", err)
	}
	start := time.Now()
	if fixturePath != "" {
		raw, err := os.ReadFile(fixturePath)
		if err != nil {
			return nil, err
		}
		path := filepath.Join(outDir, "engineering-review.raw.json")
		_ = securefs.WriteFile(path, raw)
		return &Result{
			ReviewerID:     "engineering-review",
			Kind:           "adversary",
			ExecutionClass: dataroot.ClassFixture,
			RawJSON:        raw,
			ExitCode:       0,
			LatencyMS:      time.Since(start).Milliseconds(),
			ArtifactPath:   path,
		}, nil
	}

	adv, err := exec.LookPath("adversary")
	if err != nil {
		return &Result{
			ReviewerID:     "engineering-review",
			Kind:           "adversary",
			ExecutionClass: dataroot.ClassPartial,
			Blocked: &dataroot.BlockedResult{
				Dependency:     "adversary-cli",
				Operation:      "run-engineering-review",
				Classification: "not-installed",
				SanitizedError: "adversary not in PATH",
				StagesNotRun:   []string{"review"},
				RetrySafe:      true,
				NextAction:     "install adversary CLI",
			},
		}, nil
	}
	if repoPath == "" || baseSHA == "" || headSHA == "" {
		return &Result{
			ReviewerID:     "engineering-review",
			Kind:           "adversary",
			ExecutionClass: dataroot.ClassPartial,
			Blocked: &dataroot.BlockedResult{
				Dependency:     "git-checkout",
				Operation:      "run-engineering-review",
				Classification: "missing-source",
				SanitizedError: "repo path and base/head SHAs required for real adversary run",
				StagesNotRun:   []string{"review"},
				RetrySafe:      true,
				NextAction:     "prepare a git checkout with exact base and reviewed head SHAs",
			},
		}, nil
	}
	if adversaryRef == "" {
		adversaryRef = "engineering-review"
	}
	// Prefer absolute local path so we don't try OCI pull for a bare name.
	if abs, err := filepath.Abs(adversaryRef); err == nil {
		if st, err := os.Stat(abs); err == nil && st.IsDir() {
			adversaryRef = abs
		}
	}
	outFile := filepath.Join(outDir, "engineering-review.raw.json")
	provider := os.Getenv("ADVERSARY_MODEL_PROVIDER")
	if provider == "" {
		provider = defaultModelProvider()
	}
	model := os.Getenv("ADVERSARY_MODEL")
	if model == "" {
		model = defaultModel(provider)
	}
	args := []string{
		"run", adversaryRef,
		"--path", repoPath,
		"--base", baseSHA,
		"--head", headSHA,
		"--format", "json",
		"--output-file", outFile,
		"--force",
		"--model-provider", provider,
		"--model", model,
	}
	cmd := exec.CommandContext(ctx, adv, args...)
	// Ensure child sees consistent env even if flags are ignored by older CLIs.
	cmd.Env = append(os.Environ(),
		"ADVERSARY_MODEL_PROVIDER="+provider,
		"ADVERSARY_MODEL="+model,
	)
	combined, err := cmd.CombinedOutput()
	latency := time.Since(start).Milliseconds()
	if ctx.Err() != nil {
		return nil, fmt.Errorf("adversary run interrupted: %w", ctx.Err())
	}
	exitCode := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			exitCode = ee.ExitCode()
		} else {
			exitCode = 1
		}
	}
	raw, readErr := os.ReadFile(outFile)
	if readErr != nil || len(raw) == 0 {
		raw = combined
	}
	// Output file may contain human progress text on failure; only accept real JSON.
	if !looksLikeJSON(raw) {
		msg := strings.TrimSpace(string(combined))
		if msg == "" {
			msg = strings.TrimSpace(string(raw))
		}
		return &Result{
			ReviewerID:     "engineering-review",
			Kind:           "adversary",
			ExecutionClass: dataroot.ClassPartial,
			ExitCode:       exitCode,
			LatencyMS:      latency,
			ArtifactPath:   outFile,
			Blocked: &dataroot.BlockedResult{
				Dependency:     "adversary-run",
				Operation:      "run-engineering-review",
				Classification: classifyAdversaryError(msg),
				SanitizedError: truncate(msg, 500),
				StagesNotRun:   []string{"judge"},
				RetrySafe:      true,
				NextAction:     nextActionForAdversaryError(msg),
			},
		}, nil
	}
	_ = securefs.WriteFile(outFile, raw)
	class := dataroot.ClassReal
	if exitCode != 0 {
		class = dataroot.ClassPartial
	}
	return &Result{
		ReviewerID:     "engineering-review",
		Kind:           "adversary",
		ExecutionClass: class,
		RawJSON:        raw,
		ExitCode:       exitCode,
		LatencyMS:      latency,
		ArtifactPath:   outFile,
	}, nil
}

func looksLikeJSON(raw []byte) bool {
	s := strings.TrimSpace(string(raw))
	return strings.HasPrefix(s, "{") || strings.HasPrefix(s, "[")
}

func defaultModelProvider() string {
	// Prefer provider whose key is present; openai is a common default.
	if os.Getenv("OPENAI_API_KEY") != "" {
		return "openai"
	}
	if os.Getenv("ANTHROPIC_API_KEY") != "" {
		return "anthropic"
	}
	if os.Getenv("FIREWORKS_API_KEY") != "" {
		return "fireworks"
	}
	return "openai"
}

func defaultModel(provider string) string {
	switch provider {
	case "anthropic":
		return "claude-sonnet-4-20250514"
	case "fireworks":
		return "accounts/fireworks/models/llama-v3p1-70b-instruct"
	default:
		return "gpt-4o-mini"
	}
}

func classifyAdversaryError(msg string) string {
	l := strings.ToLower(msg)
	switch {
	case strings.Contains(l, "api key") || strings.Contains(l, "model_provider") || strings.Contains(l, "model provider"):
		return "missing-secret"
	case strings.Contains(l, "not installed") || strings.Contains(l, "oci reference"):
		return "not-installed"
	case strings.Contains(l, "merge-base") || strings.Contains(l, "unable to read") || strings.Contains(l, "git diff"):
		return "missing-source"
	default:
		return "failed"
	}
}

func nextActionForAdversaryError(msg string) string {
	l := strings.ToLower(msg)
	switch {
	case strings.Contains(l, "model_provider") || strings.Contains(l, "model provider"):
		return "set ADVERSARY_MODEL_PROVIDER=openai (or anthropic/fireworks) and ensure the matching API key is set"
	case strings.Contains(l, "api key"):
		return "set the model provider API key (e.g. OPENAI_API_KEY) for engineering-review"
	case strings.Contains(l, "not installed") || strings.Contains(l, "oci"):
		return "pass --source /path/to/engineering-review-adversary (local checkout) or adversary pull engineering-review"
	case strings.Contains(l, "git") || strings.Contains(l, "merge-base"):
		return "factory checkout failed to prepare base/head; re-run or pass a different --pr"
	default:
		return "run the same adversary command manually with --verbose and fix the reported error"
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
