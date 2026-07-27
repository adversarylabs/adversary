package adversary

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	semver "github.com/Masterminds/semver/v3"
	"github.com/adversarylabs/adversary/pkg/detection"
	"github.com/adversarylabs/adversary/pkg/oci"
)

type AutoOptions struct {
	// ReviewContext, when set, is the resolved change used for detection.
	// When nil, ChangeRequest is resolved through Changes.
	ReviewContext *detection.Context
	ChangeRequest ChangeRequest
	// AllFiles runs selected adversaries against the entire target (whole-repo
	// scan) instead of injecting the change context as the review focus.
	AllFiles                 bool
	MinimumConfidence        detection.Confidence
	Includes                 []string
	Excludes                 []string
	All                      bool
	DryRun                   bool
	AllowUnsafeHostExecution bool
	RunTimeout               time.Duration
	DetectionTimeout         time.Duration
	Format                   string
	IncludeSuppressed        bool
	ReportSelections         func(AutoResult) error
	// ReportRunStart is called before each selected adversary runs (1-based index
	// among selected adversaries). Used for terminal progress when results go elsewhere.
	ReportRunStart func(name string, index, total int) error
	// ReportRunFinish is called after each selected adversary finishes. err is nil
	// on clean success, FindingsError when findings were reported, or a hard error.
	ReportRunFinish func(name string, index, total int, err error) error
}

type AutoResult struct {
	Context    detection.Context
	Selections []DetectionSelection
	Findings   int
	RunErrors  []error
}

type AutoRunner struct {
	Runner   Runner
	Changes  ChangeResolver
	Resolver *Resolver
}

func (a AutoRunner) Auto(ctx context.Context, opts AutoOptions) (AutoResult, error) {
	if a.Changes == nil {
		return AutoResult{}, fmt.Errorf("change resolver dependency is required")
	}
	if a.Resolver == nil {
		return AutoResult{}, fmt.Errorf("adversary resolver dependency is required")
	}
	minimum := opts.MinimumConfidence
	if minimum == "" {
		minimum = detection.ConfidenceMedium
	}
	var reviewContext detection.Context
	var err error
	if opts.ReviewContext != nil {
		reviewContext = *opts.ReviewContext
	} else {
		reviewContext, err = a.Changes.ResolveChanges(ctx, opts.ChangeRequest)
		if err != nil {
			return AutoResult{}, err
		}
	}
	repositoryRoot := reviewContext.RepositoryRoot
	if repositoryRoot == "" {
		repositoryRoot = opts.ChangeRequest.RepoPath
	}
	candidates, err := a.availableCandidates(opts.Includes)
	if err != nil {
		return AutoResult{}, err
	}
	needsRepositoryFiles := false
	if len(reviewContext.RepositoryFiles) == 0 {
		for _, candidate := range candidates {
			if len(candidate.Manifest.Detection.RepositoryFiles) > 0 {
				needsRepositoryFiles = true
				break
			}
		}
	}
	if needsRepositoryFiles {
		files, ok := a.Changes.(RepositoryFileResolver)
		if !ok {
			return AutoResult{}, fmt.Errorf("repository file resolver dependency is required by declarative detection")
		}
		reviewContext.RepositoryFiles, err = files.RepositoryFiles(ctx, repositoryRoot)
		if err != nil {
			return AutoResult{}, err
		}
	}
	selections := make([]DetectionSelection, 0, len(candidates))
	for _, candidate := range candidates {
		result := EvaluateDeclarativeDetection(candidate.Manifest, reviewContext)
		var detectorErr error
		if !opts.All && candidate.Manifest.Detection.Entrypoint != "" {
			ref := candidate.Reference
			if candidate.Digest != "" {
				ref = candidate.Digest
			}
			programResult, err := a.Runner.Detect(ctx, DetectOptions{AdversaryRef: ref, ReferenceIdentity: candidate.Reference, RepoPath: repositoryRoot, ReviewContext: reviewContext, AllowUnsafeHostExecution: opts.AllowUnsafeHostExecution, Timeout: opts.DetectionTimeout})
			if err == nil {
				result = programResult
			} else {
				detectorErr = err
				var policyErr *DetectorPolicyError
				if !errors.As(err, &policyErr) || !policyErr.DeclarativeFallback {
					result = detection.Result{SchemaVersion: detection.SchemaVersion, Applicable: false, Confidence: detection.ConfidenceLow, Reasons: []string{"programmatic detector failed"}}
				}
			}
		}
		selections = append(selections, DetectionSelection{Candidate: candidate, Result: result, Error: detectorErr})
	}
	selections, err = FilterAndOrderSelections(selections, minimum, opts.Includes, opts.Excludes, opts.All)
	if err != nil {
		return AutoResult{}, err
	}
	result := AutoResult{Context: reviewContext, Selections: selections}
	if opts.ReportSelections != nil {
		if err := opts.ReportSelections(result); err != nil {
			return result, err
		}
	}
	if opts.DryRun {
		return result, nil
	}
	selectedTotal := 0
	for _, selection := range selections {
		if selection.Selected {
			selectedTotal++
		}
	}
	runIndex := 0
	for _, selection := range selections {
		if !selection.Selected {
			continue
		}
		runIndex++
		if opts.ReportRunStart != nil {
			if err := opts.ReportRunStart(selection.Candidate.Name, runIndex, selectedTotal); err != nil {
				return result, err
			}
		}
		ref := selection.Candidate.Reference
		if selection.Candidate.Digest != "" {
			ref = selection.Candidate.Digest
		}
		runOpts := RunOptions{
			AdversaryRef:             ref,
			ReferenceIdentity:        selection.Candidate.Reference,
			RepoPath:                 repositoryRoot,
			Force:                    true,
			Format:                   opts.Format,
			IncludeSuppressed:        opts.IncludeSuppressed,
			AllowUnsafeHostExecution: opts.AllowUnsafeHostExecution,
			RunTimeout:               opts.RunTimeout,
			AllFiles:                 opts.AllFiles,
			// Multi automatic selection keeps a clean progress stream; use
			// --verbose on explicit single-ref run for identity banners.
			Verbose: false,
		}
		if !opts.AllFiles {
			ctxCopy := reviewContext
			runOpts.ReviewContext = &ctxCopy
		}
		err := a.Runner.Run(ctx, runOpts)
		if opts.ReportRunFinish != nil {
			if finishErr := opts.ReportRunFinish(selection.Candidate.Name, runIndex, selectedTotal, err); finishErr != nil {
				return result, finishErr
			}
		}
		if err == nil {
			continue
		}
		var findings *FindingsError
		if errors.As(err, &findings) {
			result.Findings += findings.Count
			continue
		}
		result.RunErrors = append(result.RunErrors, fmt.Errorf("%s: %w", selection.Candidate.Name, err))
	}
	if len(result.RunErrors) > 0 {
		return result, &AutoExecutionError{Errors: result.RunErrors}
	}
	if result.Findings > 0 {
		return result, &FindingsError{Count: result.Findings}
	}
	return result, nil
}

func (a AutoRunner) availableCandidates(includes []string) ([]DetectionCandidate, error) {
	entries, err := a.Resolver.Repository.ReferenceEntries()
	if err != nil {
		return nil, err
	}
	// Collapse aliases that point at the same package bytes first. Users commonly
	// retain both library/* and adversarylabs/* refs for one digest after the
	// default namespace migration; automatic selection must not run that package twice.
	byDigest := make(map[string]DetectionCandidate, len(entries))
	for _, entry := range entries {
		resolved, err := ResolveReferenceWithRuntime(entry.Digest, *a.Resolver, a.Runner.runtimeFiles())
		if err != nil || resolved.Manifest == nil {
			continue
		}
		candidate := DetectionCandidate{Name: resolved.Manifest.Name, Reference: entry.CanonicalReference, Digest: entry.Digest, Manifest: *resolved.Manifest}
		if existing, ok := byDigest[candidate.Digest]; ok {
			if preferCandidateReference(candidate, existing) {
				byDigest[candidate.Digest] = candidate
			}
			continue
		}
		byDigest[candidate.Digest] = candidate
	}
	// Then keep one candidate per registry/repository identity, preferring the
	// highest package version. Distinct publishers (different repositories) stay separate.
	candidates := make([]DetectionCandidate, 0, len(byDigest)+len(includes))
	byIdentity := make(map[string]int, len(byDigest))
	for _, candidate := range byDigest {
		key := candidateIdentityKey(candidate)
		if index, exists := byIdentity[key]; exists {
			if preferCandidateVersion(candidate, candidates[index]) {
				candidates[index] = candidate
			}
			continue
		}
		byIdentity[key] = len(candidates)
		candidates = append(candidates, candidate)
	}
	selectedDigests := make(map[string]struct{}, len(candidates))
	for _, candidate := range candidates {
		if candidate.Digest != "" {
			selectedDigests[candidate.Digest] = struct{}{}
		}
	}
	for _, include := range includes {
		if candidateSliceMatches(candidates, include) {
			continue
		}
		resolved, err := ResolveReferenceWithRuntime(include, *a.Resolver, a.Runner.runtimeFiles())
		if err != nil || !resolved.LocalDir || resolved.Manifest == nil {
			if err == nil {
				err = fmt.Errorf("not installed locally")
			}
			return nil, fmt.Errorf("forced adversary %q is unavailable: %w", include, err)
		}
		if resolved.Digest != "" {
			if _, seen := selectedDigests[resolved.Digest]; seen {
				continue
			}
			selectedDigests[resolved.Digest] = struct{}{}
		}
		candidates = append(candidates, DetectionCandidate{Name: resolved.Manifest.Name, Reference: include, Digest: resolved.Digest, Manifest: *resolved.Manifest})
	}
	sort.Slice(candidates, func(i, j int) bool {
		return strings.ToLower(candidates[i].Name) < strings.ToLower(candidates[j].Name)
	})
	return candidates, nil
}

func candidateIdentityKey(candidate DetectionCandidate) string {
	if parsed, err := oci.ParseReference(candidate.Reference); err == nil {
		repo := parsed.Repository
		// Treat the historical default namespace as the official publisher path so
		// library/go-cli and adversarylabs/go-cli collapse to one automatic selection.
		if strings.HasPrefix(strings.ToLower(repo), "library/") {
			repo = "adversarylabs/" + repo[len("library/"):]
		}
		// Early packages were published as <name>-adversary; normalize to the
		// current short repository name so renames do not double-run.
		parts := strings.Split(repo, "/")
		last := parts[len(parts)-1]
		if trimmed, ok := strings.CutSuffix(last, "-adversary"); ok && trimmed != "" {
			parts[len(parts)-1] = trimmed
			repo = strings.Join(parts, "/")
		}
		return strings.ToLower(parsed.Registry + "/" + repo)
	}
	return strings.ToLower(candidate.Reference)
}

// preferCandidateReference chooses which alias to keep when multiple references
// resolve to the same package digest. Prefer the modern adversarylabs namespace
// over the legacy library default, then a concrete version tag over :latest.
func preferCandidateReference(candidate, current DetectionCandidate) bool {
	candScore := referencePreferenceScore(candidate.Reference)
	currScore := referencePreferenceScore(current.Reference)
	if candScore != currScore {
		return candScore > currScore
	}
	if candidate.Manifest.Version != current.Manifest.Version {
		return newerManifestVersion(candidate.Manifest.Version, current.Manifest.Version)
	}
	return candidate.Reference < current.Reference
}

func preferCandidateVersion(candidate, current DetectionCandidate) bool {
	if candidate.Manifest.Version != current.Manifest.Version {
		return newerManifestVersion(candidate.Manifest.Version, current.Manifest.Version)
	}
	return preferCandidateReference(candidate, current)
}

func referencePreferenceScore(ref string) int {
	parsed, err := oci.ParseReference(ref)
	if err != nil {
		return 0
	}
	score := 0
	parts := strings.Split(parsed.Repository, "/")
	if len(parts) > 0 {
		switch strings.ToLower(parts[0]) {
		case "adversarylabs":
			score += 100
		case "library":
			// legacy default namespace; lose to adversarylabs
		default:
			score += 50
		}
	}
	tag := strings.TrimSpace(parsed.Tag)
	switch {
	case tag == "" || strings.EqualFold(tag, "latest"):
		// mutable tags are less specific than a pinned version
	default:
		score += 10
		if _, err := semver.NewVersion(tag); err == nil {
			score += 5
		}
	}
	return score
}

func newerManifestVersion(candidate, current string) bool {
	left, leftErr := semver.NewVersion(candidate)
	right, rightErr := semver.NewVersion(current)
	if leftErr == nil && rightErr == nil {
		return left.GreaterThan(right)
	}
	return candidate > current
}

func candidateSliceMatches(candidates []DetectionCandidate, value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	for _, candidate := range candidates {
		for _, name := range candidateNames(candidate) {
			if value == name {
				return true
			}
		}
	}
	return false
}

type AutoExecutionError struct{ Errors []error }

func (e *AutoExecutionError) Error() string {
	parts := make([]string, 0, len(e.Errors))
	for _, err := range e.Errors {
		parts = append(parts, err.Error())
	}
	return fmt.Sprintf("%d selected adversary execution(s) failed: %s", len(e.Errors), strings.Join(parts, "; "))
}

func (e *AutoExecutionError) Unwrap() []error { return e.Errors }
