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
	ChangeRequest            ChangeRequest
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
	reviewContext, err := a.Changes.ResolveChanges(ctx, opts.ChangeRequest)
	if err != nil {
		return AutoResult{}, err
	}
	repositoryRoot := reviewContext.RepositoryRoot
	candidates, err := a.availableCandidates(opts.Includes)
	if err != nil {
		return AutoResult{}, err
	}
	needsRepositoryFiles := false
	for _, candidate := range candidates {
		if len(candidate.Manifest.Detection.RepositoryFiles) > 0 {
			needsRepositoryFiles = true
			break
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
	// The portable context describes the executor-visible repository path. The
	// host path remains an execution parameter and is never exposed as detector
	// protocol data.
	reviewContext.RepositoryRoot = "/workspace"

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
	for _, selection := range selections {
		if !selection.Selected {
			continue
		}
		ref := selection.Candidate.Reference
		if selection.Candidate.Digest != "" {
			ref = selection.Candidate.Digest
		}
		err := a.Runner.Run(ctx, RunOptions{AdversaryRef: ref, ReferenceIdentity: selection.Candidate.Reference, RepoPath: repositoryRoot, ReviewContext: &reviewContext, Force: true, Format: opts.Format, IncludeSuppressed: opts.IncludeSuppressed, AllowUnsafeHostExecution: opts.AllowUnsafeHostExecution, RunTimeout: opts.RunTimeout})
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
	candidates := make([]DetectionCandidate, 0, len(entries)+len(includes))
	byIdentity := make(map[string]int, len(entries))
	for _, entry := range entries {
		resolved, err := ResolveReferenceWithRuntime(entry.Digest, *a.Resolver, a.Runner.runtimeFiles())
		if err != nil || resolved.Manifest == nil {
			continue
		}
		candidate := DetectionCandidate{Name: resolved.Manifest.Name, Reference: entry.CanonicalReference, Digest: entry.Digest, Manifest: *resolved.Manifest}
		key := candidateIdentityKey(candidate)
		if index, exists := byIdentity[key]; exists {
			if newerManifestVersion(candidate.Manifest.Version, candidates[index].Manifest.Version) {
				candidates[index] = candidate
			}
			continue
		}
		byIdentity[key] = len(candidates)
		candidates = append(candidates, candidate)
	}
	selectedIdentity := make(map[string]struct{}, len(candidates))
	for _, candidate := range candidates {
		selectedIdentity[candidateIdentityKey(candidate)+"@"+candidate.Digest] = struct{}{}
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
			candidate := DetectionCandidate{Name: resolved.Manifest.Name, Reference: include, Digest: resolved.Digest, Manifest: *resolved.Manifest}
			key := candidateIdentityKey(candidate) + "@" + resolved.Digest
			if _, seen := selectedIdentity[key]; seen {
				continue
			}
			selectedIdentity[key] = struct{}{}
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
		return strings.ToLower(parsed.Registry + "/" + parsed.Repository)
	}
	return strings.ToLower(candidate.Reference)
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
