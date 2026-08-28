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
	"github.com/adversarylabs/adversary/pkg/review"
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
	RepoIndexMode            string
	ReportSelections         func(AutoResult) error
	// ReportRunStart is called before each selected adversary runs (1-based index
	// among selected adversaries). Used for terminal progress when results go elsewhere.
	ReportRunStart func(name string, index, total int) error
	// ReportRunFinish is called after each selected adversary finishes. err is nil
	// on clean success, FindingsError when findings were reported, or a hard error.
	ReportRunFinish func(name string, index, total int, err error) error
	// OnEnvelope captures each successful decode for post-run projection.
	// name is the selected adversary display name.
	OnEnvelope func(name string, env review.RunEnvelope)
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
			RepoIndexMode:            opts.RepoIndexMode,
			// Multi automatic selection keeps a clean progress stream; use
			// --verbose on explicit single-ref run for identity banners.
			Verbose: false,
		}
		if opts.OnEnvelope != nil {
			name := selection.Candidate.Name
			runOpts.OnEnvelope = func(env review.RunEnvelope) { opts.OnEnvelope(name, env) }
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
		// Team-owned adversarylabs/* source packages are explicit-only. Promoted
		// library/* packages are the automatic catalog candidates.
		if isRetiredAutoReference(entry.CanonicalReference, resolved.Manifest.Name) {
			continue
		}
		candidate := DetectionCandidate{Name: catalogCandidateName(entry.CanonicalReference, resolved.Manifest.Name), Reference: entry.CanonicalReference, Digest: entry.Digest, Manifest: *resolved.Manifest}
		if existing, ok := byDigest[candidate.Digest]; ok {
			if preferCandidateReference(candidate, existing) {
				byDigest[candidate.Digest] = candidate
			}
			continue
		}
		byDigest[candidate.Digest] = candidate
	}
	// Then keep one candidate per package family on the same registry class,
	// preferring domain/name, official host, and highest version. Distinct
	// third-party publishers stay separate. Flat renames (go-cli ↔ go/cli,
	// dockerfile ↔ container/dockerfile) collapse here.
	candidates := make([]DetectionCandidate, 0, len(byDigest)+len(includes))
	for _, candidate := range byDigest {
		merged := false
		for i := range candidates {
			if !sameAutoIdentity(candidates[i], candidate) {
				continue
			}
			if preferCandidateVersion(candidate, candidates[i]) {
				candidates[i] = candidate
			}
			merged = true
			break
		}
		if !merged {
			candidates = append(candidates, candidate)
		}
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

// officialRegistryHost is the free-catalog registry used for retired-path filtering.
const officialRegistryHost = "registry.adversarylabs.ai"

// sameAutoIdentity reports whether two candidates should only run once.
// Official/local catalog packages collapse by package family (flat ↔ domain
// renames). Third-party publishers only collapse within the same publisher.
func sameAutoIdentity(a, b DetectionCandidate) bool {
	fa := packageFamilyKey(a.Name)
	fb := packageFamilyKey(b.Name)
	if fa == "" {
		fa = packageFamilyKey(a.Reference)
	}
	if fb == "" {
		fb = packageFamilyKey(b.Reference)
	}
	if !packageFamiliesMatch(fa, fb) {
		return false
	}
	pa, errA := oci.ParseReference(a.Reference)
	pb, errB := oci.ParseReference(b.Reference)
	if errA != nil || errB != nil {
		return true
	}
	ha, hb := strings.ToLower(pa.Registry), strings.ToLower(pb.Registry)
	// Treat official free catalog and local dev registry as one selection pool
	// so a signed prod go/cli wins over an unsigned localhost go-cli.
	aOfficial := ha == officialRegistryHost || isLocalDevRegistry(ha)
	bOfficial := hb == officialRegistryHost || isLocalDevRegistry(hb)
	if aOfficial && bOfficial {
		return true
	}
	if aOfficial != bOfficial {
		return true // still same family; preference score picks official
	}
	// Third-party: same registry + publisher only.
	pubA, pubB := "", ""
	if parts := strings.Split(pa.Repository, "/"); len(parts) > 0 {
		pubA = strings.ToLower(parts[0])
	}
	if parts := strings.Split(pb.Repository, "/"); len(parts) > 0 {
		pubB = strings.ToLower(parts[0])
	}
	if pubA == "library" {
		pubA = "adversarylabs"
	}
	if pubB == "library" {
		pubB = "adversarylabs"
	}
	return ha == hb && pubA == pubB
}

// packageFamilyKey normalizes catalog ids so flat renames share an identity:
// go/cli and go-cli → go-cli; container/dockerfile and dockerfile share a family
// via suffix matching in packageFamiliesMatch.
func packageFamilyKey(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		return ""
	}
	// Strip a registry host only when the value looks like host/repo (not a
	// bare domain/name catalog id such as go/cli — oci.ParseReference would
	// treat "go" as the host).
	if strings.Contains(n, ".") || strings.Contains(n, "://") ||
		(strings.Count(n, ":") == 1 && !strings.Contains(n, "/")) ||
		strings.HasPrefix(n, "localhost/") || strings.HasPrefix(n, "localhost:") {
		if parsed, err := oci.ParseReference(n); err == nil && parsed.Repository != "" {
			n = strings.ToLower(parsed.Repository)
		}
	}
	return strings.ReplaceAll(n, "/", "-")
}

// packageFamiliesMatch reports whether two package family keys refer to the same
// specialist after domain/name migration (flat ↔ domain, or reversed compound).
func packageFamiliesMatch(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	if a == b {
		return true
	}
	// container-dockerfile vs dockerfile; security-secrets vs secrets
	if strings.HasSuffix(a, "-"+b) || strings.HasSuffix(b, "-"+a) {
		return true
	}
	// engineering-review vs review-engineering
	pa := strings.Split(a, "-")
	pb := strings.Split(b, "-")
	if len(pa) == 2 && len(pb) == 2 && pa[0] == pb[1] && pa[1] == pb[0] {
		return true
	}
	return false
}

const officialMetaPackage = "adversarylabs/adversary"

// isRetiredAutoReference skips official catalog paths the free catalog no longer
// publishes (same policy as inventory: adversarylabs/* publisher, library/flat),
// except the intentional meta package adversarylabs/adversary.
func isRetiredAutoReference(reference, manifestName string) bool {
	name := strings.ToLower(strings.TrimSpace(manifestName))
	parsed, err := oci.ParseReference(reference)
	if err != nil {
		return strings.HasPrefix(name, "adversarylabs/") && name != officialMetaPackage
	}
	if !strings.EqualFold(parsed.Registry, officialRegistryHost) {
		return strings.HasPrefix(name, "adversarylabs/") && name != officialMetaPackage
	}
	ns, rest, hasRest := strings.Cut(parsed.Repository, "/")
	switch strings.ToLower(ns) {
	case "adversarylabs":
		// Keep the meta package; retire historical publisher clones (go-cli, …).
		return !strings.EqualFold(rest, "adversary")
	case "library":
		return !hasRest || rest == ""
	default:
		return strings.HasPrefix(name, "adversarylabs/") && name != officialMetaPackage
	}
}

func catalogCandidateName(reference, manifestName string) string {
	parsed, err := oci.ParseReference(reference)
	if err == nil && strings.EqualFold(parsed.Registry, officialRegistryHost) {
		if strings.HasPrefix(strings.ToLower(parsed.Repository), "library/") {
			return parsed.Repository[len("library/"):]
		}
	}
	return manifestName
}

func isLocalDevRegistry(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	return host == "localhost" || strings.HasPrefix(host, "localhost:") ||
		host == "127.0.0.1" || strings.HasPrefix(host, "127.0.0.1:")
}

// preferCandidateReference chooses which alias to keep when multiple references
// resolve to the same package digest or package family. Prefer domain/name
// catalog ids, official registry over localhost, modern namespaces, then a
// concrete version tag over :latest.
func preferCandidateReference(candidate, current DetectionCandidate) bool {
	candScore := candidatePreferenceScore(candidate)
	currScore := candidatePreferenceScore(current)
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

func candidatePreferenceScore(candidate DetectionCandidate) int {
	score := referencePreferenceScore(candidate.Reference)
	// Domain catalog ids (go/cli) beat flat renames (go-cli).
	if strings.Contains(strings.TrimSpace(candidate.Name), "/") {
		score += 40
	}
	return score
}

func referencePreferenceScore(ref string) int {
	parsed, err := oci.ParseReference(ref)
	if err != nil {
		return 0
	}
	score := 0
	host := strings.ToLower(parsed.Registry)
	if host == officialRegistryHost {
		score += 80
	} else if isLocalDevRegistry(host) {
		// Local packs are fine for dev but lose to signed prod catalog.
		score += 10
	} else {
		score += 40
	}
	parts := strings.Split(parsed.Repository, "/")
	if len(parts) > 0 {
		switch strings.ToLower(parts[0]) {
		case "library":
			// Reserved promoted catalog namespace.
			score += 70
		case "adversarylabs":
			// Team-owned source package; prefer its promoted library alias.
			score += 20
		default:
			// domain path (go/, container/, …) preferred
			if len(parts) >= 2 {
				score += 50
			} else {
				score += 25
			}
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
