package adversary

import (
	"fmt"
	"sort"
	"strings"

	"github.com/adversarylabs/adversary/pkg/detection"
	"github.com/adversarylabs/adversary/pkg/manifest"
)

func EvaluateDeclarativeDetection(m manifest.Manifest, context detection.Context) detection.Result {
	declaration := m.Detection
	patterns := declaration.Files
	legacy := false
	if len(patterns) == 0 && len(declaration.RepositoryFiles) == 0 && declaration.Entrypoint == "" && len(m.Triggers.FilesChanged) > 0 {
		patterns = m.Triggers.FilesChanged
		legacy = true
	}

	repositoryMatch := matchAnyPath(declaration.RepositoryFiles, context.RepositoryFiles)
	relevant := make([]string, 0)
	for _, changed := range context.ChangedFiles {
		if len(declaration.ChangeTypes) > 0 && !containsString(declaration.ChangeTypes, string(changed.Status)) {
			continue
		}
		if matchAnyPath(patterns, []string{changed.Path}) || changed.PreviousPath != "" && matchAnyPath(patterns, []string{changed.PreviousPath}) {
			relevant = append(relevant, changed.Path)
		}
	}
	changeMatch := len(relevant) > 0
	result := detection.Result{SchemaVersion: detection.SchemaVersion, Applicable: changeMatch, Confidence: detection.ConfidenceLow, Reasons: []string{}, RelevantFiles: relevant, RepositoryMatch: boolPointer(repositoryMatch), ChangeMatch: boolPointer(changeMatch)}
	if changeMatch {
		result.Confidence = detection.ConfidenceHigh
		if legacy {
			result.Reasons = []string{"changed files matched legacy triggers.files_changed"}
		} else {
			result.Reasons = []string{"changed files matched detection.files"}
		}
	} else if repositoryMatch {
		result.Reasons = []string{"repository matched, but this change did not match"}
	} else if len(patterns) == 0 && len(declaration.RepositoryFiles) == 0 {
		result.Reasons = []string{"adversary does not declare automatic detection"}
	} else {
		result.Reasons = []string{"no changed files matched the adversary detection declaration"}
	}
	result.Normalize()
	return result
}

func matchAnyPath(patterns, paths []string) bool {
	for _, pattern := range patterns {
		for _, path := range paths {
			if globMatch(pattern, path) {
				return true
			}
		}
	}
	return false
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func boolPointer(value bool) *bool { return &value }

type DetectionCandidate struct {
	Name      string
	Reference string
	Digest    string
	Manifest  manifest.Manifest
}

type DetectionSelection struct {
	Candidate DetectionCandidate
	Result    detection.Result
	Selected  bool
	Forced    bool
	Excluded  bool
	Error     error
}

func FilterAndOrderSelections(selections []DetectionSelection, minimum detection.Confidence, includes, excludes []string, all bool) ([]DetectionSelection, error) {
	if !minimum.Valid() {
		return nil, fmt.Errorf("invalid minimum confidence %q", minimum)
	}
	includeSet := normalizedNameSet(includes)
	excludeSet := normalizedNameSet(excludes)
	for i := range selections {
		selection := &selections[i]
		names := candidateNames(selection.Candidate)
		selection.Excluded = setMatchesAny(excludeSet, names)
		selection.Forced = setMatchesAny(includeSet, names)
		switch {
		case selection.Excluded:
			selection.Selected = false
		case all || selection.Forced:
			selection.Selected = true
		case selection.Error != nil && !selection.Result.Applicable:
			selection.Selected = false
		default:
			selection.Selected = selection.Result.Applicable && selection.Result.Confidence.Rank() >= minimum.Rank()
		}
	}
	sort.SliceStable(selections, func(i, j int) bool {
		left, right := selections[i], selections[j]
		if left.Selected != right.Selected {
			return left.Selected
		}
		if left.Result.Confidence.Rank() != right.Result.Confidence.Rank() {
			return left.Result.Confidence.Rank() > right.Result.Confidence.Rank()
		}
		return strings.ToLower(left.Candidate.Name) < strings.ToLower(right.Candidate.Name)
	})
	return selections, nil
}

func normalizedNameSet(values []string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[strings.ToLower(strings.TrimSpace(value))] = struct{}{}
	}
	return result
}

func candidateNames(candidate DetectionCandidate) []string {
	return []string{strings.ToLower(candidate.Name), strings.ToLower(candidate.Reference), strings.ToLower(manifest.ShortName(candidate.Name))}
}

func setMatchesAny(set map[string]struct{}, values []string) bool {
	for _, value := range values {
		if _, ok := set[value]; ok {
			return true
		}
	}
	return false
}
