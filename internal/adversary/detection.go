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
	forced, err := resolveForcedSelections(selections, includes)
	if err != nil {
		return nil, err
	}
	excluded, err := resolveNamedSelections(selections, excludes, "excluded")
	if err != nil {
		return nil, err
	}
	for i := range selections {
		selection := &selections[i]
		selection.Excluded = excluded[i]
		selection.Forced = forced[i]
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

func resolveForcedSelections(selections []DetectionSelection, includes []string) (map[int]bool, error) {
	return resolveNamedSelections(selections, includes, "forced")
}

func resolveNamedSelections(selections []DetectionSelection, values []string, operation string) (map[int]bool, error) {
	resolved := make(map[int]bool, len(values))
	for _, raw := range values {
		value := strings.ToLower(strings.TrimSpace(raw))
		exact := make([]int, 0, 1)
		short := make([]int, 0, 1)
		for i, selection := range selections {
			candidate := selection.Candidate
			if value == strings.ToLower(candidate.Name) || value == strings.ToLower(candidate.Reference) {
				exact = append(exact, i)
				continue
			}
			if value == strings.ToLower(manifest.ShortName(candidate.Name)) {
				short = append(short, i)
			}
		}
		matches := exact
		if len(matches) == 0 {
			matches = short
		}
		if len(matches) == 0 {
			return nil, fmt.Errorf("%s adversary %q did not resolve to an available candidate", operation, raw)
		}
		if len(matches) > 1 {
			qualified := make([]string, 0, len(matches))
			for _, index := range matches {
				qualified = append(qualified, selections[index].Candidate.Name)
			}
			sort.Strings(qualified)
			return nil, fmt.Errorf("%s adversary %q is ambiguous; use one of: %s", operation, raw, strings.Join(qualified, ", "))
		}
		resolved[matches[0]] = true
	}
	return resolved, nil
}

func candidateNames(candidate DetectionCandidate) []string {
	return []string{strings.ToLower(candidate.Name), strings.ToLower(candidate.Reference), strings.ToLower(manifest.ShortName(candidate.Name))}
}
