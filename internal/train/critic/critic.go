package critic

import (
	"fmt"
	"sort"
	"strings"

	"github.com/adversarylabs/adversary/internal/train/judge"
)

// Hypothesis is a generalized improvement hypothesis (not a repo-specific fix).
type Hypothesis struct {
	ID                     string   `json:"id"`
	ObservedFailure        string   `json:"observed_failure"`
	GeneralizedFailureMode string   `json:"generalized_failure_mode"`
	WhyNotRepoSpecific     string   `json:"why_not_repository_specific"`
	OwningAdversary        string   `json:"owning_adversary"`
	Principle              string   `json:"principle"`
	Counterexamples        []string `json:"counterexamples"`
	SuggestedChangeSurface string   `json:"suggested_change_surface"` // prompt | deterministic-analysis | thresholds | fixtures
	SupportingFailureKinds []string `json:"supporting_failure_kinds"`
	CaseIDs                []string `json:"case_ids"`
}

// AnalyzeFailures produces generalized critic hypotheses from a failure list.
func AnalyzeFailures(failures []judge.Failure, targetAdversary string) []Hypothesis {
	if targetAdversary == "" {
		targetAdversary = "engineering-review"
	}
	byKind := map[string][]judge.Failure{}
	for _, f := range failures {
		byKind[f.Kind] = append(byKind[f.Kind], f)
	}
	var kinds []string
	for k := range byKind {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)

	var out []Hypothesis
	for i, kind := range kinds {
		fs := byKind[kind]
		caseSet := map[string]struct{}{}
		for _, f := range fs {
			caseSet[f.CaseID] = struct{}{}
		}
		var caseIDs []string
		for id := range caseSet {
			caseIDs = append(caseIDs, id)
		}
		sort.Strings(caseIDs)

		h := Hypothesis{
			ID:                     fmt.Sprintf("h-%d-%s", i+1, kind),
			OwningAdversary:        targetAdversary,
			SupportingFailureKinds: []string{kind},
			CaseIDs:                caseIDs,
			ObservedFailure:        summarizeObserved(kind, fs),
			GeneralizedFailureMode: generalize(kind),
			WhyNotRepoSpecific:     "Pattern derived from failure kind frequency across cases, not from a single repository path or project convention.",
			Principle:              principleFor(kind),
			Counterexamples:        counterexamplesFor(kind),
			SuggestedChangeSurface: surfaceFor(kind),
		}
		out = append(out, h)
	}
	// If we have multiple kinds, add a cross-cutting synthesis hypothesis.
	if len(out) >= 2 {
		out = append(out, Hypothesis{
			ID:                     "h-synthesis",
			OwningAdversary:        targetAdversary,
			SupportingFailureKinds: kinds,
			CaseIDs:                allCaseIDs(failures),
			ObservedFailure:        fmt.Sprintf("Multiple failure modes across %d findings", len(failures)),
			GeneralizedFailureMode: "Review quality degrades when detection, evidence, and prioritization are not jointly calibrated against human-accepted concerns.",
			WhyNotRepoSpecific:     "Synthesis spans all observed failure kinds, independent of repository identity.",
			Principle:              "Prefer changes that improve concern coverage without increasing unsupported high-severity claims.",
			Counterexamples: []string{
				"A change that only hard-codes one case's wording",
				"A severity threshold tweak that floods low-value noise",
			},
			SuggestedChangeSurface: "prompt",
		})
	}
	return out
}

func summarizeObserved(kind string, fs []judge.Failure) string {
	return fmt.Sprintf("%s occurred %d time(s); example: %s", kind, len(fs), fs[0].Detail)
}

func generalize(kind string) string {
	switch kind {
	case "missed-concern":
		return "The reviewer systematically under-detects a class of engineering concerns that human reviewers raise and authors fix."
	case "false-positive":
		return "The reviewer emits findings that do not correspond to accepted human concerns, diluting signal."
	case "unsupported-claim":
		return "Findings lack file/line evidence or actionable detail, reducing trust and matchability."
	default:
		return "Unclassified review quality failure mode."
	}
}

func principleFor(kind string) string {
	switch kind {
	case "missed-concern":
		return "Expand detection and reasoning for the missed concern class with general evidence requirements, not repository-specific rules."
	case "false-positive":
		return "Tighten claim gates: require concrete evidence and suppress speculative findings without code anchors."
	case "unsupported-claim":
		return "Require evidence snippets and path localization before emitting a finding."
	default:
		return "Improve review quality with generalized, evidence-backed rules."
	}
}

func counterexamplesFor(kind string) []string {
	switch kind {
	case "missed-concern":
		return []string{
			"A legitimate style-only comment that should not become a gold concern",
			"A project convention that is not portable across codebases",
		}
	case "false-positive":
		return []string{
			"A true defect humans missed (gold set incomplete)",
			"A valid finding whose wording diverges from human phrasing but shares the concern",
		}
	default:
		return []string{"Over-fitting evidence format to one tool's output style"}
	}
}

func surfaceFor(kind string) string {
	switch kind {
	case "missed-concern":
		return "prompt"
	case "false-positive", "unsupported-claim":
		return "prompt"
	default:
		return "prompt"
	}
}

func allCaseIDs(failures []judge.Failure) []string {
	set := map[string]struct{}{}
	for _, f := range failures {
		set[f.CaseID] = struct{}{}
	}
	var ids []string
	for id := range set {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// FormatHypothesis renders a human-readable hypothesis.
func FormatHypothesis(h Hypothesis) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Hypothesis %s\n", h.ID)
	fmt.Fprintf(&b, "Observed failure:\n  %s\n", h.ObservedFailure)
	fmt.Fprintf(&b, "Generalized failure mode:\n  %s\n", h.GeneralizedFailureMode)
	fmt.Fprintf(&b, "Why not repository-specific:\n  %s\n", h.WhyNotRepoSpecific)
	fmt.Fprintf(&b, "Principle:\n  %s\n", h.Principle)
	fmt.Fprintf(&b, "Owning adversary: %s\n", h.OwningAdversary)
	fmt.Fprintf(&b, "Suggested surface: %s\n", h.SuggestedChangeSurface)
	return b.String()
}
