package adversary

import (
	"errors"
	"reflect"
	"testing"

	"github.com/adversarylabs/adversary/pkg/detection"
	"github.com/adversarylabs/adversary/pkg/manifest"
)

func TestEvaluateDeclarativeDetectionSeparatesRepositoryAndChangeMatch(t *testing.T) {
	m := manifest.Manifest{Detection: manifest.Detection{Files: []string{"**/*.yaml"}, RepositoryFiles: []string{"Dockerfile"}}}
	context := detection.Context{ChangedFiles: []detection.ChangedFile{{Path: "README.md", Status: detection.StatusModified}}, RepositoryFiles: []string{"Dockerfile", "README.md"}}
	got := EvaluateDeclarativeDetection(m, context)
	if got.Applicable || got.RepositoryMatch == nil || !*got.RepositoryMatch || got.ChangeMatch == nil || *got.ChangeMatch {
		t.Fatalf("result = %#v", got)
	}
}

func TestEvaluateDeclarativeDetectionMatchesRenamesAndChangeTypes(t *testing.T) {
	m := manifest.Manifest{Detection: manifest.Detection{Files: []string{"**/*.dockerfile"}, ChangeTypes: []string{"renamed"}}}
	context := detection.Context{ChangedFiles: []detection.ChangedFile{{Path: "containers/app.txt", PreviousPath: "containers/app.dockerfile", Status: detection.StatusRenamed}}}
	got := EvaluateDeclarativeDetection(m, context)
	if !got.Applicable || got.Confidence != detection.ConfidenceHigh || !reflect.DeepEqual(got.RelevantFiles, []string{"containers/app.txt"}) {
		t.Fatalf("result = %#v", got)
	}
}

func TestEvaluateDeclarativeDetectionUsesLegacyTriggers(t *testing.T) {
	m := manifest.Manifest{Triggers: manifest.Triggers{FilesChanged: []string{"Dockerfile"}}}
	got := EvaluateDeclarativeDetection(m, detection.Context{ChangedFiles: []detection.ChangedFile{{Path: "Dockerfile", Status: detection.StatusModified}}})
	if !got.Applicable || got.Confidence != detection.ConfidenceHigh {
		t.Fatalf("result = %#v", got)
	}
}

func TestFilterAndOrderSelections(t *testing.T) {
	selections := []DetectionSelection{
		{Candidate: DetectionCandidate{Name: "low"}, Result: detection.Result{Applicable: true, Confidence: detection.ConfidenceLow}},
		{Candidate: DetectionCandidate{Name: "z-high"}, Result: detection.Result{Applicable: true, Confidence: detection.ConfidenceHigh}},
		{Candidate: DetectionCandidate{Name: "a-high"}, Result: detection.Result{Applicable: true, Confidence: detection.ConfidenceHigh}},
		{Candidate: DetectionCandidate{Name: "forced"}, Result: detection.Result{Applicable: false, Confidence: detection.ConfidenceLow}, Error: errors.New("detector failed")},
	}
	got, err := FilterAndOrderSelections(selections, detection.ConfidenceMedium, []string{"forced", "low"}, []string{"low"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Candidate.Name != "a-high" || got[1].Candidate.Name != "z-high" || got[2].Candidate.Name != "forced" || !got[2].Selected || got[3].Selected {
		t.Fatalf("ordered selections = %#v", got)
	}
}

func TestForcedShortNameMustResolveUniquely(t *testing.T) {
	selections := []DetectionSelection{
		{Candidate: DetectionCandidate{Name: "adversarylabs/security", Reference: "registry.test/adversarylabs/security:1"}, Result: detection.Result{Confidence: detection.ConfidenceLow}},
		{Candidate: DetectionCandidate{Name: "randomperson/security", Reference: "registry.test/randomperson/security:1"}, Result: detection.Result{Confidence: detection.ConfidenceLow}},
	}
	if _, err := FilterAndOrderSelections(selections, detection.ConfidenceMedium, []string{"security"}, nil, false); err == nil {
		t.Fatal("ambiguous short include was accepted")
	}
	got, err := FilterAndOrderSelections(selections, detection.ConfidenceMedium, []string{"adversarylabs/security"}, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if !got[0].Selected || got[0].Candidate.Name != "adversarylabs/security" || got[1].Selected {
		t.Fatalf("qualified selection = %#v", got)
	}
}

func TestExcludedShortNameMustResolveUniquely(t *testing.T) {
	selections := []DetectionSelection{
		{Candidate: DetectionCandidate{Name: "adversarylabs/security", Reference: "registry.test/adversarylabs/security:1"}, Result: detection.Result{Applicable: true, Confidence: detection.ConfidenceHigh}},
		{Candidate: DetectionCandidate{Name: "randomperson/security", Reference: "registry.test/randomperson/security:1"}, Result: detection.Result{Applicable: true, Confidence: detection.ConfidenceHigh}},
	}
	if _, err := FilterAndOrderSelections(selections, detection.ConfidenceMedium, nil, []string{"security"}, false); err == nil {
		t.Fatal("ambiguous short exclusion was accepted")
	}
	got, err := FilterAndOrderSelections(selections, detection.ConfidenceMedium, nil, []string{"randomperson/security"}, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, selection := range got {
		if selection.Candidate.Name == "randomperson/security" && !selection.Excluded {
			t.Fatalf("qualified exclusion was not applied: %#v", got)
		}
		if selection.Candidate.Name == "adversarylabs/security" && !selection.Selected {
			t.Fatalf("unrelated publisher was excluded: %#v", got)
		}
	}
}
