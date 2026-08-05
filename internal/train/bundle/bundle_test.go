package bundle

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/adversarylabs/adversary/internal/train/cases"
)

func sampleCase() *cases.Case {
	return &cases.Case{
		SchemaVersion: 4,
		ID:            "opentelemetry-go-pr-9001-r1",
		Repository:    cases.Repository{Owner: "open-telemetry", Name: "opentelemetry-go"},
		PullRequest:   cases.PullRequest{Number: 9001, BaseSHA: "basebasebasebasebasebasebasebasebasebase", InitialHeadSHA: "headheadheadheadheadheadheadheadheadhead"},
		ReviewEvent: cases.ReviewEvent{
			RoundIndex:  1,
			ReviewedSHA: "headheadheadheadheadheadheadheadheadhead",
			SubmittedAt: time.Now().UTC(),
		},
		Comments: []cases.Comment{{ID: 1, Body: "leak", Path: "x.go"}},
		FollowUp: cases.FollowUp{Commits: []cases.FollowUpCommit{{SHA: "fixfixfixfixfixfixfixfixfixfix"}}},
		Labels: cases.Labels{
			ExpectedConcerns: []cases.ExpectedConcern{
				{ID: "c1", Summary: "goroutine leak on shutdown", Approved: true},
			},
			KnownNonIssues: []string{"style"},
		},
		Metadata: cases.Metadata{Split: "discovery", CreatedAt: time.Now().UTC()},
	}
}

func TestReviewerProjectionOmitsLabelsAndFollowUps(t *testing.T) {
	man, err := BuildFromCase(sampleCase())
	if err != nil {
		t.Fatal(err)
	}
	// Full bundle must contain sensitive sections.
	for _, name := range []string{SectionExpectedConcerns, SectionFollowUp, SectionHumanReview} {
		if _, ok := man.Sections[name]; !ok {
			t.Fatalf("full bundle missing %s", name)
		}
	}
	proj, err := ProjectForRole(man, RoleReviewer)
	if err != nil {
		t.Fatal(err)
	}
	if err := AssertReviewerIsolation(proj); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{SectionExpectedConcerns, SectionFollowUp, SectionHumanReview, SectionKnownNonIssues, SectionSplit} {
		if _, ok := proj.Sections[name]; ok {
			t.Fatalf("reviewer projection must not include %s", name)
		}
	}
	for _, name := range []string{SectionCheckout, SectionDiff, SectionRepoMetadata} {
		if _, ok := proj.Sections[name]; !ok {
			t.Fatalf("reviewer projection missing allowed section %s", name)
		}
	}
}

func TestMaterializeReviewerInputNoLabelLeak(t *testing.T) {
	man, err := BuildFromCase(sampleCase())
	if err != nil {
		t.Fatal(err)
	}
	proj, err := ProjectForRole(man, RoleReviewer)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := MaterializeReviewerInput(proj, dir); err != nil {
		t.Fatal(err)
	}
	// Walk all files and ensure no expected concern text / follow-up SHAs.
	err = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		s := string(raw)
		if strings.Contains(s, "expected_concerns") || strings.Contains(s, "goroutine leak on shutdown") {
			t.Errorf("label content leaked into %s", path)
		}
		if strings.Contains(s, "fixfixfixfixfixfixfixfixfixfix") {
			t.Errorf("follow-up sha leaked into %s", path)
		}
		if strings.Contains(s, SectionFollowUp) || strings.Contains(s, SectionExpectedConcerns) {
			t.Errorf("forbidden section name in %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestAssertReviewerIsolationRejectsInjectedSection(t *testing.T) {
	p := &Projection{
		Role: RoleReviewer,
		Sections: map[string]Section{
			SectionCheckout:         {Digest: "sha256:aa"},
			SectionExpectedConcerns: {Digest: "sha256:bb", Payload: []byte(`[{"id":"c1"}]`)},
		},
	}
	if err := AssertReviewerIsolation(p); err == nil {
		t.Fatal("expected isolation error")
	}
}

func TestBundleDigestStable(t *testing.T) {
	man1, err := BuildFromCase(sampleCase())
	if err != nil {
		t.Fatal(err)
	}
	man2, err := BuildFromCase(sampleCase())
	if err != nil {
		t.Fatal(err)
	}
	if man1.BundleDigest == "" || man1.BundleDigest != man2.BundleDigest {
		t.Fatalf("digests differ: %s vs %s", man1.BundleDigest, man2.BundleDigest)
	}
}
