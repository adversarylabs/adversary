package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/adversarylabs/adversary/internal/findingverify"
	"github.com/adversarylabs/adversary/internal/modelreview"
	"github.com/adversarylabs/adversary/pkg/detection"
	"github.com/adversarylabs/adversary/pkg/review"
)

type verificationProvider struct{}

func (verificationProvider) Name() string  { return "fake" }
func (verificationProvider) Model() string { return "fixture" }
func (verificationProvider) Review(ctx context.Context, r modelreview.Request) (modelreview.Result, error) {
	var input struct {
		Candidate findingverify.Candidate `json:"candidate"`
	}
	if err := json.Unmarshal(r.Input, &input); err != nil {
		return modelreview.Result{}, err
	}
	c := input.Candidate
	if c.Finding.ID == "broken" {
		return modelreview.Result{}, errors.New("provider failed")
	}
	status := "keep"
	if c.Finding.ID == "false" {
		status = "reject"
	}
	evidence := []findingverify.Citation{}
	for _, s := range c.Sources {
		if s.Side == "head" && s.Unavailable == "" {
			evidence = append(evidence, findingverify.Citation{SourceID: s.ID, Line: s.StartLine})
			break
		}
	}
	data, _ := json.Marshal(findingverify.Decision{CandidateID: c.ID, Status: status, Confidence: "high", Reason: "The source establishes this outcome.", Evidence: evidence, Requests: []findingverify.ReadRequest{}})
	return modelreview.Result{Output: data}, nil
}
func verificationCollector(t *testing.T) *findingverify.Collector {
	t.Helper()
	dir := t.TempDir()
	git := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false", "-C", dir}, args...)...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git: %s: %v", out, err)
		}
		return strings.TrimSpace(string(out))
	}
	git("init")
	git("config", "user.name", "Fixture")
	git("config", "user.email", "fixture@example.invalid")
	if err := os.WriteFile(filepath.Join(dir, "guard.go"), []byte("guard\n"), 0600); err != nil {
		t.Fatal(err)
	}
	git("add", ".")
	git("commit", "-m", "fixture")
	sha := git("rev-parse", "HEAD")
	c, err := findingverify.NewCollector(context.Background(), &detection.Context{RepositoryRoot: dir, BaseRef: sha, HeadRef: sha, Mode: detection.ModeExplicitRange, ChangedFiles: []detection.ChangedFile{{Path: "guard.go", Status: detection.StatusModified}}})
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func verificationRuns(ids ...string) []composedRunResult {
	line := 1
	runs := []composedRunResult{}
	for _, id := range ids {
		finding := review.Finding{ID: id, Title: "Same title", Summary: "Same claim", Severity: "medium", Confidence: "high", Category: "correctness", Evidence: []review.Evidence{{File: "guard.go", Line: &line}}}
		envelope := &review.RunEnvelope{ProtocolVersion: 1, Result: review.ReviewResult{Adversary: review.ReviewAdversary{Name: id}, Positives: []review.Note{}, Observations: []review.Note{}, Findings: []review.Finding{finding}}}
		runs = append(runs, composedRunResult{ref: id, scope: "full-change", envelope: envelope})
	}
	return runs
}
func TestSharedVerificationPrecedesDeduplication(t *testing.T) {
	// The false candidate arrives first and would otherwise be chosen as the
	// representative of the valid finding with the same assertion and location.
	runs := verificationRuns("false", "valid")
	output := filepath.Join(t.TempDir(), "report.json")
	filtered, report, err := verifyComposedResults(context.Background(), &runOptions{verificationProvider: verificationProvider{}, verificationRuntime: processRuntime{}, verificationOutput: output}, runs, verificationCollector(t), nil, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	env, err := aggregateComposedReview("root", filtered)
	if err != nil {
		t.Fatal(err)
	}
	applyVerificationSummary(&env, *report, false)
	if len(env.Result.Findings) != 1 || env.Result.Findings[0].ID != "valid" {
		t.Fatal(env.Result.Findings)
	}
	if len(runs[0].envelope.Result.Findings) != 1 || len(report.Snapshot.Candidates) != 2 {
		t.Fatal("raw candidates erased")
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var saved findingverify.Report
	if err = json.Unmarshal(data, &saved); err != nil {
		t.Fatal(err)
	}
	if saved.Snapshot.Candidates[0].Finding.ID != "false" {
		t.Fatal("rejected original lost")
	}
	if env.Result.Opinion.Ship == nil || *env.Result.Opinion.Ship {
		t.Fatal(env.Result.Opinion)
	}
}
func TestIncompleteVerificationPreservesVerifiedPeersWithoutCleanOpinion(t *testing.T) {
	filtered, report, err := verifyComposedResults(context.Background(), &runOptions{verificationProvider: verificationProvider{}}, verificationRuns("valid", "broken"), verificationCollector(t), nil, io.Discard)
	if err == nil {
		t.Fatal("incomplete verification succeeded")
	}
	env, aggregateErr := aggregateComposedReview("root", filtered)
	if aggregateErr != nil {
		t.Fatal(aggregateErr)
	}
	applyVerificationSummary(&env, *report, true)
	if len(env.Result.Findings) != 1 || env.Result.Findings[0].ID != "valid" || env.Result.Opinion.Ship != nil {
		t.Fatal(env.Result)
	}
	metadata := string(env.Result.Observations[len(env.Result.Observations)-1].Metadata)
	if !strings.Contains(metadata, `"id":"broken"`) || !strings.Contains(metadata, `"status":"unresolved"`) {
		t.Fatal(metadata)
	}
}
func TestUnavailableContextDoesNotPublishUnverifiedFindings(t *testing.T) {
	filtered, report, err := verifyComposedResults(context.Background(), &runOptions{verificationProvider: verificationProvider{}}, verificationRuns("valid"), nil, errors.New("no context"), io.Discard)
	if err == nil || len(filtered[0].envelope.Result.Findings) != 0 || report.Decisions[0].Status != "unresolved" {
		t.Fatal(filtered, report, err)
	}
}
func TestVerificationArtifactDoesNotFollowDestinationSymlink(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "source")
	if err := os.WriteFile(victim, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "report")
	if err := os.Symlink(victim, link); err != nil {
		t.Skip("symlinks unavailable")
	}
	if err := findingverify.WriteReport(link, findingverify.Report{Version: findingverify.Version}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(victim)
	if err != nil || string(data) != "original" {
		t.Fatal(string(data), err)
	}
	info, err := os.Stat(link)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0077 != 0 {
		t.Fatal("private source report is group/world readable")
	}
}
