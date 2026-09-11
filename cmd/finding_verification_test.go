package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	internaladversary "github.com/adversarylabs/adversary/internal/adversary"
	"github.com/adversarylabs/adversary/internal/application"
	"github.com/adversarylabs/adversary/internal/findingverify"
	"github.com/adversarylabs/adversary/internal/modelreview"
	"github.com/adversarylabs/adversary/pkg/detection"
	"github.com/adversarylabs/adversary/pkg/repository"
	"github.com/adversarylabs/adversary/pkg/review"
)

type verificationFixtureRuntime struct {
	processRuntime
	collector *findingverify.Collector
}

type verificationExecutionRuntime struct{ *multiRecordingRuntime }

func (r verificationExecutionRuntime) Run(ctx context.Context, opts application.AdversaryRunOptions) error {
	var envelope review.RunEnvelope
	if err := json.Unmarshal([]byte(r.stdoutBodies[opts.AdversaryRef]), &envelope); err != nil {
		return err
	}
	if opts.OnEnvelope != nil {
		opts.OnEnvelope(envelope)
	}
	return r.multiRecordingRuntime.Run(ctx, opts)
}

func (r verificationFixtureRuntime) prepareFindingVerification(context.Context, *detection.Context) (*findingverify.Collector, error) {
	return r.collector, nil
}

func TestComposedUnresolvedReviewReturnsUsableProtocolAndNormalExitCode(t *testing.T) {
	for _, tc := range []struct {
		name        string
		ids         []string
		count, exit int
	}{
		{"mixed", []string{"valid", "uncertain"}, 1, 1},
		{"only-unresolved", []string{"uncertain"}, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out, progress bytes.Buffer
			base := lifecycleTestApp(t, repository.Repository{Root: t.TempDir()}, &out, &progress)
			deps := base.Dependencies()
			spy := &multiRecordingRuntime{inner: deps.Runtime, stdoutBodies: map[string]string{}, errs: map[string]error{}}
			for _, run := range verificationRuns(tc.ids...) {
				raw, err := json.Marshal(run.envelope)
				if err != nil {
					t.Fatal(err)
				}
				spy.stdoutBodies[run.ref] = string(raw)
				spy.errs[run.ref] = &internaladversary.FindingsError{Count: 1}
			}
			deps.Runtime = verificationExecutionRuntime{spy}
			app, err := application.New(deps)
			if err != nil {
				t.Fatal(err)
			}
			opts := &runOptions{noTelemetry: true, composeConcurrency: 1, format: "json", verifyFindings: true, verificationProvider: verificationProvider{}, verificationRuntime: verificationFixtureRuntime{collector: verificationCollector(t)}}
			err = runComposedAdversaries(context.Background(), app, opts, tc.ids[0], tc.ids, "", "", &out, &progress)
			if ExitCode(err) != tc.exit {
				t.Fatalf("exit %d, want %d: %v\n%s", ExitCode(err), tc.exit, err, progress.String())
			}
			env, err := review.DecodeRunEnvelope(out.Bytes())
			if err != nil {
				t.Fatalf("invalid output: %v\n%s", err, out.String())
			}
			if len(env.Result.Findings) != tc.count || env.Result.Opinion.Ship != nil {
				t.Fatalf("lost findings or claimed clean: %+v", env.Result)
			}
			if !strings.Contains(out.String(), `"unresolved"`) {
				t.Fatal("lost unresolved diagnostics")
			}
		})
	}
}

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
	if c.Finding.ID == "uncertain" {
		status = "unresolved"
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
func TestUnresolvedVerificationPreservesVerifiedPeersWithoutExecutionError(t *testing.T) {
	filtered, report, err := verifyComposedResults(context.Background(), &runOptions{verificationProvider: verificationProvider{}}, verificationRuns("valid", "false", "uncertain", "broken"), verificationCollector(t), nil, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	env, aggregateErr := aggregateComposedReview("root", filtered)
	if aggregateErr != nil {
		t.Fatal(aggregateErr)
	}
	applyVerificationSummary(&env, *report, false)
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
	if err != nil || len(filtered[0].envelope.Result.Findings) != 0 || report.Decisions[0].Status != "unresolved" {
		t.Fatal(filtered, report, err)
	}
}

func TestAllUnresolvedIsEmptyReviewNotCleanOpinionOrExecutionFailure(t *testing.T) {
	for _, id := range []string{"uncertain", "broken"} {
		t.Run(id, func(t *testing.T) {
			filtered, report, err := verifyComposedResults(context.Background(), &runOptions{verificationProvider: verificationProvider{}}, verificationRuns(id), verificationCollector(t), nil, io.Discard)
			if err != nil {
				t.Fatal(err)
			}
			env, err := aggregateComposedReview("root", filtered)
			if err != nil {
				t.Fatal(err)
			}
			applyVerificationSummary(&env, *report, false)
			if len(env.Result.Findings) != 0 || env.Result.Opinion.Ship != nil || !strings.Contains(env.Result.Opinion.Summary, "Unresolved findings withheld") {
				t.Fatal(env.Result)
			}
			if len(report.Decisions) != 1 || report.Decisions[0].Status != "unresolved" {
				t.Fatal(report)
			}
		})
	}
}

func TestVerificationCancellationAndArtifactFailureRemainErrors(t *testing.T) {
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := verifyComposedResults(cancelled, &runOptions{verificationProvider: verificationProvider{}}, verificationRuns("uncertain"), nil, errors.New("no context"), io.Discard); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
	if _, _, err := verifyComposedResults(context.Background(), &runOptions{verificationProvider: verificationProvider{}, verificationRuntime: processRuntime{}, verificationOutput: filepath.Join(t.TempDir(), "missing", "report.json")}, verificationRuns("uncertain"), verificationCollector(t), nil, io.Discard); err == nil {
		t.Fatal("artifact write failure hidden")
	}
}

func TestReanchorFindingToVerifiedChangedCitation(t *testing.T) {
	offDiff := 90
	finding := review.Finding{ID: "finding", Evidence: []review.Evidence{{File: "context.go", Line: &offDiff}}}
	candidate := findingverify.Candidate{
		ChangedRegions: []detection.ReviewRegion{{Path: "changed.go", StartLine: 12, EndLine: 14}},
		Sources:        []findingverify.Source{{ID: "changed-source", Path: "changed.go", Side: "head", StartLine: 10, Content: "a\nb\nc\nd\ne\n"}},
	}
	decision := findingverify.Decision{Evidence: []findingverify.Citation{{SourceID: "changed-source", Line: 13}}}
	got := reanchorFindingToChangedCitation(finding, candidate, decision)
	if len(got.Evidence) != 2 || got.Evidence[0].File != "changed.go" || got.Evidence[0].Line == nil || *got.Evidence[0].Line != 13 {
		t.Fatalf("evidence = %#v", got.Evidence)
	}
	alreadyAnchored := review.Finding{ID: "finding", Evidence: []review.Evidence{{File: "changed.go", Line: got.Evidence[0].Line}}}
	got = reanchorFindingToChangedCitation(alreadyAnchored, candidate, decision)
	if len(got.Evidence) != 1 {
		t.Fatalf("existing changed anchor duplicated: %#v", got.Evidence)
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
