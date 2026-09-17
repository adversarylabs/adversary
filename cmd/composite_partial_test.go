package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	internaladversary "github.com/adversarylabs/adversary/internal/adversary"
	"github.com/adversarylabs/adversary/internal/application"
	"github.com/adversarylabs/adversary/pkg/repository"
	"github.com/adversarylabs/adversary/pkg/review"
)

func TestCompositeIsolatesFailedReviewers(t *testing.T) {
	for _, tc := range []struct {
		name                                                               string
		empty, skipped, allFailed, incomplete, verify, cancel, badArtifact bool
		exit, count                                                        int
	}{
		{name: "verified-peer-survives", verify: true, exit: 1, count: 1},
		{name: "unverified-peer-survives", exit: 1, count: 1},
		{name: "empty-peer-is-not-clean", empty: true},
		{name: "all-failed-is-fatal", allFailed: true, exit: 2},
		{name: "only-skipped-peer-is-fatal", skipped: true, exit: 2},
		{name: "incomplete-child-propagates", incomplete: true, exit: 1, count: 1},
		{name: "cancellation-is-fatal", cancel: true, exit: 130},
		{name: "artifact-failure-is-fatal", verify: true, badArtifact: true, exit: 2, count: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out, progress bytes.Buffer
			base := lifecycleTestApp(t, repository.Repository{Root: t.TempDir()}, &out, &progress)
			deps := base.Dependencies()
			spy := &multiRecordingRuntime{inner: deps.Runtime, stdoutBodies: map[string]string{}, errs: map[string]error{}}
			runs := verificationRuns("valid", "bad-specialist")
			for i, run := range runs {
				ship := true
				run.envelope.Result.Opinion = &review.Opinion{Ship: &ship, Summary: "Ready"}
				if i == 0 && (tc.empty || tc.skipped) {
					run.envelope.Result.Findings = []review.Finding{}
				}
				if i == 0 && tc.skipped {
					run.envelope.Result.Observations = []review.Note{{Key: "run-skipped", Summary: "Not applicable"}}
				}
				if i == 1 && tc.incomplete {
					run.envelope.Result.Findings = []review.Finding{}
					run.envelope.Result.Observations = []review.Note{{Key: "review.evidence-incomplete", Summary: "One unsupported candidate withheld"}}
				} else if i == 1 || tc.allFailed {
					// A failing process must not leak even a valid-looking partial envelope.
					spy.errs[run.ref] = errors.New("invalid_model_evidence")
				} else if len(run.envelope.Result.Findings) > 0 {
					spy.errs[run.ref] = &internaladversary.FindingsError{Count: 1}
				}
				raw, err := json.Marshal(run.envelope)
				if err != nil {
					t.Fatal(err)
				}
				spy.stdoutBodies[run.ref] = string(raw)
			}
			deps.Runtime = verificationExecutionRuntime{spy}
			app, err := application.New(deps)
			if err != nil {
				t.Fatal(err)
			}
			opts := &runOptions{noTelemetry: true, composeConcurrency: 1, format: "json", verifyFindings: tc.verify, verificationProvider: verificationProvider{}, verificationRuntime: verificationFixtureRuntime{collector: verificationCollector(t)}}
			if tc.badArtifact {
				opts.verificationOutput = t.TempDir()
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.cancel {
				cancel()
			}
			err = runComposedAdversaries(ctx, app, opts, "valid", []string{"valid", "bad-specialist"}, "", "", &out, &progress)
			if ExitCode(err) != tc.exit {
				t.Fatalf("exit %d want %d: %v\n%s", ExitCode(err), tc.exit, err, progress.String())
			}
			if tc.allFailed || tc.cancel {
				return
			}
			env, decodeErr := review.DecodeRunEnvelope(out.Bytes())
			if decodeErr != nil {
				t.Fatalf("decode: %v\n%s", decodeErr, out.String())
			}
			if len(env.Result.Findings) != tc.count {
				t.Fatalf("findings: %+v", env.Result.Findings)
			}
			if env.Result.Opinion == nil || env.Result.Opinion.Ship != nil {
				t.Fatalf("partial review claimed clean: %+v", env.Result.Opinion)
			}
			if !strings.Contains(out.String(), "composition.incomplete") {
				t.Fatal("missing coverage warning")
			}
			for _, f := range env.Result.Findings {
				if f.ID == "bad-specialist" {
					t.Fatal("failed review leaked a finding")
				}
			}
		})
	}
}
