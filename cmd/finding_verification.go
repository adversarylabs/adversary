package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/adversarylabs/adversary/internal/application"
	"github.com/adversarylabs/adversary/internal/findingverify"
	"github.com/adversarylabs/adversary/internal/modelreview"
	"github.com/adversarylabs/adversary/pkg/detection"
	"github.com/adversarylabs/adversary/pkg/review"
	"github.com/spf13/cobra"
)

// Host services live on the process runtime rather than in command handlers.
type findingVerificationRuntime interface {
	prepareFindingVerification(context.Context, *detection.Context) (*findingverify.Collector, error)
	findingVerificationProvider(modelreview.Config) (modelreview.Provider, error)
	readFindingVerification(string) (findingverify.Report, error)
	writeFindingVerification(string, findingverify.Report) error
}

func verifyComposedResults(ctx context.Context, opts *runOptions, runs []composedRunResult, collector *findingverify.Collector, contextErr error, progress io.Writer) ([]composedRunResult, *findingverify.Report, error) {
	snapshot := findingverify.Snapshot{Version: findingverify.Version, Candidates: []findingverify.Candidate{}}
	var reader findingverify.Reader
	if collector != nil {
		snapshot.Base, snapshot.Head = collector.Base, collector.Head
		reader = collector.Read
	}
	for i, run := range runs {
		if run.envelope == nil {
			continue
		}
		for j, f := range run.envelope.Result.Findings {
			c := findingverify.Candidate{ID: fmt.Sprintf("run-%d-finding-%d", i, j), Reviewer: run.ref, Scope: run.scope, WholeRepository: opts.allFiles, Finding: f, Sources: []findingverify.Source{}}
			if contextErr != nil {
				c.ContextError = "Pinned review context unavailable."
			} else if collector != nil {
				collector.Prepare(ctx, &c)
			} else {
				c.ContextError = "Pinned review context unavailable."
			}
			snapshot.Candidates = append(snapshot.Candidates, c)
		}
	}
	provider := opts.verificationProvider
	if provider == nil && len(snapshot.Candidates) > 0 {
		// Provider configuration errors become explicit unresolved decisions. They
		// must not silently bypass verification or erase successful peer findings.
		if opts.verificationRuntime != nil {
			provider, _ = opts.verificationRuntime.findingVerificationProvider(modelreview.Config{Provider: opts.modelProvider, Model: opts.model})
		}
	}
	report, err := findingverify.Run(ctx, snapshot, provider, reader)
	if err != nil {
		return nil, nil, err
	}
	filtered := append([]composedRunResult(nil), runs...)
	decision := 0
	for i, run := range runs {
		if run.envelope == nil {
			continue
		}
		envelope := *run.envelope
		envelope.Result.Findings = []review.Finding{}
		for _, f := range run.envelope.Result.Findings {
			if report.Decisions[decision].Status == "keep" {
				envelope.Result.Findings = append(envelope.Result.Findings, f)
			}
			decision++
		}
		filtered[i].envelope = &envelope
	}
	keep, reject, unresolved := verificationCounts(report)
	fmt.Fprintf(progress, "Finding verification: %d kept · %d rejected · %d unresolved\n", keep, reject, unresolved)
	if opts.verificationOutput != "" {
		if opts.verificationRuntime == nil {
			return filtered, &report, fmt.Errorf("runtime cannot save verification report")
		}
		if err := opts.verificationRuntime.writeFindingVerification(opts.verificationOutput, report); err != nil {
			return filtered, &report, err
		}
	}
	if ctx.Err() != nil {
		return filtered, &report, ctx.Err()
	}
	// Uncertainty is a per-finding outcome, not a failed review. Only verified
	// findings reach the merger; withheld candidates remain in the report.
	return filtered, &report, nil
}
func verificationCounts(r findingverify.Report) (keep, reject, unresolved int) {
	for _, d := range r.Decisions {
		switch d.Status {
		case "keep":
			keep++
		case "reject":
			reject++
		default:
			unresolved++
		}
	}
	return
}
func applyVerificationSummary(env *review.RunEnvelope, r findingverify.Report, incomplete bool) {
	_, reject, unresolved := verificationCounts(r)
	// Include original unresolved findings for inspection without presenting them
	// as confirmed review comments. Full source/replay data is an opt-in file.
	pending := []findingverify.Candidate{}
	for i, d := range r.Decisions {
		if d.Status == "unresolved" {
			c := r.Snapshot.Candidates[i]
			c.Sources = nil
			c.RetrievedSources = nil
			c.Patch = ""
			pending = append(pending, c)
		}
	}
	metadata, _ := json.Marshal(struct {
		Revision   string                    `json:"promptRevision"`
		Decisions  []findingverify.Decision  `json:"decisions"`
		Unresolved []findingverify.Candidate `json:"unresolvedCandidates"`
	}{r.PromptRevision, r.Decisions, pending})
	summary := fmt.Sprintf("%d verified findings after deduplication; %d rejected; %d unresolved.", len(env.Result.Findings), reject, unresolved)
	env.Result.Observations = append(env.Result.Observations, review.Note{Key: "composition.finding-verification", Summary: summary, Metadata: metadata})
	risk := "none"
	for _, f := range env.Result.Findings {
		if severityRank(f.Severity) > severityRank(risk) {
			risk = f.Severity
		}
	}
	env.Result.Assessment = &review.Assessment{Risk: risk, Summary: summary}
	env.Result.Opinion = &review.Opinion{Summary: summary}
	if !incomplete && unresolved == 0 {
		ship := len(env.Result.Findings) == 0
		env.Result.Opinion.Ship = &ship
	} else if incomplete {
		env.Result.Opinion.Summary = "Review incomplete. " + summary
	} else {
		env.Result.Opinion.Summary = "Unresolved findings withheld; no clean-review opinion. " + summary
	}
}
func newVerifyFindingsCommand(app *application.App) *cobra.Command {
	var providerName, model, output string
	command := &cobra.Command{Use: "verify-findings <report.json>", Short: "Replay candidate verification from a saved report without regenerating reviews", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		runtime, ok := app.Dependencies().Runtime.(findingVerificationRuntime)
		if !ok {
			return fmt.Errorf("runtime does not support finding verification replay")
		}
		original, err := runtime.readFindingVerification(args[0])
		if err != nil {
			return err
		}
		provider, err := runtime.findingVerificationProvider(modelreview.Config{Provider: providerName, Model: model})
		if err != nil {
			return err
		}
		// Replay has no live repository reader. A request absent from the saved
		// packet stays unresolved rather than silently reading a different checkout.
		report, err := findingverify.Run(cmd.Context(), original.Snapshot, provider, nil)
		if err != nil {
			return err
		}
		if output != "" {
			err = runtime.writeFindingVerification(output, report)
		} else {
			err = json.NewEncoder(cmd.OutOrStdout()).Encode(report)
		}
		if err != nil {
			return err
		}
		// A completed replay may contain unresolved decisions. Its report is the
		// outcome; uncertainty must not turn it into an execution failure.
		return cmd.Context().Err()
	}}
	command.Flags().StringVar(&providerName, "model-provider", "", "verification model provider")
	command.Flags().StringVar(&model, "model", "", "verification model")
	command.Flags().StringVar(&output, "output", "", "save replay result (default: stdout)")
	return command
}
