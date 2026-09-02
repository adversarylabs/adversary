package cmd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	internaladversary "github.com/adversarylabs/adversary/internal/adversary"
	"github.com/adversarylabs/adversary/internal/application"
	"github.com/adversarylabs/adversary/internal/githubreview"
	"github.com/adversarylabs/adversary/pkg/adversarylabs"
	"github.com/adversarylabs/adversary/pkg/review"
)

type composedRunResult struct {
	ref      string
	envelope *review.RunEnvelope
	err      error
	stderr   string
	duration time.Duration
}

// runComposedAdversaries executes a composition root and its children in
// parallel, then presents the composition as one review. Child manifests scope
// the changed files they receive; the repository index remains available for
// cross-file reasoning.
func runComposedAdversaries(
	ctx context.Context,
	app *application.App,
	opts *runOptions,
	root string,
	refs []string,
	apiURL, profile string,
	resultOut, progressOut io.Writer,
) error {
	started := time.Now()
	results := make([]composedRunResult, len(refs))
	limit := min(opts.composeConcurrency, len(refs))
	sem := make(chan struct{}, limit)
	var wg sync.WaitGroup
	for i, ref := range refs {
		i, ref := i, ref
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				results[i] = composedRunResult{ref: ref, err: ctx.Err()}
				return
			}
			defer func() { <-sem }()

			local := *opts
			local.format = "json"
			local.outputFile = ""
			local.envelopes = nil
			var stdout, stderr strings.Builder
			runStarted := time.Now()
			// Manifest composition uses stable catalog IDs such as go/concurrency,
			// while installed official packages are stored under library/... refs.
			// Apply the same catalog-boundary normalization to composed children that
			// runAdversaries applies to top-level CLI arguments.
			executionRef := canonicalCatalogReference(ref)
			err := runOneAdversary(ctx, app, &local, executionRef, apiURL, profile, &stdout, &stderr)
			result := composedRunResult{ref: ref, err: err, stderr: stderr.String(), duration: time.Since(runStarted)}
			if len(local.envelopes) > 0 {
				envelope := local.envelopes[len(local.envelopes)-1].Envelope
				result.envelope = &envelope
			}
			results[i] = result
		}()
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return err
	}

	var usage []adversarylabs.RunUsageAdversaryResult
	var hardErr error
	findingsBeforeDedupe := 0
	for i, result := range results {
		usage = append(usage, runUsageResult(result.ref, result.err, result.duration, result.envelope))
		if result.envelope != nil {
			findingsBeforeDedupe += len(result.envelope.Result.Findings)
		}
		status := "done"
		var findings *internaladversary.FindingsError
		switch {
		case result.err == nil:
		case errors.As(result.err, &findings):
			status = fmt.Sprintf("%d findings", findings.Count)
		default:
			status = "failed: " + compactRunFailure(result.err, result.stderr)
			if hardErr == nil {
				hardErr = fmt.Errorf("adversary %q failed: %w", result.ref, result.err)
			}
		}
		writeProgressDiagnostics(progressOut, result.stderr)
		fmt.Fprintf(progressOut, "[%d/%d] %-36s %s\n", i+1, len(results), result.ref, status)
	}

	aggregate, err := aggregateComposedReview(root, results)
	if err != nil {
		return err
	}
	opts.envelopes = append(opts.envelopes, githubreview.NamedEnvelope{Adversary: root, Envelope: aggregate})
	if opts.format == "json" {
		encoder := json.NewEncoder(resultOut)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(aggregate); err != nil {
			return fmt.Errorf("write composed review: %w", err)
		}
	} else if err := review.RenderTerminal(resultOut, aggregate.Result); err != nil {
		return fmt.Errorf("write composed review: %w", err)
	}

	reportRunUsage(ctx, app, apiURL, profile, adversarylabs.RunUsageReport{
		Adversaries: refs,
		DurationMS:  time.Since(started).Milliseconds(),
		Results:     usage,
	})
	fmt.Fprintf(progressOut, "\nRan %d reviewers concurrently · findings: %d → %d after deduplication\n", len(refs), findingsBeforeDedupe, len(aggregate.Result.Findings))
	if strings.TrimSpace(opts.outputFile) != "" {
		fmt.Fprintf(progressOut, "Results written to %s\n", opts.outputFile)
	}
	if hardErr != nil {
		return hardErr
	}
	if len(aggregate.Result.Findings) > 0 {
		return &internaladversary.FindingsError{Count: len(aggregate.Result.Findings)}
	}
	return nil
}

type findingSource struct {
	Adversary string `json:"adversary"`
	FindingID string `json:"findingId"`
	RuleID    string `json:"ruleId,omitempty"`
}

func aggregateComposedReview(root string, runs []composedRunResult) (review.RunEnvelope, error) {
	var aggregate review.RunEnvelope
	for _, run := range runs {
		if run.envelope != nil && run.ref == root {
			aggregate = *run.envelope
			break
		}
	}
	if aggregate.ProtocolVersion == 0 {
		for _, run := range runs {
			if run.envelope != nil {
				aggregate = *run.envelope
				break
			}
		}
	}
	if aggregate.ProtocolVersion == 0 {
		return review.RunEnvelope{}, fmt.Errorf("composition produced no review result")
	}
	aggregate.Result.Observations = append(aggregate.Result.Observations, review.Note{
		Key:      "composition.reviewers",
		Summary:  fmt.Sprintf("Composition routed this change across %d reviewers.", len(runs)),
		Metadata: compositionReviewerMetadata(runs),
	})
	aggregate.Result.Adversary.Name = root
	aggregate.Result.Findings = nil
	aggregate.Result.SuppressedFindings = nil
	aggregate.Result.Suppressed = review.Suppressed{}

	var merged []review.Finding
	var suppressed []review.Finding
	for _, run := range runs {
		if run.envelope == nil {
			if run.err != nil {
				aggregate.Result.Observations = append(aggregate.Result.Observations, review.Note{
					Key: "composition-reviewer-failed", Summary: fmt.Sprintf("%s did not complete: %s", run.ref, compactRunFailure(run.err, run.stderr)),
				})
			}
			continue
		}
		for _, finding := range run.envelope.Result.Findings {
			merged = mergeComposedFinding(merged, finding, run.ref)
		}
		for _, finding := range run.envelope.Result.SuppressedFindings {
			suppressed = mergeComposedFinding(suppressed, finding, run.ref)
		}
		aggregate.Result.Suppressed.Observations += run.envelope.Result.Suppressed.Observations
		aggregate.Result.Suppressed.Findings += run.envelope.Result.Suppressed.Findings
	}
	sort.SliceStable(merged, func(i, j int) bool {
		return severityRank(merged[i].Severity) > severityRank(merged[j].Severity)
	})
	aggregate.Result.Findings = merged
	if suppressed != nil {
		for i := range suppressed {
			used := append(append([]review.Finding(nil), merged...), suppressed[:i]...)
			suppressed[i].ID = uniqueFindingID(used, suppressed[i].ID, "suppressed")
		}
		aggregate.Result.SuppressedFindings = suppressed
		aggregate.Result.Suppressed.Findings = len(suppressed)
	}
	return aggregate, nil
}

func compositionReviewerMetadata(runs []composedRunResult) json.RawMessage {
	type reviewerStatus struct {
		Adversary string `json:"adversary"`
		Status    string `json:"status"`
	}
	metadata := struct {
		Role      string           `json:"role"`
		Reviewers []reviewerStatus `json:"reviewers"`
	}{Role: "context"}
	for _, run := range runs {
		status := "complete"
		if run.err != nil {
			var findings *internaladversary.FindingsError
			if !errors.As(run.err, &findings) {
				status = "failed"
			}
		}
		if run.envelope != nil && reviewWasSkipped(run.envelope.Result) {
			status = "skipped"
		}
		metadata.Reviewers = append(metadata.Reviewers, reviewerStatus{Adversary: run.ref, Status: status})
	}
	encoded, _ := json.Marshal(metadata)
	return encoded
}

func reviewWasSkipped(result review.ReviewResult) bool {
	for _, observation := range result.Observations {
		if observation.Key == "run-skipped" {
			return true
		}
	}
	return false
}

func mergeComposedFinding(existing []review.Finding, finding review.Finding, ref string) []review.Finding {
	source := findingSource{Adversary: ref, FindingID: finding.ID, RuleID: finding.RuleID}
	finding.Metadata = addFindingSource(finding.Metadata, source)
	match := duplicateFindingIndex(existing, finding)
	if match < 0 {
		finding.ID = uniqueFindingID(existing, finding.ID, ref)
		return append(existing, finding)
	}
	mergeFinding(&existing[match], finding, source)
	return existing
}

func addFindingSource(raw json.RawMessage, source findingSource) json.RawMessage {
	metadata := map[string]any{}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &metadata)
	}
	var sources []findingSource
	if existing, ok := metadata["compositionSources"]; ok {
		data, _ := json.Marshal(existing)
		_ = json.Unmarshal(data, &sources)
	}
	for _, current := range sources {
		if current.Adversary == source.Adversary && current.FindingID == source.FindingID {
			encoded, _ := json.Marshal(metadata)
			return encoded
		}
	}
	metadata["compositionSources"] = append(sources, source)
	encoded, _ := json.Marshal(metadata)
	return encoded
}

func mergeFinding(dst *review.Finding, src review.Finding, source findingSource) {
	dst.Metadata = addFindingSource(dst.Metadata, source)
	if severityRank(src.Severity) > severityRank(dst.Severity) {
		dst.Severity = src.Severity
	}
	if confidenceRank(src.Confidence) > confidenceRank(dst.Confidence) {
		dst.Confidence = src.Confidence
	}
	dst.Evidence = appendUniqueEvidence(dst.Evidence, src.Evidence...)
	dst.Tags = appendUniqueStrings(dst.Tags, src.Tags...)
	if len(src.WhyItMatters) > len(dst.WhyItMatters) {
		dst.WhyItMatters = src.WhyItMatters
	}
	if len(src.Recommendation) > len(dst.Recommendation) {
		dst.Recommendation = src.Recommendation
	}
}

func duplicateFindingIndex(existing []review.Finding, candidate review.Finding) int {
	for i := range existing {
		if candidate.GroupKey != "" && existing[i].GroupKey == candidate.GroupKey && samePrimaryFile(existing[i], candidate) {
			return i
		}
		if sameFindingLocation(existing[i], candidate) && titleSimilarity(existing[i].Title, candidate.Title) >= 0.6 {
			return i
		}
	}
	return -1
}

func samePrimaryFile(a, b review.Finding) bool {
	return len(a.Evidence) > 0 && len(b.Evidence) > 0 && a.Evidence[0].File != "" && a.Evidence[0].File == b.Evidence[0].File
}

func sameFindingLocation(a, b review.Finding) bool {
	if !samePrimaryFile(a, b) {
		return false
	}
	if a.Evidence[0].Line == nil || b.Evidence[0].Line == nil {
		return false
	}
	delta := *a.Evidence[0].Line - *b.Evidence[0].Line
	return delta >= -2 && delta <= 2
}

func titleSimilarity(a, b string) float64 {
	aTokens, bTokens := wordSet(a), wordSet(b)
	if len(aTokens) == 0 || len(bTokens) == 0 {
		return 0
	}
	intersection, union := 0, len(aTokens)
	for token := range bTokens {
		if _, ok := aTokens[token]; ok {
			intersection++
		} else {
			union++
		}
	}
	return float64(intersection) / float64(union)
}

func wordSet(value string) map[string]struct{} {
	words := strings.FieldsFunc(strings.ToLower(value), func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsNumber(r) })
	out := make(map[string]struct{}, len(words))
	for _, word := range words {
		if len(word) > 2 {
			out[word] = struct{}{}
		}
	}
	return out
}

func uniqueFindingID(existing []review.Finding, id, source string) string {
	for _, finding := range existing {
		if finding.ID == id {
			sum := sha256.Sum256([]byte(source + "\x00" + id))
			return id + "-" + hex.EncodeToString(sum[:4])
		}
	}
	return id
}

func appendUniqueEvidence(dst []review.Evidence, values ...review.Evidence) []review.Evidence {
	for _, value := range values {
		duplicate := false
		for _, current := range dst {
			if current.File == value.File && intValue(current.Line) == intValue(value.Line) && current.Message == value.Message {
				duplicate = true
				break
			}
		}
		if !duplicate {
			dst = append(dst, value)
		}
	}
	return dst
}

func appendUniqueStrings(dst []string, values ...string) []string {
	for _, value := range values {
		found := false
		for _, current := range dst {
			if current == value {
				found = true
				break
			}
		}
		if !found {
			dst = append(dst, value)
		}
	}
	return dst
}

func intValue(value *int) int {
	if value == nil {
		return 0
	}
	return *value
}

func severityRank(value string) int {
	return map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}[value]
}

func confidenceRank(value string) int {
	return map[string]int{"high": 3, "medium": 2, "low": 1}[value]
}
