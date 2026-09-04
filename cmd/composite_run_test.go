package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	internaladversary "github.com/adversarylabs/adversary/internal/adversary"
	"github.com/adversarylabs/adversary/pkg/review"
)

func TestRetryableComposedRunFailure(t *testing.T) {
	if !retryableComposedRunFailure(context.Background(), errors.New("host execution failed"), "model_timeout") {
		t.Fatal("model timeout should be retried")
	}
	if !retryableComposedRunFailure(context.Background(), errors.New("HTTP 503"), "") {
		t.Fatal("provider 503 should be retried")
	}
	if !retryableComposedRunFailure(context.Background(), errors.New("camel model request failed: Service Unavailable"), "") {
		t.Fatal("provider service unavailable should be retried")
	}
	if retryableComposedRunFailure(context.Background(), &internaladversary.FindingsError{Count: 1}, "model_timeout") {
		t.Fatal("a findings exit is successful and must not be retried")
	}
	if retryableComposedRunFailure(context.Background(), errors.New("invalid manifest"), "") {
		t.Fatal("deterministic package errors should not be retried")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if retryableComposedRunFailure(cancelled, errors.New("context deadline exceeded"), "") {
		t.Fatal("a cancelled parent context must not be retried")
	}
}

func TestAggregateComposedReviewDeduplicatesAndRetainsSources(t *testing.T) {
	line := 12
	root := review.RunEnvelope{ProtocolVersion: 1, Result: review.ReviewResult{
		Adversary: review.ReviewAdversary{Name: "review/code", Version: "0.0.3"},
		Target:    review.ReviewTarget{Repository: "repo"},
		Positives: []review.Note{}, Observations: []review.Note{}, Suppressed: review.Suppressed{},
		Findings: []review.Finding{{ID: "race", Title: "Unsynchronized map access", Category: "correctness", Severity: "high", Confidence: "medium", Summary: "map is shared", Evidence: []review.Evidence{{File: "main.go", Line: &line}}}},
	}}
	specialist := review.RunEnvelope{ProtocolVersion: 1, Result: review.ReviewResult{
		Adversary: review.ReviewAdversary{Name: "go/concurrency"}, Target: root.Result.Target,
		Positives: []review.Note{}, Observations: []review.Note{}, Suppressed: review.Suppressed{},
		Findings: []review.Finding{{ID: "map-race", Title: "Unsynchronized shared map access", Category: "correctness", Severity: "critical", Confidence: "high", Summary: "race", Evidence: []review.Evidence{{File: "main.go", Line: &line}}}},
	}}

	got, err := aggregateComposedReview("review/code", []composedRunResult{{ref: "review/code", envelope: &root}, {ref: "go/concurrency", envelope: &specialist}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Result.Findings) != 1 || got.Result.Findings[0].Severity != "critical" || got.Result.Findings[0].Confidence != "high" {
		t.Fatalf("aggregate = %#v", got.Result.Findings)
	}
	var metadata struct {
		Sources []findingSource `json:"compositionSources"`
	}
	if err := json.Unmarshal(got.Result.Findings[0].Metadata, &metadata); err != nil {
		t.Fatal(err)
	}
	if len(metadata.Sources) != 2 || metadata.Sources[0].Adversary != "review/code" || metadata.Sources[1].Adversary != "go/concurrency" {
		t.Fatalf("sources = %#v", metadata.Sources)
	}
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := review.DecodeRunEnvelope(encoded); err != nil {
		t.Fatalf("aggregate is not a valid review envelope: %v", err)
	}
}

func TestAggregateComposedReviewKeepsDistinctNearbyFindings(t *testing.T) {
	line := 12
	envelope := func(id, title string) review.RunEnvelope {
		return review.RunEnvelope{ProtocolVersion: 1, Result: review.ReviewResult{
			Adversary: review.ReviewAdversary{Name: id}, Target: review.ReviewTarget{}, Positives: []review.Note{}, Observations: []review.Note{}, Suppressed: review.Suppressed{},
			Findings: []review.Finding{{ID: id, Title: title, Category: "correctness", Severity: "high", Confidence: "high", Summary: title, Evidence: []review.Evidence{{File: "main.go", Line: &line}}}},
		}}
	}
	a := envelope("a", "SQL transaction leaks on rollback")
	b := envelope("b", "Authorization bypasses tenant boundary")
	got, err := aggregateComposedReview("a", []composedRunResult{{ref: "a", envelope: &a}, {ref: "b", envelope: &b}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Result.Findings) != 2 {
		t.Fatalf("findings = %#v", got.Result.Findings)
	}
}

func TestAggregateComposedReviewKeepsEmptyFindingsProtocolValid(t *testing.T) {
	root := review.RunEnvelope{ProtocolVersion: 1, Result: review.ReviewResult{
		Adversary: review.ReviewAdversary{Name: "review/code", Version: "0.0.4"},
		Target:    review.ReviewTarget{Repository: "repo"}, Positives: []review.Note{},
		Observations: []review.Note{}, Findings: []review.Finding{}, Suppressed: review.Suppressed{},
	}}
	got, err := aggregateComposedReview("review/code", []composedRunResult{{ref: "review/code", envelope: &root}})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) == "" || got.Result.Findings == nil {
		t.Fatalf("clean composite findings must be an array: %s", encoded)
	}
	if _, err := review.DecodeRunEnvelope(encoded); err != nil {
		t.Fatalf("clean aggregate is not a valid review envelope: %v", err)
	}
}
