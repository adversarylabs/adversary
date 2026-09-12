package findingverify

import (
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/adversarylabs/adversary/internal/modelreview"
	"github.com/adversarylabs/adversary/pkg/detection"
	"github.com/adversarylabs/adversary/pkg/review"
)

type fakeProvider struct {
	review func(context.Context, modelreview.Request) (modelreview.Result, error)
}

func (f fakeProvider) Name() string  { return "fake" }
func (f fakeProvider) Model() string { return "fixture" }
func (f fakeProvider) Review(ctx context.Context, r modelreview.Request) (modelreview.Result, error) {
	return f.review(ctx, r)
}

type modelInput struct {
	Candidate       Candidate       `json:"candidate"`
	Previous        *Decision       `json:"previous"`
	SourceRanges    []sourceRange   `json:"sourceRanges"`
	InvalidOutput   json.RawMessage `json:"invalidOutput"`
	ValidationError string          `json:"validationError"`
}

func inputOf(t *testing.T, r modelreview.Request) modelInput {
	t.Helper()
	var input modelInput
	if err := json.Unmarshal(r.Input, &input); err != nil {
		t.Fatal(err)
	}
	return input
}
func resultOf(d Decision) modelreview.Result {
	data, _ := json.Marshal(d)
	return modelreview.Result{Output: data}
}
func source(p, text string) Source {
	s := Source{Path: p, Side: "head", StartLine: 1, Content: text, EndOfFile: true}
	s.ID = sourceID(s)
	return s
}
func fixture(ids ...string) Snapshot {
	s := Snapshot{Version: Version, Base: "base", Head: "head", Candidates: []Candidate{}}
	for _, id := range ids {
		s.Candidates = append(s.Candidates, Candidate{ID: id, Reviewer: "specialist", Finding: review.Finding{ID: id, Summary: "Original claim"}, Patch: "changed guard", Sources: []Source{source("guard.go", "authorizeEach(ids)\n")}})
	}
	return s
}
func decision(c Candidate, status string) Decision {
	d := Decision{CandidateID: c.ID, Status: status, Confidence: "high", Reason: "The cited guard independently checks every requested item.", Evidence: []Citation{}, Requests: []ReadRequest{}}
	if status != "unresolved" {
		d.Evidence = append(d.Evidence, Citation{SourceID: c.Sources[0].ID, Line: 1})
	}
	return d
}
func TestIndependentDecisionsPreservePeersAndOriginals(t *testing.T) {
	snapshot := fixture("keep", "reject", "failure")
	provider := fakeProvider{review: func(ctx context.Context, r modelreview.Request) (modelreview.Result, error) {
		in := inputOf(t, r)
		if in.Candidate.ID == "failure" {
			return modelreview.Result{}, errors.New("provider diagnostic must not leak")
		}
		return resultOf(decision(in.Candidate, in.Candidate.ID)), nil
	}}
	report, err := Run(context.Background(), snapshot, provider, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i, want := range []string{"keep", "reject", "unresolved"} {
		if report.Decisions[i].Status != want {
			t.Fatalf("%d: %+v", i, report.Decisions[i])
		}
	}
	if len(report.Snapshot.Candidates) != 3 || report.Snapshot.Candidates[1].Finding.Summary != "Original claim" {
		t.Fatal("original pool changed")
	}
	if len(snapshot.Candidates[0].Sources) != 1 {
		t.Fatal("caller mutated")
	}
	if report.Calls[2].Error != "Verification provider request failed." {
		t.Fatal(report.Calls[2])
	}
	if report.Decisions[2].Failure != FailureProviderRequest {
		t.Fatal(report.Decisions[2])
	}
}
func TestBoundedRetrievalAndOfflineReplayUseSameInputs(t *testing.T) {
	snapshot := fixture("one")
	extra := source("callee.go", "func apply(ids []ID) {}\n")
	var reads atomic.Int32
	reader := func(ctx context.Context, r ReadRequest) Source { reads.Add(1); return extra }
	provider := fakeProvider{review: func(ctx context.Context, r modelreview.Request) (modelreview.Result, error) {
		in := inputOf(t, r)
		if in.Previous == nil {
			if len(in.Candidate.Sources) != 1 || len(in.Candidate.RetrievedSources) != 0 {
				t.Fatal("future evidence leaked into first pass")
			}
			d := decision(in.Candidate, "unresolved")
			d.Requests = []ReadRequest{{Path: "callee.go", Side: "head", StartLine: 1, EndLine: 20}}
			return resultOf(d), nil
		}
		d := decision(in.Candidate, "keep")
		d.Evidence = []Citation{{SourceID: extra.ID, Line: 1}}
		return resultOf(d), nil
	}}
	first, err := Run(context.Background(), snapshot, provider, reader)
	if err != nil {
		t.Fatal(err)
	}
	if reads.Load() != 1 || len(first.Calls) != 2 || first.Decisions[0].Status != "keep" {
		t.Fatalf("%+v", first)
	}
	second, err := Run(context.Background(), first.Snapshot, provider, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Calls) != 2 || second.Decisions[0].Status != "keep" {
		t.Fatalf("%+v", second)
	}
	for i := range first.Calls {
		if first.Calls[i].InputDigest != second.Calls[i].InputDigest {
			t.Fatal("replay changed model inputs")
		}
	}
	if len(snapshot.Candidates[0].RetrievedSources) != 0 {
		t.Fatal("input pool mutated")
	}
}
func TestUnavailableReplayContextRemainsUnresolved(t *testing.T) {
	var calls atomic.Int32
	p := fakeProvider{review: func(ctx context.Context, r modelreview.Request) (modelreview.Result, error) {
		calls.Add(1)
		in := inputOf(t, r)
		d := decision(in.Candidate, "unresolved")
		d.Requests = []ReadRequest{{Path: "missing.go", Side: "head", StartLine: 1, EndLine: 20}}
		if in.Previous != nil && in.Candidate.Sources[len(in.Candidate.Sources)-1].Unavailable == "" {
			t.Fatal("missing offline context hidden")
		}
		return resultOf(d), nil
	}}
	r, err := Run(context.Background(), fixture("one"), p, nil)
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 || r.Decisions[0].Status != "unresolved" {
		t.Fatal(r)
	}
}
func TestInvalidDecisionsAreNotSilentlyAccepted(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*Decision)
	}{
		{"wrong id", func(d *Decision) { d.CandidateID = "foreign" }},
		{"unknown status", func(d *Decision) { d.Status = "maybe" }},
		{"no decisive fact", func(d *Decision) { d.Reason = " " }},
		{"uncited reject", func(d *Decision) { d.Status = "reject"; d.Evidence = []Citation{} }},
		{"invented source", func(d *Decision) { d.Evidence[0].SourceID = "invented" }},
		{"line past source", func(d *Decision) { d.Evidence[0].Line = 2 }},
		{"traversal", func(d *Decision) {
			d.Requests = []ReadRequest{{Path: "../secret", Side: "head", StartLine: 1, EndLine: 2}}
		}},
		{"oversized read", func(d *Decision) {
			d.Requests = []ReadRequest{{Path: "big.go", Side: "head", StartLine: 1, EndLine: 201}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := fakeProvider{review: func(ctx context.Context, r modelreview.Request) (modelreview.Result, error) {
				d := decision(inputOf(t, r).Candidate, "keep")
				tc.mutate(&d)
				return resultOf(d), nil
			}}
			r, err := Run(context.Background(), fixture("one"), p, nil)
			if err != nil {
				t.Fatal(err)
			}
			if r.Decisions[0].Status != "unresolved" || r.Decisions[0].Failure != FailureInvalidDecision {
				t.Fatal(r)
			}
		})
	}
}
func TestMalformedProviderJSONAndLowConfidence(t *testing.T) {
	for _, raw := range []string{`{"candidateId":"one"}`, `not json`, `{"candidateId":"one","status":"reject","confidence":"high","reason":"x","evidence":[],"requests":[],"extra":true}`} {
		p := fakeProvider{review: func(context.Context, modelreview.Request) (modelreview.Result, error) {
			return modelreview.Result{Output: json.RawMessage(raw)}, nil
		}}
		r, err := Run(context.Background(), fixture("one"), p, nil)
		if err != nil {
			t.Fatal(err)
		}
		if r.Decisions[0].Status != "unresolved" {
			t.Fatal(r)
		}
	}
	p := fakeProvider{review: func(ctx context.Context, r modelreview.Request) (modelreview.Result, error) {
		d := decision(inputOf(t, r).Candidate, "reject")
		d.Confidence = "low"
		return resultOf(d), nil
	}}
	r, err := Run(context.Background(), fixture("one"), p, nil)
	if err != nil {
		t.Fatal(err)
	}
	if r.Decisions[0].Status != "unresolved" {
		t.Fatal(r)
	}
}

func TestKeptFindingRequiresChangedLineCitation(t *testing.T) {
	changed := source("changed.go", "first\nsecond\nthird\n")
	unchanged := source("context.go", "supporting context\n")
	candidate := Candidate{
		ID: "one", Reviewer: "reviewer", Finding: review.Finding{ID: "finding", Summary: "claim"},
		ChangedRegions: []detection.ReviewRegion{{Path: "changed.go", StartLine: 2, EndLine: 2}},
		Sources:        []Source{changed, unchanged},
	}
	offDiff := Decision{CandidateID: "one", Status: "keep", Confidence: "high", Reason: "The context supports the claim.", Evidence: []Citation{{SourceID: unchanged.ID, Line: 1}}, Requests: []ReadRequest{}}
	if err := validateDecision(offDiff, candidate); err == nil {
		t.Fatal("off-diff keep accepted")
	}
	onDiff := offDiff
	onDiff.Evidence = append(onDiff.Evidence, Citation{SourceID: changed.ID, Line: 2})
	if err := validateDecision(onDiff, candidate); err != nil {
		t.Fatalf("changed-line keep rejected: %v", err)
	}
	reject := offDiff
	reject.Status = "reject"
	if err := validateDecision(reject, candidate); err != nil {
		t.Fatalf("off-diff rejection should remain valid: %v", err)
	}
}
func TestStructuralCorrectionPreservesRetrievalBudgetAndReplay(t *testing.T) {
	snapshot := fixture("one", "peer")
	extra := source("callee.go", "func apply(ids []ID) {}\n")
	var reads atomic.Int32
	reader := func(ctx context.Context, r ReadRequest) Source {
		if !validRequest(r) {
			t.Fatal("invalid request reached reader")
		}
		reads.Add(1)
		return extra
	}
	p := fakeProvider{review: func(ctx context.Context, r modelreview.Request) (modelreview.Result, error) {
		in := inputOf(t, r)
		d := decision(in.Candidate, "keep")
		if in.Candidate.ID == "peer" {
			return resultOf(d), nil
		}
		if len(in.SourceRanges) == 0 || in.SourceRanges[0].EndLine != 1 {
			t.Fatal("missing exact citation ranges")
		}
		if in.Previous == nil {
			d.Status = "unresolved"
			d.Evidence = []Citation{}
			d.Requests = []ReadRequest{{Path: "callee.go", Side: "head", StartLine: 1, EndLine: 201}}
			if in.ValidationError != "" {
				if !json.Valid(in.InvalidOutput) {
					t.Fatal("original invalid output missing")
				}
				d.Requests[0].EndLine = 200
			}
		} else {
			d.Evidence = []Citation{{SourceID: extra.ID, Line: 2}}
			if in.ValidationError != "" {
				d.Evidence[0].Line = 1
			}
		}
		return resultOf(d), nil
	}}
	r, err := Run(context.Background(), snapshot, p, reader)
	if err != nil {
		t.Fatal(err)
	}
	if reads.Load() != 1 || len(r.Calls) != 5 || r.Decisions[0].Status != "keep" || r.Decisions[1].Status != "keep" {
		t.Fatalf("%+v", r)
	}
	for i, want := range []struct{ round, attempt int }{{1, 1}, {1, 2}, {2, 1}, {2, 2}, {1, 1}} {
		if r.Calls[i].Round != want.round || r.Calls[i].Attempt != want.attempt {
			t.Fatal(r.Calls)
		}
	}
	if r.Calls[0].Error == "" || r.Calls[2].Error == "" {
		t.Fatal("invalid decisions were erased")
	}
	replayed, err := Run(context.Background(), r.Snapshot, p, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := range r.Calls {
		if r.Calls[i].InputDigest != replayed.Calls[i].InputDigest {
			t.Fatal("replay inputs differ")
		}
	}
}

func TestStructuralCorrectionsBoundedAndNeverReadInvalidPaths(t *testing.T) {
	var requests atomic.Int32
	p := fakeProvider{review: func(ctx context.Context, r modelreview.Request) (modelreview.Result, error) {
		requests.Add(1)
		d := decision(inputOf(t, r).Candidate, "unresolved")
		d.Requests = []ReadRequest{{Path: "../secret", Side: "head", StartLine: 1, EndLine: 2}}
		return resultOf(d), nil
	}}
	r, err := Run(context.Background(), fixture("one"), p, func(context.Context, ReadRequest) Source { t.Fatal("unsafe read"); return Source{} })
	if err != nil || requests.Load() != 3 || len(r.Calls) != 3 || r.Decisions[0].Status != "unresolved" {
		t.Fatal(r, err)
	}
	for _, call := range r.Calls {
		if call.Error == "" || len(call.Output) == 0 {
			t.Fatal("missing failure evidence")
		}
	}
}

func TestValidUnresolvedDecisionIsNotQualityRerolled(t *testing.T) {
	var calls atomic.Int32
	p := fakeProvider{review: func(ctx context.Context, r modelreview.Request) (modelreview.Result, error) {
		calls.Add(1)
		return resultOf(decision(inputOf(t, r).Candidate, "unresolved")), nil
	}}
	r, err := Run(context.Background(), fixture("one"), p, nil)
	if err != nil || calls.Load() != 1 || r.Decisions[0].Status != "unresolved" {
		t.Fatal(r, err)
	}
}

func TestMissingProviderCancellationAndSnapshotIntegrity(t *testing.T) {
	r, err := Run(context.Background(), fixture("one"), nil, nil)
	if err != nil || r.Decisions[0].Status != "unresolved" {
		t.Fatal(r, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p := fakeProvider{review: func(context.Context, modelreview.Request) (modelreview.Result, error) {
		t.Fatal("provider called after cancellation")
		return modelreview.Result{}, nil
	}}
	r, err = Run(ctx, fixture("one", "two"), p, nil)
	if err != nil || len(r.Decisions) != 2 {
		t.Fatal(r, err)
	}
	altered := fixture("one")
	altered.Candidates[0].Sources[0].Content = "changed"
	if _, err = Run(context.Background(), altered, p, nil); err == nil {
		t.Fatal("tampered source accepted")
	}
	if _, err = Run(context.Background(), fixture("duplicate", "duplicate"), p, nil); err == nil {
		t.Fatal("duplicate IDs accepted")
	}
}
