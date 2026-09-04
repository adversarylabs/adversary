package telemetry

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/adversarylabs/adversary/pkg/adversarylabs"
)

func TestParseTagsAndBenchmarkTrace(t *testing.T) {
	tags, err := ParseTags([]string{"benchmark=true", "experiment=routing-r1"})
	if err != nil {
		t.Fatal(err)
	}
	if tags["benchmark"] != "true" {
		t.Fatalf("tags = %#v", tags)
	}
	for _, invalid := range [][]string{{"missing"}, {"secret="}, {"1bad=value"}, {"x=y", "x=z"}} {
		if _, err := ParseTags(invalid); err == nil {
			t.Fatalf("expected %v to fail", invalid)
		}
	}

	start := time.Unix(1_788_364_800, 0)
	report := BuildTrace(adversarylabs.RunUsageReport{
		Adversaries: []string{"go/security"}, DurationMS: 2500, Tags: tags,
		Results: []adversarylabs.RunUsageAdversaryResult{{Adversary: "go/security", Status: "findings", DurationMS: 2000, HighCount: 1, Scope: "batch-001", GroupCount: 3, RegionCount: 5, ChangedLineCount: 220}},
		Phases:  []adversarylabs.RunUsagePhase{{Name: "build-review-graph", Status: "completed", StartedAtUnixNano: unixNanoString(start), EndedAtUnixNano: unixNanoString(start.Add(500 * time.Millisecond))}},
	}, start, start.Add(2500*time.Millisecond))
	if len(report.TraceID) != 32 || len(report.Spans) != 3 {
		t.Fatalf("trace = %#v", report)
	}
	payload, err := OTLPJSON(report, "2026.9.3-beta.1")
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatal(err)
	}
	text := string(payload)
	for _, want := range []string{"resourceSpans", "adversary.run.tag.benchmark", "adversary review", "adversary phase", "build-review-graph", "go/security", "adversary.run.group_count", "adversary.run.region_count", "adversary.run.changed_line_count"} {
		if !strings.Contains(text, want) {
			t.Fatalf("OTLP payload missing %q: %s", want, text)
		}
	}
	for _, forbidden := range []string{"repository", "prompt", "finding text"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("OTLP payload contains %q", forbidden)
		}
	}
}
