package review

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDecodeRunEnvelope(t *testing.T) {
	data := []byte(`{
  "protocolVersion": 1,
  "result": {
    "adversary": {"name": "dockerfile"},
    "target": {"repository": "/repo", "filesScanned": 1},
    "assessment": {"risk": "low", "summary": "Well structured."},
    "positives": [{"key": "multi-stage", "summary": "Build and runtime are separated."}],
    "observations": [{"key": "layout", "summary": "Three stages are named."}],
    "findings": [
      {
        "id": "base-image",
        "ruleId": "dockerfile.base-image.unpinned-digest",
        "title": "Base images are not pinned by digest",
        "category": "supply-chain",
        "severity": "low",
        "confidence": "high",
        "summary": "Three stages reference node:22-bookworm-slim by tag rather than digest.",
        "whyItMatters": "Container image tags are mutable.",
        "impact": "Future builds may consume different base images.",
        "evidence": [
          {"file": "Dockerfile", "line": 3, "message": "deps stage", "snippet": "FROM node:22-bookworm-slim AS deps", "metadata": {"image": "node:22-bookworm-slim"}}
        ],
        "recommendation": "Pin production base images.",
        "remediation": {"estimate": "10-20 minutes", "complexity": "small"}
      }
    ],
    "opinion": {"ship": true, "summary": "I would ship this Dockerfile as-is."},
    "suppressed": {"observations": 0, "findings": 0}
  }
}`)
	envelope, err := DecodeRunEnvelope(data)
	if err != nil {
		t.Fatal(err)
	}
	result := envelope.Result
	if result.Assessment == nil || result.Assessment.Risk != "low" {
		t.Fatalf("Assessment = %#v", result.Assessment)
	}
	if len(result.Positives) != 1 {
		t.Fatalf("Positives len = %d", len(result.Positives))
	}
	finding := result.Findings[0]
	if finding.Category != "supply-chain" || finding.Confidence != "high" || finding.Impact == "" {
		t.Fatalf("Finding = %#v", finding)
	}
	if len(finding.Evidence) != 1 || !json.Valid(finding.Evidence[0].Metadata) {
		t.Fatalf("Evidence = %#v", finding.Evidence)
	}
}

func TestRenderTerminalReviewResult(t *testing.T) {
	line3 := 3
	line11 := 11
	line20 := 20
	filesScanned := 1
	result := ReviewResult{
		Adversary: ReviewAdversary{Name: "dockerfile"},
		Target:    ReviewTarget{Repository: "/Users/marc/go/src/github.com/adversarylabs/adversarylabs", FilesScanned: &filesScanned},
		Assessment: &Assessment{
			Risk:    "low",
			Summary: "This is a well-structured multi-stage Node Dockerfile with one low-risk reproducibility concern.",
		},
		Positives: []Note{
			{Key: "dependency-build-runtime", Summary: "Dependency installation, build, and runtime are separated cleanly."},
			{Key: "runtime-artifacts", Summary: "The runtime stage copies built artifacts from the builder stage."},
		},
		Findings: []Finding{
			{
				ID:           "base-image",
				Title:        "Base images are not pinned by digest",
				Category:     "supply-chain",
				Severity:     "low",
				Confidence:   "high",
				Summary:      "Three stages reference node:22-bookworm-slim by tag rather than digest.",
				WhyItMatters: "Container image tags are mutable and can resolve to different image contents over time.",
				Impact:       "Future builds may consume different base images even when the Dockerfile itself has not changed.",
				Evidence: []Evidence{
					{File: "Dockerfile", Line: &line3, Message: "deps stage", Snippet: "FROM node:22-bookworm-slim AS deps", Metadata: json.RawMessage(`{"image":"node:22-bookworm-slim"}`)},
					{File: "Dockerfile", Line: &line11, Message: "builder stage", Snippet: "FROM node:22-bookworm-slim AS builder"},
					{File: "Dockerfile", Line: &line20, Message: "runner stage", Snippet: "FROM node:22-bookworm-slim AS runner"},
				},
				Recommendation: "Pin production base images using image:tag@sha256:<digest> when reproducibility and auditability matter.\n\nUse Renovate or Dependabot to keep pinned digests current.",
				Remediation:    &Remediation{Estimate: "10-20 minutes", Complexity: "small"},
			},
		},
		Opinion:    &Opinion{Summary: "I would ship this Dockerfile as-is. Digest pinning is the only material improvement identified."},
		Suppressed: Suppressed{},
	}

	var b strings.Builder
	if err := RenderTerminal(&b, result); err != nil {
		t.Fatal(err)
	}
	got := b.String()
	for _, want := range []string{
		"Adversary: dockerfile",
		"Overall assessment",
		"Positive signals",
		"Overall opinion",
		"Review complete",
		"Files scanned: 1",
		"Category: supply-chain",
		"Confidence: high",
		"Why it matters",
		"Impact",
		"- Dockerfile:3 - deps stage",
		"  FROM node:22-bookworm-slim AS deps",
		"Estimated remediation",
		"10-20 minutes",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("terminal output missing %q in:\n%s", want, got)
		}
	}
	for _, notWant := range []string{`"image"`, "lockfilePresent", "Evidence:"} {
		if strings.Contains(got, notWant) {
			t.Fatalf("terminal output contains raw/legacy text %q in:\n%s", notWant, got)
		}
	}
}

func TestDecodeRunEnvelopeRejectsUnversionedPayload(t *testing.T) {
	_, err := DecodeRunEnvelope([]byte(`{"findings":[]}`))
	if err == nil {
		t.Fatal("expected error")
	}
}
