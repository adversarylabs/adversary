package review

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode"
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

func TestRenderTerminalSuppressionContract(t *testing.T) {
	finding := func(id, title string) Finding {
		return Finding{ID: id, Title: title, Category: "policy", Severity: "low", Confidence: "high", Summary: title + " summary", Evidence: []Evidence{}}
	}
	tests := []struct {
		name    string
		result  ReviewResult
		want    []string
		notWant []string
		order   []string
	}{
		{
			name:    "zero counts remain quiet",
			result:  ReviewResult{Findings: []Finding{}},
			notWant: []string{"Suppressed observations", "Suppressed findings", "reason unavailable"},
		},
		{
			name:    "observation count does not disclose details",
			result:  ReviewResult{Findings: []Finding{}, Suppressed: Suppressed{Observations: 3}},
			want:    []string{"Findings: 0", "Suppressed observations: 3"},
			notWant: []string{"Suppressed findings", "reason unavailable"},
		},
		{
			name:    "finding count without requested details",
			result:  ReviewResult{Findings: []Finding{}, Suppressed: Suppressed{Findings: 2}},
			want:    []string{"Findings: 0", "Suppressed findings: 2"},
			notWant: []string{"reason unavailable"},
		},
		{
			name: "included details preserve producer order and do not change visible total",
			result: ReviewResult{
				Findings:           []Finding{finding("visible", "Visible finding")},
				Suppressed:         Suppressed{Findings: 2},
				SuppressedFindings: []Finding{finding("z", "Producer first"), finding("a", "Producer second")},
			},
			want:  []string{"Findings: 1", "Suppressed findings: 2", "[low; suppressed; reason unavailable] Producer first", "[low; suppressed; reason unavailable] Producer second"},
			order: []string{"Visible finding", "Producer first", "Producer second"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out strings.Builder
			if err := RenderTerminal(&out, tt.result); err != nil {
				t.Fatal(err)
			}
			got := out.String()
			for _, want := range tt.want {
				if !strings.Contains(got, want) {
					t.Errorf("missing %q in:\n%s", want, got)
				}
			}
			for _, notWant := range tt.notWant {
				if strings.Contains(got, notWant) {
					t.Errorf("unexpected %q in:\n%s", notWant, got)
				}
			}
			position := -1
			for _, want := range tt.order {
				next := strings.Index(got, want)
				if next <= position {
					t.Errorf("%q is not in producer order in:\n%s", want, got)
				}
				position = next
			}
		})
	}
}

func TestRenderTerminalSuppressionGoldens(t *testing.T) {
	finding := func(id, title string) Finding {
		return Finding{ID: id, Title: title, Category: "policy", Severity: "low", Confidence: "high", Summary: title + " summary", Evidence: []Evidence{}}
	}
	tests := []struct {
		name   string
		result ReviewResult
	}{
		{"counts", ReviewResult{Findings: []Finding{}, Suppressed: Suppressed{Observations: 3, Findings: 2}}},
		{"included", ReviewResult{Findings: []Finding{}, Suppressed: Suppressed{Findings: 2}, SuppressedFindings: []Finding{finding("z", "Producer first"), finding("a", "Producer second")}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out strings.Builder
			if err := RenderTerminal(&out, tt.result); err != nil {
				t.Fatal(err)
			}
			want, err := os.ReadFile(filepath.Join("testdata", "suppression-"+tt.name+".golden"))
			if err != nil {
				t.Fatal(err)
			}
			if out.String() != string(want) {
				t.Fatalf("output changed\n--- want\n%s--- got\n%s", want, out.String())
			}
			if strings.Contains(out.String(), "\x1b[") {
				t.Fatal("terminal contract emitted ANSI color")
			}
		})
	}
}

func TestRenderTerminalSanitizesUntrustedProtocolStringsGolden(t *testing.T) {
	result := ReviewResult{
		Adversary:    ReviewAdversary{Name: "alpha\x1b[2J\rOVER"},
		Target:       ReviewTarget{Repository: "repo\u202etxt\u2028next"},
		Assessment:   &Assessment{Risk: "low", Summary: "first\rOVER\x1b[2J\n\nsecond\x00tail"},
		Positives:    []Note{{Key: "unused", Summary: "positive\nINJECT"}},
		Observations: []Note{{Key: "unused", Summary: "observe\u0085INJECT"}},
		Findings: []Finding{{
			ID: "not-rendered\x1b", Title: "title\rOVER", Category: "cat\u2066evil", Severity: "low\x1b[31m", Confidence: "high\tINJECT",
			Summary: "line one\rOVER\x1b[2J\n\nline two\u202ehidden", Evidence: []Evidence{{File: "file\rOVER", Message: "message\x1b[2J", Snippet: "snippet\nINJECT"}},
			Recommendation: "recommend\u009b31m", Remediation: &Remediation{Estimate: "soon\rOVER"},
		}},
		Opinion: &Opinion{Summary: "ship\x07bell"},
	}
	var out strings.Builder
	if err := RenderTerminal(&out, result); err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(filepath.Join("testdata", "terminal-sanitization.golden"))
	if err != nil {
		t.Fatal(err)
	}
	if out.String() != string(want) {
		t.Fatalf("output changed\n--- want\n%s--- got\n%s", want, out.String())
	}
	for _, r := range out.String() {
		if r != '\n' && (unicode.IsControl(r) || isTerminalDirectionControl(r) || unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r)) {
			t.Fatalf("unsafe terminal rune U+%04X in %q", r, out.String())
		}
	}
}

func TestRenderTerminalPreservesLegitimateUnicodeFormatCharacters(t *testing.T) {
	const emoji = "developer 👩‍💻"
	const persian = "می‌روم"
	const bom = "before\ufeffafter"
	result := ReviewResult{
		Adversary:    ReviewAdversary{Name: emoji},
		Observations: []Note{{Key: "persian", Summary: persian}, {Key: "bom", Summary: bom}},
		Findings:     []Finding{},
	}
	var out strings.Builder
	if err := RenderTerminal(&out, result); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{emoji, persian, bom} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("legitimate Unicode %q changed in %q", want, out.String())
		}
		if sanitizeTerminalInline(want) != want {
			t.Fatalf("inline sanitizer changed %q", want)
		}
	}
}

func TestDecodeRunEnvelopeRejectsUnversionedPayload(t *testing.T) {
	_, err := DecodeRunEnvelope([]byte(`{"findings":[]}`))
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestDecodeRunEnvelopeSharedFixture(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "schema", "fixtures", "adversary.review.v1.valid.json"))
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := DecodeRunEnvelope(data)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(envelope.Result.SuppressedFindings); got != 1 {
		t.Fatalf("SuppressedFindings len = %d", got)
	}
}

func TestDecodeRunEnvelopeRejectsInvalidContracts(t *testing.T) {
	tests := map[string]string{
		"unknown field":             `{"protocolVersion":1,"extra":true,"result":{}}`,
		"trailing JSON":             `{"protocolVersion":1,"result":{}} {}`,
		"missing required arrays":   `{"protocolVersion":1,"result":{"adversary":{"name":"test"},"target":{},"suppressed":{"observations":0,"findings":0}}}`,
		"missing suppressed counts": `{"protocolVersion":1,"result":{"adversary":{"name":"test"},"target":{},"positives":[],"observations":[],"findings":[],"suppressed":{}}}`,
		"unsupported severity":      `{"protocolVersion":1,"result":{"adversary":{"name":"test"},"target":{},"positives":[],"observations":[],"findings":[{"id":"x","title":"x","category":"test","severity":"urgent","confidence":"high","summary":"x","evidence":[]}],"suppressed":{"observations":0,"findings":0}}}`,
		"suppressed count mismatch": `{"protocolVersion":1,"result":{"adversary":{"name":"test"},"target":{},"positives":[],"observations":[],"findings":[],"suppressed":{"observations":0,"findings":1},"suppressedFindings":[]}}`,
	}
	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeRunEnvelope([]byte(data)); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestDecodeRunEnvelopeRejectsSharedInvalidFixtures(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "schema", "fixtures", "adversary.review.v1.invalid.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixtures []struct {
		Name     string          `json:"name"`
		Envelope json.RawMessage `json:"envelope"`
	}
	if err := json.Unmarshal(data, &fixtures); err != nil {
		t.Fatal(err)
	}
	for _, fixture := range fixtures {
		t.Run(fixture.Name, func(t *testing.T) {
			if _, err := DecodeRunEnvelope(fixture.Envelope); err == nil {
				t.Fatal("expected shared invalid fixture to be rejected")
			}
		})
	}
}

func TestProtocolSchemasAreValidJSONAndSDKCopiesMatch(t *testing.T) {
	for _, name := range []string{"adversary.input.v1.schema.json", "adversary.review.v1.schema.json"} {
		canonical, err := os.ReadFile(filepath.Join("..", "..", "schema", name))
		if err != nil {
			t.Fatal(err)
		}
		if !json.Valid(canonical) {
			t.Fatalf("schema/%s is not valid JSON", name)
		}
		vendored, err := os.ReadFile(filepath.Join("..", "..", "templates", "typescript", "vendor", "adversary-sdk", "schemas", name))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(canonical, vendored) {
			t.Fatalf("vendored SDK schema %s differs from canonical schema", name)
		}
	}
}

func TestCanonicalEnvelopePreservesSharedProducerOrder(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "schema", "fixtures", "adversary.review.v1.order.json"))
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := DecodeRunEnvelope(data)
	if err != nil {
		t.Fatal(err)
	}
	if encoded := EncodeEnvelope(envelope.Result); string(encoded) != strings.TrimSpace(string(data)) {
		t.Fatalf("canonical encoding reordered shared fixture:\n%s", encoded)
	}
}
