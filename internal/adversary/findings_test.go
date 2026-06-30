package adversary

import (
	"strings"
	"testing"
)

func TestParseFindings(t *testing.T) {
	data := []byte(`{
  "schema_version": "adversary.findings.v1",
  "adversary": "adversarylabs/github-actions",
  "findings": [
    {
      "id": "GHA-001",
      "severity": "high",
      "title": "Workflow uses unpinned third-party action",
      "file": ".github/workflows/test.yml",
      "line": 12,
      "evidence": "uses: actions/checkout@v4",
      "recommendation": "Pin third-party actions to a full commit SHA."
    }
  ]
}`)
	output, err := ParseFindings(data)
	if err != nil {
		t.Fatal(err)
	}
	if output.Adversary != "adversarylabs/github-actions" {
		t.Fatalf("Adversary = %q", output.Adversary)
	}
	if len(output.Findings) != 1 {
		t.Fatalf("Findings len = %d", len(output.Findings))
	}
	if output.Findings[0].Severity != "high" {
		t.Fatalf("Severity = %q", output.Findings[0].Severity)
	}
}

func TestRenderTextFindings(t *testing.T) {
	var b strings.Builder
	err := RenderTextFindings(&b, FindingsOutput{
		SchemaVersion: FindingsSchemaVersion,
		Adversary:     "adversarylabs/github-actions",
		Findings: []Finding{
			{
				Severity:       "high",
				Title:          "Workflow uses unpinned third-party action",
				File:           ".github/workflows/test.yml",
				Line:           12,
				Evidence:       "uses: actions/checkout@v4",
				Recommendation: "Pin third-party actions to a full commit SHA.",
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	got := b.String()
	for _, want := range []string{
		"[high] Workflow uses unpinned third-party action",
		".github/workflows/test.yml:12",
		"Evidence: uses: actions/checkout@v4",
		"Recommendation: Pin third-party actions to a full commit SHA.",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("rendered findings missing %q in:\n%s", want, got)
		}
	}
}
