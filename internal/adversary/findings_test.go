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

func TestParseFindingsWithRuleIDPathAndMessage(t *testing.T) {
	data := []byte(`{
  "schema_version": "adversary.findings.v1",
  "adversary": "adversarylabs/dockerfile",
  "findings": [
    {
      "rule_id": "docker.user.root",
      "severity": "medium",
      "title": "Container runs as root",
      "message": "Dockerfile explicitly switches to the root user.",
      "path": "Dockerfile.root",
      "line": 2
    }
  ]
}`)
	output, err := ParseFindings(data)
	if err != nil {
		t.Fatal(err)
	}
	if output.Findings[0].RuleID != "docker.user.root" {
		t.Fatalf("RuleID = %q", output.Findings[0].RuleID)
	}
	if output.Findings[0].Location() != "Dockerfile.root" {
		t.Fatalf("Location = %q", output.Findings[0].Location())
	}
}

func TestRenderTextFindings(t *testing.T) {
	var b strings.Builder
	err := RenderTextFindings(&b, FindingsOutput{
		SchemaVersion: FindingsSchemaVersion,
		Adversary:     "adversarylabs/github-actions",
		Summary: &ScanSummary{
			FilesScanned:  5,
			RulesExecuted: 12,
		},
		Findings: []Finding{
			{
				Severity: "high",
				Title:    "Workflow uses unpinned third-party action",
				Path:     ".github/workflows/test.yml",
				Line:     12,
				Message:  "Action reference is not pinned.",
				Evidence: "uses: actions/checkout@v4",
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	got := b.String()
	for _, want := range []string{
		"Scan complete",
		"Files scanned: 5",
		"Rules executed: 12",
		"Findings: 1",
		"[high] Workflow uses unpinned third-party action",
		".github/workflows/test.yml:12",
		"Message: Action reference is not pinned.",
		"Evidence: uses: actions/checkout@v4",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("rendered findings missing %q in:\n%s", want, got)
		}
	}
}

func TestRenderTextFindingsNoFindings(t *testing.T) {
	var b strings.Builder
	err := RenderTextFindings(&b, FindingsOutput{
		SchemaVersion: FindingsSchemaVersion,
		Adversary:     "adversarylabs/github-actions",
		Summary: &ScanSummary{
			FilesScanned:  1,
			RulesExecuted: 3,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	got := b.String()
	for _, want := range []string{
		"Scan complete",
		"Files scanned: 1",
		"Rules executed: 3",
		"Findings: 0",
		"No findings.",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("rendered findings missing %q in:\n%s", want, got)
		}
	}
}
