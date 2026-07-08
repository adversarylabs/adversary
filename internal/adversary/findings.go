package adversary

import (
	"encoding/json"
	"fmt"
	"io"
)

const FindingsSchemaVersion = "adversary.findings.v1"

type FindingsOutput struct {
	SchemaVersion string       `json:"schema_version"`
	Adversary     string       `json:"adversary"`
	Summary       *ScanSummary `json:"summary,omitempty"`
	Findings      []Finding    `json:"findings"`
}

type ScanSummary struct {
	FilesScanned  int `json:"files_scanned"`
	RulesExecuted int `json:"rules_executed"`
}

type Finding struct {
	ID             string `json:"id"`
	RuleID         string `json:"rule_id"`
	Severity       string `json:"severity"`
	Title          string `json:"title"`
	Message        string `json:"message"`
	File           string `json:"file"`
	Path           string `json:"path"`
	Line           int    `json:"line"`
	Evidence       string `json:"evidence"`
	Recommendation string `json:"recommendation"`
}

func ParseFindings(data []byte) (FindingsOutput, error) {
	var output FindingsOutput
	if err := json.Unmarshal(data, &output); err != nil {
		return FindingsOutput{}, err
	}
	if output.SchemaVersion != FindingsSchemaVersion {
		return FindingsOutput{}, fmt.Errorf("unsupported findings schema_version %q", output.SchemaVersion)
	}
	return output, nil
}

func RenderTextFindings(w io.Writer, output FindingsOutput) error {
	summary := output.ScanSummary()
	if _, err := fmt.Fprintln(w, "Scan complete"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "Files scanned: %d\n", summary.FilesScanned); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "Rules executed: %d\n", summary.RulesExecuted); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "Findings: %d\n", len(output.Findings)); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w); err != nil {
		return err
	}

	if len(output.Findings) == 0 {
		_, err := fmt.Fprintln(w, "No findings.")
		return err
	}

	for i, finding := range output.Findings {
		if i > 0 {
			if _, err := fmt.Fprintln(w); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintf(w, "[%s] %s\n", finding.Severity, finding.Title); err != nil {
			return err
		}
		location := finding.Location()
		if location != "" {
			if finding.Line > 0 {
				if _, err := fmt.Fprintf(w, "%s:%d\n", location, finding.Line); err != nil {
					return err
				}
			} else if _, err := fmt.Fprintln(w, location); err != nil {
				return err
			}
		}
		if finding.Message != "" {
			if _, err := fmt.Fprintf(w, "Message: %s\n", finding.Message); err != nil {
				return err
			}
		}
		if finding.Evidence != "" {
			if _, err := fmt.Fprintf(w, "Evidence: %s\n", finding.Evidence); err != nil {
				return err
			}
		}
		if finding.Recommendation != "" {
			if _, err := fmt.Fprintf(w, "Recommendation: %s\n", finding.Recommendation); err != nil {
				return err
			}
		}
	}
	return nil
}

func (output FindingsOutput) ScanSummary() ScanSummary {
	if output.Summary != nil {
		return *output.Summary
	}
	files := map[string]struct{}{}
	for _, finding := range output.Findings {
		if location := finding.Location(); location != "" {
			files[location] = struct{}{}
		}
	}
	return ScanSummary{
		FilesScanned:  len(files),
		RulesExecuted: 0,
	}
}

func (finding Finding) Location() string {
	if finding.File != "" {
		return finding.File
	}
	return finding.Path
}
