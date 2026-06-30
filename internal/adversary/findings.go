package adversary

import (
	"encoding/json"
	"fmt"
	"io"
)

const FindingsSchemaVersion = "adversary.findings.v1"

type FindingsOutput struct {
	SchemaVersion string    `json:"schema_version"`
	Adversary     string    `json:"adversary"`
	Findings      []Finding `json:"findings"`
}

type Finding struct {
	ID             string `json:"id"`
	Severity       string `json:"severity"`
	Title          string `json:"title"`
	File           string `json:"file"`
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
		if finding.File != "" {
			if finding.Line > 0 {
				if _, err := fmt.Fprintf(w, "%s:%d\n", finding.File, finding.Line); err != nil {
					return err
				}
			} else if _, err := fmt.Fprintln(w, finding.File); err != nil {
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
