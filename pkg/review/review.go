package review

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

const ProtocolVersion = 1

type RunEnvelope struct {
	ProtocolVersion int          `json:"protocolVersion"`
	Result          ReviewResult `json:"result"`
}

type ReviewResult struct {
	Adversary          ReviewAdversary `json:"adversary"`
	Target             ReviewTarget    `json:"target"`
	Assessment         *Assessment     `json:"assessment,omitempty"`
	Positives          []Note          `json:"positives"`
	Observations       []Note          `json:"observations"`
	Findings           []Finding       `json:"findings"`
	Opinion            *Opinion        `json:"opinion,omitempty"`
	Suppressed         Suppressed      `json:"suppressed"`
	Timing             *Timing         `json:"timing,omitempty"`
	SuppressedFindings []Finding       `json:"suppressedFindings,omitempty"`
	RawObservations    json.RawMessage `json:"rawObservations,omitempty"`
}

type ReviewAdversary struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

type ReviewTarget struct {
	Repository   string `json:"repository,omitempty"`
	FilesScanned *int   `json:"filesScanned,omitempty"`
}

type Assessment struct {
	Risk    string `json:"risk"`
	Summary string `json:"summary,omitempty"`
}

type Note struct {
	Key      string          `json:"key"`
	Summary  string          `json:"summary"`
	Evidence []Evidence      `json:"evidence,omitempty"`
	Metadata json.RawMessage `json:"metadata,omitempty"`
}

type Opinion struct {
	Ship    *bool  `json:"ship,omitempty"`
	Summary string `json:"summary"`
}

type Suppressed struct {
	Observations int `json:"observations"`
	Findings     int `json:"findings"`
}

type Timing struct {
	BuildMS   int `json:"buildMs,omitempty"`
	StartupMS int `json:"startupMs,omitempty"`
	ScanMS    int `json:"scanMs,omitempty"`
	TotalMS   int `json:"totalMs,omitempty"`
}

type Finding struct {
	ID             string          `json:"id"`
	RuleID         string          `json:"ruleId,omitempty"`
	GroupKey       string          `json:"groupKey,omitempty"`
	Title          string          `json:"title"`
	Category       string          `json:"category"`
	Severity       string          `json:"severity"`
	Confidence     string          `json:"confidence"`
	Summary        string          `json:"summary"`
	WhyItMatters   string          `json:"whyItMatters,omitempty"`
	Impact         string          `json:"impact,omitempty"`
	Evidence       []Evidence      `json:"evidence"`
	Recommendation string          `json:"recommendation,omitempty"`
	Remediation    *Remediation    `json:"remediation,omitempty"`
	Tags           []string        `json:"tags,omitempty"`
	Metadata       json.RawMessage `json:"metadata,omitempty"`
}

type Evidence struct {
	File     string          `json:"file,omitempty"`
	Line     *int            `json:"line,omitempty"`
	EndLine  *int            `json:"endLine,omitempty"`
	Message  string          `json:"message,omitempty"`
	Snippet  string          `json:"snippet,omitempty"`
	Metadata json.RawMessage `json:"metadata,omitempty"`
}

type Remediation struct {
	Estimate   string `json:"estimate,omitempty"`
	Complexity string `json:"complexity,omitempty"`
}

func DecodeRunEnvelope(data []byte) (RunEnvelope, error) {
	var envelope RunEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return RunEnvelope{}, err
	}
	if envelope.ProtocolVersion != ProtocolVersion {
		return RunEnvelope{}, fmt.Errorf("unsupported adversary run protocolVersion %d", envelope.ProtocolVersion)
	}
	return envelope, nil
}

func RenderTerminal(w io.Writer, result ReviewResult) error {
	var lines []string
	if result.Adversary.Name != "" {
		lines = append(lines, "Adversary: "+result.Adversary.Name)
	}
	if result.Target.Repository != "" {
		lines = append(lines, "Repository: "+result.Target.Repository)
	}
	if len(lines) > 0 {
		lines = append(lines, "")
	}

	if result.Assessment != nil {
		lines = append(lines, "Overall assessment", "")
		if result.Assessment.Risk != "" {
			lines = append(lines, "Risk: "+capitalize(result.Assessment.Risk), "")
		}
		if result.Assessment.Summary != "" {
			appendParagraphs(&lines, result.Assessment.Summary)
		}
	}

	if len(result.Positives) > 0 {
		lines = append(lines, "Positive signals", "")
		for _, note := range result.Positives {
			lines = append(lines, "- "+note.Summary)
		}
		lines = append(lines, "")
	}

	if len(result.Observations) > 0 {
		lines = append(lines, "Observations", "")
		for _, note := range result.Observations {
			lines = append(lines, "- "+note.Summary)
		}
		lines = append(lines, "")
	}

	if result.Opinion != nil && result.Opinion.Summary != "" {
		lines = append(lines, "Overall opinion", "")
		appendParagraphs(&lines, result.Opinion.Summary)
	}

	lines = append(lines, "Review complete", "")
	if result.Target.FilesScanned != nil {
		lines = append(lines, fmt.Sprintf("Files scanned: %d", *result.Target.FilesScanned))
	}
	lines = append(lines, fmt.Sprintf("Findings: %d", len(result.Findings)), "")

	for _, finding := range result.Findings {
		lines = append(lines, fmt.Sprintf("[%s] %s", finding.Severity, finding.Title))
		if location := firstEvidenceLocation(finding.Evidence); location != "" {
			lines = append(lines, location)
		}
		lines = append(lines, "")
		if finding.Category != "" {
			lines = append(lines, "Category: "+finding.Category)
		}
		if finding.Confidence != "" {
			lines = append(lines, "Confidence: "+finding.Confidence)
		}
		if finding.Category != "" || finding.Confidence != "" {
			lines = append(lines, "")
		}
		appendSection(&lines, "Summary", finding.Summary)
		appendSection(&lines, "Why it matters", finding.WhyItMatters)
		appendSection(&lines, "Impact", finding.Impact)
		if len(finding.Evidence) > 0 {
			lines = append(lines, "Evidence", "")
			for _, evidence := range finding.Evidence {
				lines = append(lines, "- "+formatEvidence(evidence))
				if evidence.Snippet != "" {
					lines = append(lines, "  "+evidence.Snippet)
				}
			}
			lines = append(lines, "")
		}
		appendSection(&lines, "Recommendation", finding.Recommendation)
		if finding.Remediation != nil {
			appendSection(&lines, "Estimated remediation", finding.Remediation.Estimate)
		}
	}

	_, err := fmt.Fprintln(w, strings.TrimRight(strings.Join(lines, "\n"), "\n"))
	return err
}

func appendSection(lines *[]string, heading, body string) {
	if body == "" {
		return
	}
	*lines = append(*lines, heading, "")
	appendParagraphs(lines, body)
}

func appendParagraphs(lines *[]string, body string) {
	for _, paragraph := range strings.Split(body, "\n\n") {
		if strings.TrimSpace(paragraph) != "" {
			*lines = append(*lines, paragraph, "")
		}
	}
}

func firstEvidenceLocation(evidence []Evidence) string {
	for _, item := range evidence {
		if location := formatEvidenceLocation(item); location != "" {
			return location
		}
	}
	return ""
}

func formatEvidence(evidence Evidence) string {
	location := formatEvidenceLocation(evidence)
	if location != "" && evidence.Message != "" {
		return location + " - " + evidence.Message
	}
	if location != "" {
		return location
	}
	if evidence.Message != "" {
		return evidence.Message
	}
	if evidence.Snippet != "" {
		return evidence.Snippet
	}
	return "Evidence"
}

func formatEvidenceLocation(evidence Evidence) string {
	if evidence.File == "" {
		return ""
	}
	if evidence.Line != nil && evidence.EndLine != nil {
		return fmt.Sprintf("%s:%d-%d", evidence.File, *evidence.Line, *evidence.EndLine)
	}
	if evidence.Line != nil {
		return fmt.Sprintf("%s:%d", evidence.File, *evidence.Line)
	}
	return evidence.File
}

func capitalize(value string) string {
	if value == "" {
		return ""
	}
	return strings.ToUpper(value[:1]) + value[1:]
}

func EncodeEnvelope(result ReviewResult) []byte {
	data, _ := json.Marshal(RunEnvelope{ProtocolVersion: ProtocolVersion, Result: result})
	return bytes.TrimSpace(data)
}
