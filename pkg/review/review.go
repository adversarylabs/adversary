package review

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"
	"unicode"
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
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return RunEnvelope{}, err
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return RunEnvelope{}, err
	}
	if envelope.ProtocolVersion != ProtocolVersion {
		return RunEnvelope{}, fmt.Errorf("unsupported adversary run protocolVersion %d", envelope.ProtocolVersion)
	}
	if err := validateRequiredReviewFields(data); err != nil {
		return RunEnvelope{}, err
	}
	if err := envelope.Result.validate(); err != nil {
		return RunEnvelope{}, fmt.Errorf("invalid adversary run result: %w", err)
	}
	return envelope, nil
}

func validateRequiredReviewFields(data []byte) error {
	var raw struct {
		Result map[string]json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	for _, field := range []string{"adversary", "target", "positives", "observations", "findings", "suppressed"} {
		if _, ok := raw.Result[field]; !ok {
			return fmt.Errorf("invalid adversary run result: %s is required", field)
		}
	}
	var suppressed map[string]json.RawMessage
	if err := json.Unmarshal(raw.Result["suppressed"], &suppressed); err != nil {
		return fmt.Errorf("invalid adversary run result: suppressed must be an object")
	}
	for _, field := range []string{"observations", "findings"} {
		if _, ok := suppressed[field]; !ok {
			return fmt.Errorf("invalid adversary run result: suppressed.%s is required", field)
		}
	}
	return nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra json.RawMessage
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("unexpected data after adversary run envelope")
		}
		return err
	}
	return nil
}

func (result ReviewResult) validate() error {
	if strings.TrimSpace(result.Adversary.Name) == "" {
		return fmt.Errorf("adversary.name must be a non-empty string")
	}
	if result.Target.FilesScanned != nil && *result.Target.FilesScanned < 0 {
		return fmt.Errorf("target.filesScanned must be non-negative")
	}
	if result.Positives == nil || result.Observations == nil || result.Findings == nil {
		return fmt.Errorf("positives, observations, and findings are required")
	}
	if result.Suppressed.Observations < 0 || result.Suppressed.Findings < 0 {
		return fmt.Errorf("suppressed counts must be non-negative")
	}
	if result.SuppressedFindings != nil && len(result.SuppressedFindings) != result.Suppressed.Findings {
		return fmt.Errorf("suppressed.findings must equal the number of suppressedFindings when included")
	}
	if result.Assessment != nil {
		if !slices.Contains([]string{"none", "low", "medium", "high", "critical"}, result.Assessment.Risk) {
			return fmt.Errorf("assessment.risk %q is not supported", result.Assessment.Risk)
		}
	}
	if result.Opinion != nil && strings.TrimSpace(result.Opinion.Summary) == "" {
		return fmt.Errorf("opinion.summary must be a non-empty string")
	}
	if result.Timing != nil && (result.Timing.BuildMS < 0 || result.Timing.StartupMS < 0 || result.Timing.ScanMS < 0 || result.Timing.TotalMS < 0) {
		return fmt.Errorf("timing values must be non-negative")
	}
	if err := validateNotes("positives", result.Positives); err != nil {
		return err
	}
	if err := validateNotes("observations", result.Observations); err != nil {
		return err
	}
	seen := make(map[string]struct{}, len(result.Findings)+len(result.SuppressedFindings))
	if err := validateFindings("findings", result.Findings, seen); err != nil {
		return err
	}
	return validateFindings("suppressedFindings", result.SuppressedFindings, seen)
}

func validateNotes(field string, notes []Note) error {
	for i, note := range notes {
		prefix := fmt.Sprintf("%s[%d]", field, i)
		if strings.TrimSpace(note.Key) == "" || strings.TrimSpace(note.Summary) == "" {
			return fmt.Errorf("%s.key and summary must be non-empty strings", prefix)
		}
		if err := validateMetadata(prefix+".metadata", note.Metadata); err != nil {
			return err
		}
		if err := validateEvidence(prefix+".evidence", note.Evidence); err != nil {
			return err
		}
	}
	return nil
}

func validateFindings(field string, findings []Finding, seen map[string]struct{}) error {
	for i, finding := range findings {
		prefix := fmt.Sprintf("%s[%d]", field, i)
		for name, value := range map[string]string{
			"id": finding.ID, "title": finding.Title, "category": finding.Category,
			"severity": finding.Severity, "confidence": finding.Confidence, "summary": finding.Summary,
		} {
			if strings.TrimSpace(value) == "" {
				return fmt.Errorf("%s.%s must be a non-empty string", prefix, name)
			}
		}
		if !slices.Contains([]string{"info", "low", "medium", "high", "critical"}, finding.Severity) {
			return fmt.Errorf("%s.severity %q is not supported", prefix, finding.Severity)
		}
		if !slices.Contains([]string{"low", "medium", "high"}, finding.Confidence) {
			return fmt.Errorf("%s.confidence %q is not supported", prefix, finding.Confidence)
		}
		if _, exists := seen[finding.ID]; exists {
			return fmt.Errorf("%s.id %q is duplicated", prefix, finding.ID)
		}
		seen[finding.ID] = struct{}{}
		if finding.Evidence == nil {
			return fmt.Errorf("%s.evidence is required", prefix)
		}
		if err := validateMetadata(prefix+".metadata", finding.Metadata); err != nil {
			return err
		}
		seenTags := make(map[string]struct{}, len(finding.Tags))
		for _, tag := range finding.Tags {
			if _, exists := seenTags[tag]; exists {
				return fmt.Errorf("%s.tags contains duplicate value %q", prefix, tag)
			}
			seenTags[tag] = struct{}{}
		}
		if err := validateEvidence(prefix+".evidence", finding.Evidence); err != nil {
			return err
		}
	}
	return nil
}

func validateEvidence(field string, evidence []Evidence) error {
	for i, item := range evidence {
		if err := validateMetadata(fmt.Sprintf("%s[%d].metadata", field, i), item.Metadata); err != nil {
			return err
		}
		if item.Line != nil && *item.Line < 1 {
			return fmt.Errorf("%s[%d].line must be positive", field, i)
		}
		if item.EndLine != nil {
			if *item.EndLine < 1 {
				return fmt.Errorf("%s[%d].endLine must be positive", field, i)
			}
			if item.Line == nil {
				return fmt.Errorf("%s[%d].endLine requires line", field, i)
			}
			if *item.EndLine < *item.Line {
				return fmt.Errorf("%s[%d].endLine must not precede line", field, i)
			}
		}
	}
	return nil
}

func validateMetadata(field string, metadata json.RawMessage) error {
	if len(metadata) == 0 {
		return nil
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(metadata, &object); err != nil || object == nil {
		return fmt.Errorf("%s must be an object", field)
	}
	return nil
}

func RenderTerminal(w io.Writer, result ReviewResult) error {
	var lines []string
	if result.Adversary.Name != "" {
		lines = append(lines, "Adversary: "+sanitizeTerminalInline(result.Adversary.Name))
	}
	if result.Target.Repository != "" {
		lines = append(lines, "Repository: "+sanitizeTerminalInline(result.Target.Repository))
	}
	if len(lines) > 0 {
		lines = append(lines, "")
	}

	if result.Assessment != nil {
		lines = append(lines, "Overall assessment", "")
		if result.Assessment.Risk != "" {
			lines = append(lines, "Risk: "+capitalize(sanitizeTerminalInline(result.Assessment.Risk)), "")
		}
		if result.Assessment.Summary != "" {
			appendParagraphs(&lines, result.Assessment.Summary)
		}
	}

	if len(result.Positives) > 0 {
		lines = append(lines, "Positive signals", "")
		for _, note := range result.Positives {
			lines = append(lines, "- "+sanitizeTerminalInline(note.Summary))
		}
		lines = append(lines, "")
	}

	if len(result.Observations) > 0 {
		lines = append(lines, "Observations", "")
		for _, note := range result.Observations {
			lines = append(lines, "- "+sanitizeTerminalInline(note.Summary))
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
	if result.Suppressed.Observations > 0 {
		lines = append(lines, fmt.Sprintf("Suppressed observations: %d", result.Suppressed.Observations))
	}
	if result.Suppressed.Findings > 0 {
		lines = append(lines, fmt.Sprintf("Suppressed findings: %d", result.Suppressed.Findings))
	}
	if result.Suppressed.Observations > 0 || result.Suppressed.Findings > 0 {
		lines = append(lines, "")
	}

	for _, finding := range result.Findings {
		appendTerminalFinding(&lines, finding, "")
	}

	for _, finding := range result.SuppressedFindings {
		appendTerminalFinding(&lines, finding, "suppressed; reason unavailable")
	}

	_, err := fmt.Fprintln(w, strings.TrimRight(strings.Join(lines, "\n"), "\n"))
	return err
}

func appendTerminalFinding(lines *[]string, finding Finding, qualifier string) {
	label := finding.Severity
	if qualifier != "" {
		label += "; " + qualifier
	}
	*lines = append(*lines, fmt.Sprintf("[%s] %s", sanitizeTerminalInline(label), sanitizeTerminalInline(finding.Title)))
	if location := firstEvidenceLocation(finding.Evidence); location != "" {
		*lines = append(*lines, location)
	}
	*lines = append(*lines, "")
	if finding.Category != "" {
		*lines = append(*lines, "Category: "+sanitizeTerminalInline(finding.Category))
	}
	if finding.Confidence != "" {
		*lines = append(*lines, "Confidence: "+sanitizeTerminalInline(finding.Confidence))
	}
	if finding.Category != "" || finding.Confidence != "" {
		*lines = append(*lines, "")
	}
	appendSection(lines, "Summary", finding.Summary)
	appendSection(lines, "Why it matters", finding.WhyItMatters)
	appendSection(lines, "Impact", finding.Impact)
	if len(finding.Evidence) > 0 {
		*lines = append(*lines, "Evidence", "")
		for _, evidence := range finding.Evidence {
			*lines = append(*lines, "- "+formatEvidence(evidence))
			if evidence.Snippet != "" {
				*lines = append(*lines, "  "+sanitizeTerminalInline(evidence.Snippet))
			}
		}
		*lines = append(*lines, "")
	}
	appendSection(lines, "Recommendation", finding.Recommendation)
	if finding.Remediation != nil {
		appendSection(lines, "Estimated remediation", finding.Remediation.Estimate)
	}
}

func appendSection(lines *[]string, heading, body string) {
	if body == "" {
		return
	}
	*lines = append(*lines, heading, "")
	appendParagraphs(lines, body)
}

func appendParagraphs(lines *[]string, body string) {
	body = sanitizeTerminalBody(body)
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
		return location + " - " + sanitizeTerminalInline(evidence.Message)
	}
	if location != "" {
		return location
	}
	if evidence.Message != "" {
		return sanitizeTerminalInline(evidence.Message)
	}
	if evidence.Snippet != "" {
		return sanitizeTerminalInline(evidence.Snippet)
	}
	return "Evidence"
}

func formatEvidenceLocation(evidence Evidence) string {
	if evidence.File == "" {
		return ""
	}
	if evidence.Line != nil && evidence.EndLine != nil {
		return fmt.Sprintf("%s:%d-%d", sanitizeTerminalInline(evidence.File), *evidence.Line, *evidence.EndLine)
	}
	if evidence.Line != nil {
		return fmt.Sprintf("%s:%d", sanitizeTerminalInline(evidence.File), *evidence.Line)
	}
	return sanitizeTerminalInline(evidence.File)
}

func sanitizeTerminalInline(value string) string { return sanitizeTerminal(value, false) }

func sanitizeTerminalBody(value string) string { return sanitizeTerminal(value, true) }

// sanitizeTerminal removes terminal control sequences at the final human-output
// boundary. JSON output deliberately retains the validated protocol strings.
// Body fields may retain LF for the renderer's explicit paragraph formatting;
// inline fields may not create additional terminal lines.
func sanitizeTerminal(value string, allowLF bool) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' && allowLF {
			return r
		}
		if r == '\r' || r == '\n' || unicode.IsControl(r) || isTerminalDirectionControl(r) || unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r) {
			return ' '
		}
		return r
	}, value)
}

func isTerminalDirectionControl(r rune) bool {
	return r == '\u061c' || r == '\u200e' || r == '\u200f' ||
		(r >= '\u202a' && r <= '\u202e') || (r >= '\u2066' && r <= '\u2069')
}

func capitalize(value string) string {
	if value == "" {
		return ""
	}
	runes := []rune(value)
	return strings.ToUpper(string(runes[0])) + string(runes[1:])
}

func EncodeEnvelope(result ReviewResult) []byte {
	data, _ := json.Marshal(RunEnvelope{ProtocolVersion: ProtocolVersion, Result: result})
	return bytes.TrimSpace(data)
}
