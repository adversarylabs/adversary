package githubreview

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/adversarylabs/adversary/internal/modelreview"
	"github.com/adversarylabs/adversary/pkg/review"
)

// bodyOutputSchema is the JSON schema providers must satisfy for voice rewrite.
const bodyOutputSchema = `{
  "type": "object",
  "additionalProperties": false,
  "required": ["body"],
  "properties": {
    "body": { "type": "string", "minLength": 1 }
  }
}`

// EnhanceOptions controls LLM comment rewrite.
type EnhanceOptions struct {
	Provider modelreview.Provider
	// VoicePrompt is the resolved CLI default or VOICE.md text.
	VoicePrompt string
	// MaxComments caps how many findings are sent to the model (0 = 20).
	MaxComments int
	// Timeout per finding (0 = 30s).
	Timeout time.Duration
}

// EnhanceBodies rewrites planned comment bodies via the model provider.
// On missing provider, empty prompt, or per-finding failure, leaves template body
// and bodySource "template". Successful rewrites set bodySource "llm" and append
// the tracking marker.
func EnhanceBodies(ctx context.Context, plan *CommentPlan, opts EnhanceOptions) {
	if plan == nil || opts.Provider == nil || strings.TrimSpace(opts.VoicePrompt) == "" {
		return
	}
	max := opts.MaxComments
	if max <= 0 {
		max = 20
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	schema := json.RawMessage(bodyOutputSchema)
	// Always wrap package/CLI voice so Example maintainer comments banks are used.
	prompt := BuildRewritePrompt(opts.VoicePrompt)
	enhanced := 0
	for i := range plan.Comments {
		if enhanced >= max {
			break
		}
		c := &plan.Comments[i]
		if c.Placement == "unplaceable" {
			continue
		}
		body, err := rewriteOne(ctx, opts.Provider, prompt, *c, schema, timeout)
		if err != nil || strings.TrimSpace(body) == "" {
			continue
		}
		c.Body = EnsureMarker(body, c.Adversary, c.FindingID, c.Anchor.Path, c.Anchor.Line)
		c.BodySource = "llm"
		enhanced++
	}
}

func rewriteOne(
	ctx context.Context,
	provider modelreview.Provider,
	rewritePrompt string,
	c PlannedComment,
	schema json.RawMessage,
	timeout time.Duration,
) (string, error) {
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	input, err := json.Marshal(map[string]any{
		"findingId":    c.FindingID,
		"adversary":    c.Adversary,
		"severity":     c.Severity,
		"confidence":   c.Confidence,
		"title":        c.Title,
		"path":         c.Anchor.Path,
		"line":         c.Anchor.Line,
		"endLine":      c.Anchor.EndLine,
		"templateBody": c.Body,
		// Hints for picking a few-shot subsection under the example bank.
		"exampleBankHint": exampleBankHint(c.Severity, c.Title, c.Body),
	})
	if err != nil {
		return "", err
	}
	result, err := provider.Review(reqCtx, modelreview.Request{
		ProtocolVersion: modelreview.ProtocolVersion,
		Prompt:          rewritePrompt,
		Input:           input,
		Schema:          schema,
		Budget: modelreview.Budget{
			MaximumOutputTokens: 1024,
			TimeoutMS:           int(timeout / time.Millisecond),
		},
	})
	if err != nil {
		return "", err
	}
	var out struct {
		Body string `json:"body"`
	}
	if err := json.Unmarshal(result.Output, &out); err != nil {
		return "", fmt.Errorf("decode rewrite body: %w", err)
	}
	body := strings.TrimSpace(out.Body)
	if body == "" {
		return "", fmt.Errorf("empty rewrite body")
	}
	// Reject overly long model dumps.
	if len(body) > 8<<10 {
		return "", fmt.Errorf("rewrite body exceeds 8KiB")
	}
	return body, nil
}

// FindingFromComment is a helper for tests building template then enhance.
func FindingFromComment(c PlannedComment) review.Finding {
	return review.Finding{
		ID: c.FindingID, Title: c.Title, Severity: c.Severity, Confidence: c.Confidence,
		Summary: c.Title, Category: "test", Evidence: []review.Evidence{},
	}
}

// exampleBankHint suggests which voice.md subsection few-shots to prefer.
func exampleBankHint(severity, title, body string) string {
	blob := strings.ToLower(severity + " " + title + " " + body)
	switch {
	case strings.Contains(blob, "ship") || strings.Contains(blob, "landable") ||
		strings.Contains(blob, "looks fine") || strings.Contains(blob, "no material"):
		return "Ship / OK"
	case severity == "info" || strings.Contains(blob, "nit") || strings.Contains(blob, "rename") ||
		strings.Contains(blob, "style") || strings.Contains(blob, "comment is stale"):
		return "Nits / style"
	case severity == "high" || severity == "critical" ||
		strings.Contains(blob, "race") || strings.Contains(blob, "wrong") ||
		strings.Contains(blob, "broken") || strings.Contains(blob, "leak") ||
		strings.Contains(blob, "corrupt"):
		return "Defects / correctness"
	default:
		return "Design / technical judgment"
	}
}
