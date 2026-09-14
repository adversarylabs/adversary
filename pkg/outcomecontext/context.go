// Package outcomecontext defines bounded, source-attributed context used by
// adversaries to infer what a software change is intended to accomplish.
package outcomecontext

import (
	"fmt"
	"strings"
	"unicode"
)

const (
	SchemaVersion           = "adversary.outcome-context.v1"
	MaxSourceCharacters     = 32 << 10
	MaxProviderCharacters   = 100
	MaxRepositoryCharacters = 500
	MaxIntentTextCharacters = 500
)

type Context struct {
	SchemaVersion string   `json:"schema_version"`
	Subject       Subject  `json:"subject"`
	Sources       []Source `json:"sources"`
	Intent        Intent   `json:"intent"`
}

type Subject struct {
	Provider    string `json:"provider"`
	Repository  string `json:"repository"`
	PullRequest int    `json:"pull_request"`
}

type Source struct {
	Kind string `json:"kind"`
	Text string `json:"text"`
}

type Intent struct {
	Objective          string   `json:"objective"`
	Confidence         string   `json:"confidence"`
	ExpectedEffects    []string `json:"expected_effects"`
	MustPreserve       []string `json:"must_preserve"`
	AffectedBoundaries []string `json:"affected_boundaries"`
	Ambiguities        []string `json:"ambiguities"`
}

// GitHubPullRequest creates context from metadata already fetched to resolve a
// GitHub review. Empty source text is omitted.
func GitHubPullRequest(repository string, number int, title, body string) *Context {
	repository = trimContextSpace(repository)
	if repository == "" || number < 1 || runeLen(repository) > MaxRepositoryCharacters {
		return nil
	}
	sources := make([]Source, 0, 2)
	if title = normalize(title); title != "" {
		sources = append(sources, Source{Kind: "pull_request_title", Text: title})
	}
	if body = normalize(body); body != "" {
		sources = append(sources, Source{Kind: "pull_request_body", Text: body})
	}
	if len(sources) == 0 {
		return nil
	}
	objective := title
	if objective == "" {
		objective = firstLine(body)
	}
	return &Context{
		SchemaVersion: SchemaVersion,
		Subject:       Subject{Provider: "github", Repository: repository, PullRequest: number},
		Sources:       sources,
		Intent: Intent{
			Objective:          normalizeTo(objective, 500),
			Confidence:         "low",
			ExpectedEffects:    []string{},
			MustPreserve:       []string{},
			AffectedBoundaries: []string{},
			Ambiguities:        []string{"Intent has not been model-inferred; objective is derived from PR metadata."},
		},
	}
}

func (c Context) Validate() error {
	if c.SchemaVersion != SchemaVersion {
		return fmt.Errorf("outcome context schema_version must be %q", SchemaVersion)
	}
	if c.Subject.Provider != "github" {
		return fmt.Errorf("outcome context subject provider must be %q", "github")
	}
	if !hasContextText(c.Subject.Repository) {
		return fmt.Errorf("outcome context subject repository must not be empty")
	}
	if runeLen(c.Subject.Repository) > MaxRepositoryCharacters {
		return fmt.Errorf("outcome context subject repository exceeds %d characters", MaxRepositoryCharacters)
	}
	if c.Subject.PullRequest < 1 {
		return fmt.Errorf("outcome context subject pull_request must be positive")
	}
	if len(c.Sources) == 0 || len(c.Sources) > 2 {
		return fmt.Errorf("outcome context requires between one and two sources")
	}
	seen := map[string]bool{}
	for i, source := range c.Sources {
		if source.Kind != "pull_request_title" && source.Kind != "pull_request_body" {
			return fmt.Errorf("outcome context source %d has unsupported kind %q", i, source.Kind)
		}
		if !hasContextText(source.Text) {
			return fmt.Errorf("outcome context source %d text must not be empty", i)
		}
		if runeLen(source.Text) > MaxSourceCharacters {
			return fmt.Errorf("outcome context source %d exceeds %d characters", i, MaxSourceCharacters)
		}
		if seen[source.Kind] {
			return fmt.Errorf("outcome context source kind %q is duplicated", source.Kind)
		}
		seen[source.Kind] = true
	}
	if !hasContextText(c.Intent.Objective) {
		return fmt.Errorf("outcome context intent objective must not be empty")
	}
	if runeLen(c.Intent.Objective) > MaxIntentTextCharacters {
		return fmt.Errorf("outcome context intent objective exceeds %d characters", MaxIntentTextCharacters)
	}
	if c.Intent.Confidence != "low" && c.Intent.Confidence != "medium" && c.Intent.Confidence != "high" {
		return fmt.Errorf("outcome context intent confidence %q is invalid", c.Intent.Confidence)
	}
	for name, values := range map[string][]string{
		"expected_effects":    c.Intent.ExpectedEffects,
		"must_preserve":       c.Intent.MustPreserve,
		"affected_boundaries": c.Intent.AffectedBoundaries,
		"ambiguities":         c.Intent.Ambiguities,
	} {
		if values == nil {
			return fmt.Errorf("outcome context intent %s is required", name)
		}
		if len(values) > 12 {
			return fmt.Errorf("outcome context intent %s exceeds 12 items", name)
		}
		for _, value := range values {
			if !hasContextText(value) {
				return fmt.Errorf("outcome context intent %s contains empty text", name)
			}
			if runeLen(value) > MaxIntentTextCharacters {
				return fmt.Errorf("outcome context intent %s text exceeds %d characters", name, MaxIntentTextCharacters)
			}
		}
	}
	return nil
}

func ReviewedAs(c *Context) string {
	if c == nil || !hasContextText(c.Intent.Objective) {
		return ""
	}
	return "Reviewed as: " + strings.Join(strings.Fields(c.Intent.Objective), " ")
}

func firstLine(value string) string {
	for _, line := range strings.Split(value, "\n") {
		if line = trimContextSpace(line); line != "" {
			return line
		}
	}
	return ""
}

func normalize(value string) string {
	return normalizeTo(value, MaxSourceCharacters)
}

func normalizeTo(value string, maximum int) string {
	value = trimContextSpace(value)
	if maximum <= 0 {
		return ""
	}
	runes := []rune(value)
	if len(runes) > maximum {
		value = string(runes[:maximum])
	}
	return value
}

func runeLen(value string) int { return len([]rune(value)) }

// JSON Schema regular expressions treat U+FEFF as whitespace. Go's
// strings.TrimSpace does not, so keep the runtime's non-empty checks aligned.
func isContextSpace(r rune) bool { return unicode.IsSpace(r) || r == '\uFEFF' }

func trimContextSpace(value string) string { return strings.TrimFunc(value, isContextSpace) }

func hasContextText(value string) bool {
	return strings.IndexFunc(value, func(r rune) bool { return !isContextSpace(r) }) >= 0
}
