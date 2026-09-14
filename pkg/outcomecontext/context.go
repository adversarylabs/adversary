// Package outcomecontext defines bounded, source-attributed context used by
// adversaries to infer what a software change is intended to accomplish.
package outcomecontext

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

const (
	SchemaVersion = "adversary.outcome-context.v1"
	MaxTextBytes  = 64 << 10
)

type Context struct {
	SchemaVersion string   `json:"schema_version"`
	Subject       Subject  `json:"subject"`
	Sources       []Source `json:"sources"`
}

type Subject struct {
	Provider    string `json:"provider,omitempty"`
	Repository  string `json:"repository,omitempty"`
	PullRequest int    `json:"pull_request,omitempty"`
}

type Source struct {
	Kind string `json:"kind"`
	Text string `json:"text"`
}

// GitHubPullRequest creates context from metadata already fetched to resolve a
// GitHub review. Empty source text is omitted.
func GitHubPullRequest(repository string, number int, title, body string) *Context {
	sources := make([]Source, 0, 2)
	if title = normalize(title); title != "" {
		sources = append(sources, Source{Kind: "pull_request_title", Text: title})
	}
	remaining := MaxTextBytes - len(title)
	if body = normalizeTo(body, remaining); body != "" {
		sources = append(sources, Source{Kind: "pull_request_body", Text: body})
	}
	if len(sources) == 0 {
		return nil
	}
	return &Context{
		SchemaVersion: SchemaVersion,
		Subject:       Subject{Provider: "github", Repository: strings.TrimSpace(repository), PullRequest: number},
		Sources:       sources,
	}
}

func (c Context) Validate() error {
	if c.SchemaVersion != SchemaVersion {
		return fmt.Errorf("outcome context schema_version must be %q", SchemaVersion)
	}
	if len(c.Sources) == 0 || len(c.Sources) > 2 {
		return fmt.Errorf("outcome context requires between one and two sources")
	}
	total := 0
	seen := map[string]bool{}
	for i, source := range c.Sources {
		if source.Kind != "pull_request_title" && source.Kind != "pull_request_body" {
			return fmt.Errorf("outcome context source %d has unsupported kind %q", i, source.Kind)
		}
		if strings.TrimSpace(source.Text) == "" {
			return fmt.Errorf("outcome context source %d text must not be empty", i)
		}
		if seen[source.Kind] {
			return fmt.Errorf("outcome context source kind %q is duplicated", source.Kind)
		}
		seen[source.Kind] = true
		total += len(source.Text)
	}
	if total > MaxTextBytes {
		return fmt.Errorf("outcome context source text exceeds %d bytes", MaxTextBytes)
	}
	return nil
}

func normalize(value string) string {
	return normalizeTo(value, MaxTextBytes)
}

func normalizeTo(value string, maximum int) string {
	value = strings.TrimSpace(value)
	if maximum <= 0 {
		return ""
	}
	if len(value) > maximum {
		value = value[:maximum]
		for !utf8.ValidString(value) {
			value = value[:len(value)-1]
		}
	}
	return value
}
