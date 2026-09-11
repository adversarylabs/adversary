package githubreview

import (
	"fmt"
	"net/url"
	"strings"
)

// ReviewMarker is provenance embedded in an Adversary GitHub review comment.
type ReviewMarker struct {
	Version        int    `json:"version"`
	Adversary      string `json:"adversary"`
	Package        string `json:"package"`
	PackageVersion string `json:"packageVersion,omitempty"`
	FindingID      string `json:"findingId"`
	RuleID         string `json:"ruleId,omitempty"`
	HeadSHA        string `json:"headSha,omitempty"`
	Location       string `json:"location,omitempty"`
}

// ParseMarker extracts the first supported adversary-review marker from body.
// V1 remains readable so replies to comments posted by older CLI releases can
// still be captured, although those records have less package provenance.
func ParseMarker(body string) (ReviewMarker, bool, error) {
	const prefix = "<!-- adversary-review:v"
	start := strings.Index(body, prefix)
	if start < 0 {
		return ReviewMarker{}, false, nil
	}
	endRel := strings.Index(body[start:], "-->")
	if endRel < 0 {
		return ReviewMarker{}, true, fmt.Errorf("unterminated adversary review marker")
	}
	marker := strings.TrimSpace(body[start+len("<!-- ") : start+endRel])
	fields := strings.Fields(marker)
	if len(fields) == 0 {
		return ReviewMarker{}, true, fmt.Errorf("empty adversary review marker")
	}
	var out ReviewMarker
	switch fields[0] {
	case "adversary-review:v1":
		out.Version = 1
	case "adversary-review:v2":
		out.Version = 2
	default:
		return ReviewMarker{}, true, fmt.Errorf("unsupported adversary review marker %q", fields[0])
	}
	values := map[string]string{}
	for _, field := range fields[1:] {
		key, value, ok := strings.Cut(field, "=")
		if !ok || key == "" {
			continue
		}
		decoded, err := url.QueryUnescape(value)
		if err != nil {
			return ReviewMarker{}, true, fmt.Errorf("decode marker field %q: %w", key, err)
		}
		values[key] = decoded
	}
	out.Adversary = values["adversary"]
	out.Package = values["package"]
	out.PackageVersion = values["version"]
	out.FindingID = values["finding"]
	out.RuleID = values["rule"]
	out.HeadSHA = values["head"]
	out.Location = values["loc"]
	if out.Adversary == "" || out.FindingID == "" {
		return ReviewMarker{}, true, fmt.Errorf("adversary review marker missing adversary or finding")
	}
	if out.Package == "" {
		out.Package = out.Adversary
	}
	return out, true, nil
}
