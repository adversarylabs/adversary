package githubreview

import (
	"fmt"
	"path"
	"strings"

	"github.com/adversarylabs/adversary/pkg/review"
)

// ProjectOptions controls CommentPlan construction.
type ProjectOptions struct {
	Repository  string // owner/name when known
	PullRequest int
	MinSeverity string // empty = all
	Voice       VoiceInfo
}

// ProjectFindings builds a CommentPlan from one or more run envelopes.
// Visible findings only; never observations/positives/suppressedFindings.
func ProjectFindings(envelopes []NamedEnvelope, opts ProjectOptions) CommentPlan {
	plan := CommentPlan{
		SchemaVersion: 1,
		Source:        "adversary.review.v1",
		Repository:    opts.Repository,
		PullRequest:   opts.PullRequest,
		MinSeverity:   strings.TrimSpace(opts.MinSeverity),
		Voice:         opts.Voice,
		Comments:      []PlannedComment{},
		Skipped:       []SkippedFinding{},
	}
	if plan.Voice.Source == "" {
		plan.Voice.Source = "cli_default"
	}

	minRank := -1
	if plan.MinSeverity != "" {
		minRank = SeverityRank(plan.MinSeverity)
	}

	var assessmentBits []string
	for _, ne := range envelopes {
		res := ne.Envelope.Result
		adv := strings.TrimSpace(ne.Adversary)
		if adv == "" {
			adv = res.Adversary.Name
		}
		if res.Assessment != nil {
			bit := strings.TrimSpace(res.Assessment.Risk)
			if res.Assessment.Summary != "" {
				if bit != "" {
					bit += ": "
				}
				bit += strings.TrimSpace(res.Assessment.Summary)
			}
			if bit != "" {
				assessmentBits = append(assessmentBits, fmt.Sprintf("[%s] %s", adv, bit))
			}
		}
		if res.Opinion != nil && strings.TrimSpace(res.Opinion.Summary) != "" {
			assessmentBits = append(assessmentBits, fmt.Sprintf("[%s] %s", adv, strings.TrimSpace(res.Opinion.Summary)))
		}
		for _, f := range res.Findings {
			plan.Summary.FindingsSeen++
			if minRank >= 0 && SeverityRank(f.Severity) < minRank {
				plan.Skipped = append(plan.Skipped, SkippedFinding{
					FindingID: f.ID, Adversary: adv, Reason: "below_min_severity", Severity: f.Severity,
				})
				continue
			}
			pc := projectOne(adv, f)
			plan.Comments = append(plan.Comments, pc)
		}
	}

	if len(assessmentBits) > 0 {
		plan.ReviewBody = strings.Join(assessmentBits, "\n\n")
	}
	plan.Summary.Comments = len(plan.Comments)
	plan.Summary.Skipped = len(plan.Skipped)
	for _, c := range plan.Comments {
		switch c.Placement {
		case "inline":
			plan.Summary.Inline++
		case "review_body":
			plan.Summary.ReviewBody++
		case "unplaceable":
			plan.Summary.Unplaceable++
		}
	}
	return plan
}

func projectOne(adversary string, f review.Finding) PlannedComment {
	pathStr, line, endLine := primaryAnchor(f.Evidence)
	placement := "review_body"
	reason := ""
	if pathStr != "" {
		norm, err := normalizeRepoRelativePath(pathStr)
		if err != nil {
			placement = "unplaceable"
			reason = "invalid_path"
			pathStr = pathStr
		} else {
			pathStr = norm
			if line != nil {
				placement = "inline"
			} else {
				placement = "review_body"
				reason = "path_only"
			}
		}
	} else {
		placement = "review_body"
		reason = "no_evidence_path"
	}

	body := TemplateBody(adversary, f, pathStr, line)
	return PlannedComment{
		FindingID:       f.ID,
		Adversary:       adversary,
		Severity:        f.Severity,
		Confidence:      f.Confidence,
		Title:           f.Title,
		Body:            body,
		BodySource:      "template",
		Anchor:          Anchor{Path: pathStr, Line: line, EndLine: endLine},
		Placement:       placement,
		PlacementReason: reason,
	}
}

func primaryAnchor(ev []review.Evidence) (file string, line, endLine *int) {
	for _, e := range ev {
		if strings.TrimSpace(e.File) == "" {
			continue
		}
		if e.Line != nil {
			return e.File, e.Line, e.EndLine
		}
		if file == "" {
			file = e.File
		}
	}
	return file, nil, nil
}

func normalizeRepoRelativePath(p string) (string, error) {
	p = strings.TrimSpace(p)
	if p == "" {
		return "", fmt.Errorf("empty path")
	}
	p = strings.ReplaceAll(p, "\\", "/")
	for strings.HasPrefix(p, "./") {
		p = strings.TrimPrefix(p, "./")
	}
	if path.IsAbs(p) || strings.HasPrefix(p, "/") || (len(p) > 1 && p[1] == ':') {
		return "", fmt.Errorf("absolute path")
	}
	if strings.Contains(p, "\x00") {
		return "", fmt.Errorf("nul in path")
	}
	cleaned := path.Clean(p)
	if cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", fmt.Errorf("path traversal")
	}
	for _, seg := range strings.Split(cleaned, "/") {
		if seg == ".." {
			return "", fmt.Errorf("path traversal")
		}
	}
	return cleaned, nil
}

// Marker builds the HTML comment fingerprint.
func Marker(adversary, findingID, pathStr string, line *int) string {
	loc := pathStr
	if line != nil {
		loc = fmt.Sprintf("%s:%d", pathStr, *line)
	}
	if loc == "" {
		loc = "none"
	}
	return fmt.Sprintf("<!-- adversary-review:v1 adversary=%s finding=%s loc=%s -->",
		sanitizeMarker(adversary), sanitizeMarker(findingID), sanitizeMarker(loc))
}

func sanitizeMarker(s string) string {
	s = strings.ReplaceAll(s, "-->", "")
	s = strings.Map(func(r rune) rune {
		if r < 32 {
			return -1
		}
		return r
	}, s)
	return strings.TrimSpace(s)
}
