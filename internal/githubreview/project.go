package githubreview

import (
	"fmt"
	"net/url"
	"path"
	"strings"

	"github.com/adversarylabs/adversary/pkg/review"
)

// ProjectOptions controls CommentPlan construction.
type ProjectOptions struct {
	Repository  string // owner/name when known
	PullRequest int
	HeadSHA     string
	MinSeverity string // empty = all
	Voice       VoiceInfo
	OmitSummary bool // keep inline/body findings but omit aggregate assessment/opinion
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

	for _, ne := range envelopes {
		res := ne.Envelope.Result
		ref := strings.TrimSpace(ne.Adversary)
		pkg := strings.TrimSpace(res.Adversary.Name)
		adv := ref
		if adv == "" {
			adv = pkg
		}
		for _, f := range res.Findings {
			plan.Summary.FindingsSeen++
			if minRank >= 0 && SeverityRank(f.Severity) < minRank {
				plan.Skipped = append(plan.Skipped, SkippedFinding{
					FindingID: f.ID, Adversary: adv, Reason: "below_min_severity", Severity: f.Severity,
				})
				continue
			}
			pc := projectOne(adv, pkg, res.Adversary.Version, opts.HeadSHA, f)
			plan.Comments = append(plan.Comments, pc)
		}
	}

	if !opts.OmitSummary && len(plan.Comments) > 0 {
		plan.ReviewBody = TemplateSummary(plan.Comments)
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

// TemplateSummary is the deterministic fallback when no model provider is
// available. It includes only actionable findings, never clean-run opinions.
func TemplateSummary(comments []PlannedComment) string {
	if len(comments) == 0 {
		return ""
	}
	counts := map[string]int{}
	for _, comment := range comments {
		counts[strings.ToLower(strings.TrimSpace(comment.Severity))]++
	}
	var countBits []string
	for _, severity := range []string{"critical", "high", "medium", "low", "info"} {
		if count := counts[severity]; count > 0 {
			countBits = append(countBits, fmt.Sprintf("%d %s", count, severity))
		}
	}
	var body strings.Builder
	fmt.Fprintf(&body, "Adversary found %d actionable issue", len(comments))
	if len(comments) != 1 {
		body.WriteString("s")
	}
	if len(countBits) > 0 {
		fmt.Fprintf(&body, " (%s)", strings.Join(countBits, ", "))
	}
	body.WriteString(":\n")
	for _, comment := range comments {
		fmt.Fprintf(&body, "\n- **%s** %s", strings.ToLower(comment.Severity), comment.Title)
		if comment.Adversary != "" {
			fmt.Fprintf(&body, " — `%s`", comment.Adversary)
		}
	}
	return body.String()
}

func projectOne(adversary, packageName, packageVersion, headSHA string, f review.Finding) PlannedComment {
	pathStr, line, endLine := primaryAnchor(f.Evidence)
	placement := "review_body"
	reason := ""
	if pathStr != "" {
		norm, err := normalizeRepoRelativePath(pathStr)
		if err != nil {
			placement = "unplaceable"
			reason = "invalid_path"
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
	comment := PlannedComment{
		FindingID:       f.ID,
		RuleID:          f.RuleID,
		Adversary:       adversary,
		Package:         packageName,
		PackageVersion:  packageVersion,
		HeadSHA:         strings.TrimSpace(headSHA),
		Severity:        f.Severity,
		Confidence:      f.Confidence,
		Title:           f.Title,
		Body:            body,
		BodySource:      "template",
		Anchor:          Anchor{Path: pathStr, Line: line, EndLine: endLine},
		Placement:       placement,
		PlacementReason: reason,
	}
	comment.Body = EnsurePlannedMarker(body, comment)
	return comment
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

// MarkerV2 adds immutable package and review provenance used to route human
// replies back to the owning adversary. Values are query-escaped so the marker
// remains one machine-readable HTML comment.
func MarkerV2(comment PlannedComment) string {
	loc := comment.Anchor.Path
	if comment.Anchor.Line != nil {
		loc = fmt.Sprintf("%s:%d", comment.Anchor.Path, *comment.Anchor.Line)
	}
	if loc == "" {
		loc = "none"
	}
	fields := []string{
		"adversary=" + markerEscape(comment.Adversary),
		"package=" + markerEscape(comment.Package),
		"version=" + markerEscape(comment.PackageVersion),
		"finding=" + markerEscape(comment.FindingID),
		"rule=" + markerEscape(comment.RuleID),
		"head=" + markerEscape(comment.HeadSHA),
		"loc=" + markerEscape(loc),
	}
	return "<!-- adversary-review:v2 " + strings.Join(fields, " ") + " -->"
}

func markerEscape(value string) string {
	return url.QueryEscape(sanitizeMarker(value))
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
