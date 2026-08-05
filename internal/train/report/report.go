package report

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/adversarylabs/adversary/internal/train/cases"
	"github.com/adversarylabs/adversary/internal/train/critic"
	"github.com/adversarylabs/adversary/internal/train/experiment"
	"github.com/adversarylabs/adversary/internal/train/judge"
	"github.com/adversarylabs/adversary/internal/train/normalize"
	"github.com/adversarylabs/adversary/internal/train/score"
	"github.com/adversarylabs/adversary/internal/train/securefs"
	"github.com/adversarylabs/adversary/internal/train/workspace"
)

// Input is everything needed to write a human-readable run report.
type Input struct {
	RunID         string
	DataRoot      string
	RunDir        string
	ExperimentDir string // also write README here (where people often open first)
	Fixture       bool
	Live          bool
	Scorecard     *score.Scorecard
	Cases         []*cases.Case
	Judgments     map[string]*judge.ReviewJudgment
	NormReviews   map[string]*normalize.Review
	Hypotheses    []critic.Hypothesis
	Experiment    *experiment.Report
	ProposalPatch string
	BlockedNote   string
	// LocalIDs are home-grown package ids that may receive train drafts.
	// When set, suggested issues are only emitted for these owners.
	LocalIDs map[string]bool
	// OfficialIDs are official jury package ids (never receive train drafts).
	OfficialIDs map[string]bool
	// OfficialCatchByConcern maps concernID → official package that matched (if any).
	// When set, suppresses local drafts for that gold.
	OfficialCatchByConcern map[string]string
}

// Result of writing the report.
type Result struct {
	READMEPath string // primary story file to open
	Verdict    string // BAD | MIXED | GOOD
	Headline   string // one plain sentence
	CLIBlock   string // entire CLI blurb (no jargon)
	// Issues are local-package draft suggestions (train results inbox).
	Issues []SuggestedIssue
}

// Write creates a plain-English story report.
func Write(in Input) (*Result, error) {
	if in.RunDir == "" {
		return nil, fmt.Errorf("run dir required")
	}
	if err := securefs.MkdirAll(in.RunDir); err != nil {
		return nil, err
	}
	if in.ExperimentDir != "" {
		if err := securefs.MkdirAll(in.ExperimentDir); err != nil {
			return nil, err
		}
	}

	verdict, headline := classify(in.Scorecard)
	// Build issues once; story + SUGGESTED_ISSUES.md reuse them.
	issues := suggestIssues(in)
	story := renderStoryWithIssues(in, verdict, headline, issues)

	// Primary: STORY.md in the run (harder to miss than README full of other dirs)
	primary := filepath.Join(in.RunDir, "STORY.md")
	if err := securefs.WriteFile(primary, []byte(story)); err != nil {
		return nil, err
	}
	// Also README.md in run
	_ = securefs.WriteFile(filepath.Join(in.RunDir, "README.md"), []byte(story))

	// Experiments folder is what the user often opens — put the same story there.
	if in.ExperimentDir != "" {
		_ = securefs.WriteFile(filepath.Join(in.ExperimentDir, "README.md"), []byte(story))
		_ = securefs.WriteFile(filepath.Join(in.ExperimentDir, "STORY.md"), []byte(story))
	}

	if in.DataRoot != "" {
		_ = securefs.WriteFile(filepath.Join(in.DataRoot, "LATEST_STORY.md"), []byte(story))
		_ = securefs.WriteFile(filepath.Join(in.DataRoot, "LATEST_RUN_REPORT.md"), []byte(story))
	}

	writeSuggestedIssuesFile(in.ExperimentDir, issues)
	writeSuggestedIssuesFile(in.RunDir, issues)
	if in.DataRoot != "" {
		writeSuggestedIssuesFile(in.DataRoot, issues)
		_ = securefs.WriteFile(filepath.Join(in.DataRoot, "LATEST_SUGGESTED_ISSUES.md"),
			mustSuggestedIssuesBytes(issues))
	}

	openPath := primary
	if in.ExperimentDir != "" {
		openPath = filepath.Join(in.ExperimentDir, "STORY.md")
	}

	cli := formatCLI(verdict, headline, openPath, in)
	return &Result{
		READMEPath: openPath,
		Verdict:    verdict,
		Headline:   headline,
		CLIBlock:   cli,
		Issues:     issues,
	}, nil
}

func mustSuggestedIssuesBytes(issues []SuggestedIssue) []byte {
	var all strings.Builder
	all.WriteString("# Suggested GitHub issues (NOT filed — review first)\n\n")
	if len(issues) == 0 {
		all.WriteString("_No drafts this run._\n")
	}
	for i, iss := range issues {
		fmt.Fprintf(&all, "## %d. %s\n\nLabels: %s\n\n%s\n\n---\n\n",
			i+1, iss.Title, strings.Join(iss.Labels, ", "), iss.Body)
	}
	return []byte(all.String())
}

func classify(sc *score.Scorecard) (verdict, headline string) {
	if sc == nil || sc.CaseCount == 0 {
		return "UNKNOWN", "Nothing was graded."
	}
	// Use failure list for concrete counts when possible.
	missed, extra := 0, 0
	for _, f := range sc.Failures {
		switch f.Kind {
		case "missed-concern":
			missed++
		case "false-positive", "unsupported-claim":
			extra++
		}
	}

	// No in-scope misses and no noisy extras → good (includes "nothing in scope to grade").
	if missed == 0 && extra == 0 {
		return "GOOD", "No in-scope misses. Either we matched what mattered, or human comments were out of engineering-review’s mission (docs/style/etc.) and correctly ignored."
	}

	switch {
	case missed == 0 && extra > 0:
		return "MIXED", fmt.Sprintf(
			"We did not miss in-scope human concerns, but we raised %d finding(s) that did not line up with graded human comments.",
			extra)
	case sc.ImportantConcernRecall >= 0.70 && missed <= 1:
		return "GOOD", "Mostly good: we caught most in-scope human concerns."
	case sc.ImportantConcernRecall >= 0.40 || (missed > 0 && missed <= extra+1):
		return "MIXED", fmt.Sprintf(
			"Mixed: %d in-scope human concern(s) missed; %d unaligned finding(s) from us.",
			missed, extra)
	default:
		return "BAD", fmt.Sprintf(
			"Not good: %d in-scope human concern(s) missed (fair product gaps). %d unaligned finding(s) from us.",
			missed, extra)
	}
}

func estimateGold(sc *score.Scorecard) int {
	// Approximate gold count from recall and matched; failures of type missed + rough.
	// Prefer counting missed + matched from failures/per-case if available.
	missed := 0
	for _, f := range sc.Failures {
		if f.Kind == "missed-concern" {
			missed++
		}
	}
	if sc.ImportantConcernRecall > 0 && sc.ImportantConcernRecall < 1 && missed > 0 {
		// total ≈ missed / (1-recall)
		return int(float64(missed)/(1-sc.ImportantConcernRecall) + 0.5)
	}
	if missed > 0 {
		return missed
	}
	return sc.CaseCount
}

func formatCLI(verdict, headline, openPath string, in Input) string {
	var b strings.Builder
	b.WriteString("\n")
	b.WriteString("========================================================\n")
	switch verdict {
	case "GOOD":
		b.WriteString("  BOTTOM LINE: This looks GOOD\n")
	case "MIXED":
		b.WriteString("  BOTTOM LINE: This is MIXED (some wins, some misses)\n")
	case "BAD":
		b.WriteString("  BOTTOM LINE: This looks BAD — we did not match the human review well\n")
	default:
		fmt.Fprintf(&b, "  BOTTOM LINE: %s\n", verdict)
	}
	b.WriteString("========================================================\n\n")
	fmt.Fprintf(&b, "%s\n\n", headline)
	b.WriteString("Next steps:\n\n")
	b.WriteString("  adversary train results ls\n")
	b.WriteString("  adversary train results inspect <id>\n")
	b.WriteString("  adversary train results apply <id>\n\n")
	fmt.Fprintf(&b, "Full story (optional):\n  %s\n", openPath)
	if in.DataRoot != "" {
		fmt.Fprintf(&b, "  %s/LATEST_STORY.md\n", in.DataRoot)
	}
	return b.String()
}

func renderStoryWithIssues(in Input, verdict, headline string, issues []SuggestedIssue) string {
	var b strings.Builder

	fmt.Fprintf(&b, "# What happened in this train run\n\n")
	fmt.Fprintf(&b, "_Generated %s_\n\n", time.Now().UTC().Format("2006-01-02 15:04 UTC"))

	fmt.Fprintf(&b, "## Bottom line\n\n")
	switch verdict {
	case "GOOD":
		fmt.Fprintf(&b, "**This looks good.**\n\n")
	case "MIXED":
		fmt.Fprintf(&b, "**This is mixed — not a clear win.**\n\n")
	case "BAD":
		fmt.Fprintf(&b, "**This looks bad.** Our automated reviewers did not line up well with what human reviewers said on these PRs.\n\n")
	default:
		fmt.Fprintf(&b, "**%s**\n\n", verdict)
	}
	fmt.Fprintf(&b, "%s\n\n", headline)

	fmt.Fprintf(&b, "### In one sentence, what is this comparing?\n\n")
	b.WriteString("A real human code review left comments on a pull request. ")
	b.WriteString("We route each in-scope comment to the **best-fit adversary** (specialists before `engineering-review`) and ask that owner to review the **same code state**. ")
	b.WriteString("We only grade human comments that fit an adversary’s **mission** — not docs nits, style, LGTM, or misroutes.\n\n")
	b.WriteString("- **In scope** human concern + we also said something similar → **we caught it** (good).\n")
	b.WriteString("- **In scope** human concern + we said nothing like that → **we missed it** (bad for the **owning** adversary; fair issue).\n")
	b.WriteString("- **Out of scope** human comment (docs wording, pure style, CI-only for wrong owner, …) → **ignored** for grading — not a miss.\n")
	b.WriteString("- We said something the human never raised → **extra finding** (not automatically “we found a bug they missed”).\n")
	b.WriteString("- **Dump-to-eng-review is a failure:** eng-review owns only staff residual judgment no specialist owns.\n\n")

	// Stories first — the whole point
	fmt.Fprintf(&b, "## The stories (read these)\n\n")

	caseByID := map[string]*cases.Case{}
	for _, c := range in.Cases {
		caseByID[c.ID] = c
	}
	ids := make([]string, 0, len(in.Cases))
	for _, c := range in.Cases {
		ids = append(ids, c.ID)
	}
	sort.Strings(ids)

	storyNum := 0
	// Prefer missed concerns as stories first
	if in.Scorecard != nil {
		for _, f := range in.Scorecard.Failures {
			if f.Kind != "missed-concern" {
				continue
			}
			c := caseByID[f.CaseID]
			if c == nil {
				continue
			}
			storyNum++
			writeMissStory(&b, storyNum, c, f, in.NormReviews[f.CaseID])
		}
		for _, f := range in.Scorecard.Failures {
			if f.Kind != "false-positive" && f.Kind != "unsupported-claim" {
				continue
			}
			c := caseByID[f.CaseID]
			if c == nil {
				continue
			}
			storyNum++
			writeExtraStory(&b, storyNum, c, f, in.NormReviews[f.CaseID])
			if storyNum >= 10 {
				break
			}
		}
	}

	// Also write per-PR narrative with hits
	fmt.Fprintf(&b, "## Pull requests we looked at\n\n")
	for _, id := range ids {
		c := caseByID[id]
		if c == nil {
			continue
		}
		writePRSection(&b, c, in.Judgments[id], in.NormReviews[id])
	}

	// Suggested GitHub issues (draft only — not created)
	fmt.Fprintf(&b, "## Suggested GitHub issue(s) for our agents\n\n")
	b.WriteString("_These are **drafts for you to review**. Nothing was filed on GitHub. Use `adversary train results ls` / `apply`._\n\n")
	if len(issues) == 0 {
		b.WriteString("No suggested issues this run (no clear misses to generalize).\n\n")
	} else {
		for i, iss := range issues {
			fmt.Fprintf(&b, "### Suggested issue %d\n\n", i+1)
			fmt.Fprintf(&b, "**Title:** %s\n\n", iss.Title)
			fmt.Fprintf(&b, "**Labels (suggested):** `%s`\n\n", strings.Join(iss.Labels, "`, `"))
			fmt.Fprintf(&b, "**Body:**\n\n```markdown\n%s\n```\n\n", iss.Body)
		}
	}

	// What to do
	fmt.Fprintf(&b, "## What should I do next?\n\n")
	switch verdict {
	case "BAD":
		b.WriteString("1. Read the **missed** stories above — those are the important ones.\n")
		b.WriteString("2. Review the **Suggested GitHub issue(s)** — edit and file if they look right (or hand to an agent).\n")
		b.WriteString("3. Do **not** ship a random patch just because one was generated.\n\n")
	case "MIXED":
		b.WriteString("1. Read the missed stories and the suggested issue drafts.\n")
		b.WriteString("2. File only the issues you agree with.\n")
		b.WriteString("3. Re-run after any engineering-review change: `factory slice` (live discovery).\n\n")
	default:
		b.WriteString("1. Skim the stories to confirm they look right.\n")
		b.WriteString("2. Keep iterating with more live PRs.\n\n")
	}

	if in.Experiment != nil {
		fmt.Fprintf(&b, "### About the “experiment / patch” files in this folder\n\n")
		b.WriteString("The factory may also draft a **suggested patch**. ")
		b.WriteString("That is **not** a finished fix and was **not** published.\n\n")
		if in.Experiment.CandidateScoresMode == "remeasured" && (in.Experiment.DeltaRecall < 0 || in.Experiment.DeltaPrecision < 0) {
			b.WriteString("When we tried the candidate, the comparison got **worse or no better** — so you should **reject** it unless you have a manual reason not to.\n\n")
		} else if in.Experiment.CandidateScoresMode == "identical_to_base" {
			b.WriteString("We did not get a separate clean re-score of the candidate, so treat the patch as notes only.\n\n")
		}
		if in.ProposalPatch != "" {
			fmt.Fprintf(&b, "Patch file (optional to read): `%s`\n\n", in.ProposalPatch)
		}
	}

	fmt.Fprintf(&b, "### Run again\n\n```bash\nadversary train run\n```\n\nState: `%s`\n\n",
		or(in.DataRoot, ".adversary-train"))

	if in.BlockedNote != "" {
		fmt.Fprintf(&b, "## Note about a partial run\n\nSomething external blocked part of the pipeline: %s\n\n", in.BlockedNote)
	}

	b.WriteString("---\n\n")
	b.WriteString("_You can ignore receipt.json, scorecard.json, and other machine files unless you’re debugging the factory itself._\n")
	return b.String()
}

func writeMissStory(b *strings.Builder, n int, c *cases.Case, f judge.Failure, rev *normalize.Review) {
	fmt.Fprintf(b, "### Story %d — We missed something a human caught\n\n", n)

	link := reviewLink(c)
	if link != "" {
		fmt.Fprintf(b, "**Pull request:** [%s](%s)\n\n", link, link)
	}
	if c.PullRequest.Title != "" {
		fmt.Fprintf(b, "**PR title:** %s\n\n", c.PullRequest.Title)
	}

	e := concernByID(c, f.ConcernID)
	cm := (*cases.Comment)(nil)
	if e != nil {
		cm = commentForConcern(c, *e)
	}
	owner := storyOwner(e, f, rev)

	b.WriteString("**What the human reviewer said**\n\n")
	if cm != nil {
		who := cm.Author
		if who == "" {
			who = "a reviewer"
		}
		where := ""
		if cm.Path != "" {
			where = fmt.Sprintf(" on `%s`", cm.Path)
			if cm.Line > 0 {
				where += fmt.Sprintf(" line %d", cm.Line)
			}
		}
		fmt.Fprintf(b, "%s wrote%s:\n\n", who, where)
		fmt.Fprintf(b, "> %s\n\n", softWrap(cm.Body, 100))
		if cl := commentLink(c, cm); cl != "" {
			fmt.Fprintf(b, "Link to that comment: %s\n\n", cl)
		}
	} else if e != nil {
		fmt.Fprintf(b, "We recorded this as a concern the human raised:\n\n> %s\n\n", e.Summary)
	} else {
		fmt.Fprintf(b, "Human concern id `%s` (details missing from the case file).\n\n", f.ConcernID)
	}

	fmt.Fprintf(b, "**What `%s` said on the same code**\n\n", owner)
	if rev == nil || len(rev.Findings) == 0 {
		b.WriteString("It did not produce any findings for this change (or we could not read them).\n\n")
	} else {
		b.WriteString("It reported:\n\n")
		for _, finding := range rev.Findings {
			fmt.Fprintf(b, "- %s", softWrap(finding.Claim, 120))
			if finding.File != "" {
				fmt.Fprintf(b, " (`%s`", finding.File)
				if finding.LineStart > 0 {
					fmt.Fprintf(b, ":%d", finding.LineStart)
				}
				b.WriteString(")")
			}
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}

	b.WriteString("**What we concluded**\n\n")
	b.WriteString("None of those findings lined up with the human’s concern above. ")
	b.WriteString("So for grading purposes: **the human raised a real issue, and we did not catch it.** ")
	fmt.Fprintf(b, "That is a miss — something we want **%s** to get better at.\n\n", owner)
	fmt.Fprintf(b, "**What to do:** Teach `%s` to notice this *kind* of issue in general (not this one PR only).\n\n", owner)
	b.WriteString("---\n\n")
}

// storyOwner picks the adversary name for miss/extra narratives.
func storyOwner(e *cases.ExpectedConcern, f judge.Failure, rev *normalize.Review) string {
	if e != nil && e.OwnerAdversary != "" {
		return e.OwnerAdversary
	}
	if f.ReviewerID != "" && f.ReviewerID != "multi" {
		return f.ReviewerID
	}
	if rev != nil && rev.ReviewerID != "" {
		return rev.ReviewerID
	}
	return "engineering-review"
}

func writeExtraStory(b *strings.Builder, n int, c *cases.Case, f judge.Failure, rev *normalize.Review) {
	fmt.Fprintf(b, "### Story %d — We raised something that did not match the human review\n\n", n)
	link := reviewLink(c)
	if link != "" {
		fmt.Fprintf(b, "**Pull request:** [%s](%s)\n\n", link, link)
	}
	owner := storyOwner(nil, f, rev)

	fmt.Fprintf(b, "**What `%s` said**\n\n", owner)
	fnd := findingByID(rev, f.FindingID)
	if fnd != nil {
		fmt.Fprintf(b, "> %s\n\n", softWrap(fnd.Claim, 120))
		if fnd.File != "" {
			fmt.Fprintf(b, "Location: `%s`", fnd.File)
			if fnd.LineStart > 0 {
				fmt.Fprintf(b, ":%d", fnd.LineStart)
			}
			b.WriteString("\n\n")
		}
	} else {
		fmt.Fprintf(b, "(finding `%s` — text not available)\n\n", f.FindingID)
	}

	b.WriteString("**What the human review used for grading said**\n\n")
	b.WriteString("Nothing in the human’s accepted comments clearly matches that finding.\n\n")

	b.WriteString("**What we concluded**\n\n")
	if f.Kind == "unsupported-claim" {
		b.WriteString("The finding was also weak on evidence (hard to verify). ")
	}
	b.WriteString("So this counts as an **extra / unaligned finding**. ")
	b.WriteString("It does **not** automatically mean “we found a bug the human missed.” ")
	b.WriteString("It might be noise, or it might be real and worth a human look later — but it does not help us claim we matched the human review.\n\n")
	fmt.Fprintf(b, "**What to do:** If it looks like noise, tighten `%s`. If it looks truly important, have a human confirm and we can add it as a graded concern later.\n\n", owner)
	b.WriteString("---\n\n")
}

func writePRSection(b *strings.Builder, c *cases.Case, j *judge.ReviewJudgment, rev *normalize.Review) {
	fmt.Fprintf(b, "### %s\n\n", displayPRName(c))
	if link := reviewLink(c); link != "" {
		fmt.Fprintf(b, "Open the PR: %s\n\n", link)
	}

	approved := cases.ApprovedLabels(c.Labels.ExpectedConcerns)
	skipped := cases.OutOfScopeLabels(c.Labels.ExpectedConcerns)

	matched := map[string]bool{}
	if j != nil {
		for _, id := range j.ExpectedMatched {
			matched[id] = true
		}
	}

	if len(approved) == 0 {
		b.WriteString("No human concerns were **in scope** for engineering-review on this PR (so we do not grade misses here).\n\n")
	} else {
		fmt.Fprintf(b, "Human raised **%d** in-scope issue(s) (routed to an adversary):\n\n", len(approved))
		for _, e := range approved {
			owner := e.OwnerAdversary
			if owner == "" {
				owner = "engineering-review"
			}
			if matched[e.ID] {
				fmt.Fprintf(b, "- **Caught by `%s`.** Human concern: %s\n", owner, e.Summary)
				if j != nil && rev != nil {
					for _, fj := range j.Findings {
						if fj.MatchesExpectedConcern == e.ID {
							if fnd := findingByID(rev, fj.FindingID); fnd != nil {
								fmt.Fprintf(b, "  - We said: %s\n", softWrap(fnd.Claim, 100))
							}
							break
						}
					}
				}
			} else {
				fmt.Fprintf(b, "- **Miss for `%s`.** Human concern: %s\n", owner, e.Summary)
			}
		}
		b.WriteString("\n")
	}

	if len(skipped) > 0 {
		fmt.Fprintf(b, "Human also said things **not attributed to any adversary** (ignored for grading):\n\n")
		for _, e := range skipped {
			fmt.Fprintf(b, "- _Ignored:_ %s\n", softWrap(e.Summary, 120))
			if e.ScopeReason != "" {
				fmt.Fprintf(b, "  - why: %s\n", e.ScopeReason)
			}
		}
		b.WriteString("\n")
	}
}

func displayPRName(c *cases.Case) string {
	if c.PullRequest.Title != "" {
		return fmt.Sprintf("%s/%s#%d — %s", c.Repository.Owner, c.Repository.Name, c.PullRequest.Number, c.PullRequest.Title)
	}
	return c.ID
}

func reviewLink(c *cases.Case) string {
	if c == nil {
		return ""
	}
	if c.Repository.URL != "" {
		return c.Repository.URL
	}
	if c.Repository.Owner != "" && c.Repository.Name != "" && c.PullRequest.Number > 0 {
		return fmt.Sprintf("https://github.com/%s/%s/pull/%d", c.Repository.Owner, c.Repository.Name, c.PullRequest.Number)
	}
	return ""
}

func commentLink(c *cases.Case, cm *cases.Comment) string {
	base := reviewLink(c)
	if base == "" || cm == nil || cm.ID == 0 {
		return ""
	}
	return fmt.Sprintf("%s#discussion_r%d", base, cm.ID)
}

func commentForConcern(c *cases.Case, e cases.ExpectedConcern) *cases.Comment {
	if c == nil {
		return nil
	}
	var best *cases.Comment
	bestScore := 0
	for i := range c.Comments {
		cm := &c.Comments[i]
		score := 0
		if cm.GeneralizedConcern != "" {
			if ow := overlapWords(e.Summary, cm.GeneralizedConcern); ow >= 3 {
				score += 5
			} else if ow >= 2 {
				score += 3
			}
		}
		if ow := overlapWords(e.Summary, cm.Body); ow >= 3 {
			score += 3
		} else if ow >= 2 {
			score += 1
		}
		if e.File != "" && cm.Path == e.File {
			score += 1
		}
		if score > bestScore {
			bestScore = score
			best = cm
		}
	}
	if bestScore < 3 {
		return nil
	}
	return best
}

func concernByID(c *cases.Case, id string) *cases.ExpectedConcern {
	for i := range c.Labels.ExpectedConcerns {
		if c.Labels.ExpectedConcerns[i].ID == id {
			return &c.Labels.ExpectedConcerns[i]
		}
	}
	return nil
}

func findingByID(r *normalize.Review, id string) *normalize.Finding {
	if r == nil {
		return nil
	}
	for i := range r.Findings {
		if r.Findings[i].ID == id {
			return &r.Findings[i]
		}
	}
	return nil
}

func overlapWords(a, b string) int {
	set := map[string]bool{}
	for _, w := range strings.Fields(strings.ToLower(b)) {
		if len(w) > 3 {
			set[w] = true
		}
	}
	n := 0
	for _, w := range strings.Fields(strings.ToLower(a)) {
		if len(w) > 3 && set[w] {
			n++
		}
	}
	return n
}

func softWrap(s string, n int) string {
	s = strings.Join(strings.Fields(strings.ReplaceAll(s, "\n", " ")), " ")
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func or(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// SuggestedIssue is a draft GitHub issue for human review (not filed).
type SuggestedIssue struct {
	Title  string
	Labels []string
	Body   string
}

func writeSuggestedIssuesFile(dir string, issues []SuggestedIssue) {
	if dir == "" {
		return
	}
	var all strings.Builder
	all.WriteString("# Suggested GitHub issues (NOT filed — review first)\n\n")
	if len(issues) == 0 {
		all.WriteString("_No drafts this run._\n")
	}
	for i, iss := range issues {
		fmt.Fprintf(&all, "## %d. %s\n\nLabels: %s\n\n%s\n\n---\n\n",
			i+1, iss.Title, strings.Join(iss.Labels, ", "), iss.Body)
	}
	_ = securefs.WriteFile(filepath.Join(dir, "SUGGESTED_ISSUES.md"), []byte(all.String()))
}

// suggestIssues builds anonymized, generalized issue drafts from misses.
// Only local (train-eligible) owners receive drafts; official jury never does.
func suggestIssues(in Input) []SuggestedIssue {
	if in.Scorecard == nil {
		return nil
	}
	// Group missed concerns by a coarse class from summary keywords.
	type bucket struct {
		key      string
		title    string
		examples []string
		count    int
	}
	buckets := map[string]*bucket{}
	caseByID := map[string]*cases.Case{}
	for _, c := range in.Cases {
		caseByID[c.ID] = c
	}
	for _, f := range in.Scorecard.Failures {
		if f.Kind != "missed-concern" {
			continue
		}
		c := caseByID[f.CaseID]
		summary := f.ConcernID
		if c != nil {
			if e := concernByID(c, f.ConcernID); e != nil {
				summary = e.Summary
			}
		}
		owner := ""
		if c != nil {
			if e := concernByID(c, f.ConcernID); e != nil && e.OwnerAdversary != "" {
				owner = e.OwnerAdversary
			}
		}
		if owner == "" && f.ReviewerID != "" && f.ReviewerID != "multi" {
			owner = f.ReviewerID
		}
		if owner == "" {
			continue
		}
		// Train draft gate: local only, no official catch.
		if !shouldEmitTrainDraft(in, f.ConcernID, owner) {
			continue
		}
		key, title := classifyConcernClass(summary)
		// Namespace bucket by owner so issues target the right package.
		bkey := owner + "|" + key
		bkt := buckets[bkey]
		if bkt == nil {
			bkt = &bucket{key: bkey, title: owner + ": " + title}
			buckets[bkey] = bkt
		}
		bkt.count++
		if len(bkt.examples) < 3 {
			ex := softWrap(summary, 160)
			bkt.examples = append(bkt.examples, ex)
		}
	}
	if len(buckets) == 0 {
		// Do not emit noise drafts for official packages.
		return nil
	}
	keys := make([]string, 0, len(buckets))
	for k := range buckets {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []SuggestedIssue
	for _, k := range keys {
		bkt := buckets[k]
		owner := ""
		if i := strings.Index(bkt.key, "|"); i >= 0 {
			owner = bkt.key[:i]
		}
		if owner == "" || !isLocalTrainOwner(in, owner) {
			continue
		}
		out = append(out, SuggestedIssue{
			Title:  bkt.title,
			Labels: []string{"train", "adversary:" + owner, "miss"},
			Body: anonymizedIssueBody(
				owner,
				fmt.Sprintf("On live discovery PRs, human reviewers raised concerns that fit **%s**, but that adversary did not surface a matching finding.", owner),
				bkt.examples,
				fmt.Sprintf("%s should detect this class of issue with evidence (file/line) on similar changes, without hard-coding a single repository or PR.", owner),
			),
		})
	}
	return out
}

func isLocalTrainOwner(in Input, owner string) bool {
	o := strings.ToLower(strings.TrimSpace(owner))
	if o == "" {
		return false
	}
	if in.OfficialIDs[o] {
		return false
	}
	// Known official short names never receive drafts even without OfficialIDs set.
	if isKnownOfficialID(o) && !in.LocalIDs[o] {
		return false
	}
	if len(in.LocalIDs) > 0 {
		return in.LocalIDs[o]
	}
	// No local set: treat non-official as local (catalog-author mode with locals only).
	return !isKnownOfficialID(o)
}

func isKnownOfficialID(id string) bool {
	officials := []string{
		"engineering-review", "go-concurrency", "go-testing", "go-security",
		"go-http", "go-database", "go-cli", "go-modules", "go",
		"githubactions", "dockerfile", "terraform", "kustomize", "helm",
		"secrets", "complexity", "python", "typescript", "nodejs",
	}
	for _, x := range officials {
		if id == x {
			return true
		}
	}
	return false
}

func shouldEmitTrainDraft(in Input, concernID, owner string) bool {
	// Use shared AttributeGold so train draft rules live in one place (workspace).
	role := workspace.RoleLocalTrainable
	if !isLocalTrainOwner(in, owner) {
		role = workspace.RoleOfficialJury
	}
	catcher := ""
	if c, ok := in.OfficialCatchByConcern[concernID]; ok {
		catcher = c
	}
	out := workspace.AttributeGold(workspace.Config{}, owner, role, true, catcher, isLocalTrainOwner(in, owner))
	return out.EmitDraft
}

func classifyConcernClass(summary string) (key, title string) {
	s := strings.ToLower(summary)
	// Word-aware for short tokens that appear inside other words
	// (e.g. "race" inside "trace" must not become a concurrency issue title).
	hasRace := containsWholeWord(s, "race") || strings.Contains(s, "data race") || strings.Contains(s, "race condition") || strings.Contains(s, "race-free")
	hasConcurrentAPI := strings.Contains(s, "overlapping") && (strings.Contains(s, "export") || strings.Contains(s, "flush") || strings.Contains(s, "shutdown")) ||
		strings.Contains(s, "concurrency invariant") || strings.Contains(s, "exporter-serialization") || strings.Contains(s, "serialization guarantee")
	switch {
	case hasConcurrentAPI || (hasRace && (strings.Contains(s, "test") || strings.Contains(s, "coverage") || strings.Contains(s, "assert"))):
		return "concurrent-api-tests", "catch missing tests for concurrent API guarantees (overlapping Export/Flush/Shutdown)"
	case hasRace || strings.Contains(s, "concurrent") || strings.Contains(s, "mutex") || strings.Contains(s, "synchron"):
		return "concurrency", "catch data races and shared-state races under concurrent use"
	case strings.Contains(s, "goroutine") || containsWholeWord(s, "leak") || (strings.Contains(s, "shutdown") && !hasConcurrentAPI) || strings.Contains(s, "lifecycle") || strings.Contains(s, "cancel"):
		return "lifecycle", "catch goroutine/worker lifecycle issues on shutdown and cancellation"
	case containsWholeWord(s, "nil") || strings.Contains(s, "panic") || strings.Contains(s, "null"):
		return "nil-safety", "catch nil/panic risks on new code paths"
	case strings.Contains(s, "error") || strings.Contains(s, "export") || strings.Contains(s, "ignored"):
		return "error-handling", "catch ignored or mishandled errors on critical paths"
	case strings.Contains(s, "package") && (strings.Contains(s, "description") || strings.Contains(s, "godoc") || strings.Contains(s, "nit")):
		return "docs-nit", "improve package/documentation comment quality"
	default:
		return "general", "catch important human-raised engineering concerns more reliably"
	}
}

// containsWholeWord reports whether w appears as a whole word in s.
func containsWholeWord(s, w string) bool {
	if w == "" || !strings.Contains(s, w) {
		return false
	}
	for i := 0; ; {
		j := strings.Index(s[i:], w)
		if j < 0 {
			return false
		}
		j += i
		beforeOK := j == 0 || !isASCIIWordChar(s[j-1])
		after := j + len(w)
		afterOK := after >= len(s) || !isASCIIWordChar(s[after])
		if beforeOK && afterOK {
			return true
		}
		i = j + 1
	}
}

func isASCIIWordChar(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '_'
}

func anonymizedIssueBody(owner, problem string, examples []string, acceptance string) string {
	if owner == "" {
		owner = "engineering-review"
	}
	var b strings.Builder
	b.WriteString("## Context\n\n")
	b.WriteString("From adversary train runs (live PR review rounds graded against human review comments).\n\n")
	b.WriteString("## Problem\n\n")
	b.WriteString(problem)
	b.WriteString("\n\n")
	if len(examples) > 0 {
		b.WriteString("## Example concern classes (paraphrased, no private data)\n\n")
		for _, ex := range examples {
			fmt.Fprintf(&b, "- %s\n", ex)
		}
		b.WriteString("\n")
	}
	b.WriteString("## Target\n\n")
	fmt.Fprintf(&b, "- Adversary: `%s`\n", owner)
	b.WriteString("- Prefer a **general** prompt/rule/analysis improvement, not a one-off for a single PR.\n")
	if owner == "engineering-review" {
		b.WriteString("- **Best-owner check:** only file here if no specialist owns this class; dump-to-eng-review is a factory failure mode.\n")
	}
	b.WriteString("\n")
	b.WriteString("## Acceptance idea\n\n")
	b.WriteString(acceptance)
	b.WriteString("\n\n")
	b.WriteString("## Out of scope\n\n")
	b.WriteString("- Do not hard-code repository names or PR numbers into the adversary.\n")
	b.WriteString("- Do not treat “extra” findings as automatically correct without human review.\n\n")
	b.WriteString("---\n_Drafted by adversary train. Not auto-filed._\n")
	return b.String()
}
