package scope

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Decision is whether a human comment is fair gold for an adversary.
type Decision string

const (
	InScope    Decision = "in_scope"
	OutOfScope Decision = "out_of_scope"
	Unclear    Decision = "unclear"
)

// Result of classifying one human comment against an adversary mission.
type Result struct {
	Decision Decision `json:"decision"`
	Reason   string   `json:"reason"`
	Method   string   `json:"method"` // heuristic | llm
}

// Classifier maps human review text to in/out of scope for an adversary.
type Classifier struct {
	// MissionMarkdown is the adversary scope doc (mission, in, out).
	MissionMarkdown string
	// AdversaryName for prompts, e.g. engineering-review.
	AdversaryName string
	// UseLLM when true attempts model classification after heuristics.
	UseLLM bool
}

// LoadMissionFromAdversary loads scope from the adversary package checkout.
// Preferred paths (first hit wins):
//
//	agent/scope.md
//	train/scope.md
//	docs/scope.md          (legacy)
//	SCOPE.md               (legacy)
//	docs/factory-scope.md  (legacy)
func LoadMissionFromAdversary(adversarySource string) (string, string, error) {
	if adversarySource == "" {
		return "", "", fmt.Errorf("empty adversary source")
	}
	root, err := filepath.Abs(adversarySource)
	if err != nil {
		return "", "", err
	}
	candidates := []string{
		filepath.Join(root, "agent", "scope.md"),
		filepath.Join(root, "train", "scope.md"),
		filepath.Join(root, "docs", "scope.md"),
		filepath.Join(root, "SCOPE.md"),
		filepath.Join(root, "docs", "factory-scope.md"),
	}
	for _, path := range candidates {
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		return string(raw), path, nil
	}
	return "", "", fmt.Errorf("no scope.md in adversary at %s (tried agent/scope.md, train/scope.md, docs/scope.md)", root)
}

// LoadMission is deprecated name kept for call sites; prefers adversarySource, then factory fallback.
func LoadMission(adversarySource, factoryRepoRoot, adversaryName string) (string, string, error) {
	if adversarySource != "" {
		if text, path, err := LoadMissionFromAdversary(adversarySource); err == nil {
			return text, path, nil
		}
	}
	// Fallback: factory-local copy (only if adversary checkout missing).
	if factoryRepoRoot != "" {
		base := filepath.Base(adversaryName)
		if base == "" || base == "." {
			base = "engineering-review"
		}
		path := filepath.Join(factoryRepoRoot, "config", "scopes", base+".md")
		raw, err := os.ReadFile(path)
		if err == nil {
			return string(raw), path, nil
		}
	}
	return "", "", fmt.Errorf("could not load scope for %s (pass --source to adversary checkout with docs/scope.md)", adversaryName)
}

// Classify decides if a human comment is in scope for the adversary.
// author is the GitHub login (used to drop bots / copilot overviews).
func (c *Classifier) Classify(commentBody, path, author string) Result {
	body := strings.TrimSpace(commentBody)
	if body == "" {
		return Result{Decision: OutOfScope, Reason: "empty comment", Method: "heuristic"}
	}

	if r, ok := heuristicOut(body, path, author, c.AdversaryName); ok {
		return r
	}

	if c.UseLLM && c.MissionMarkdown != "" {
		if r, err := c.classifyLLM(body, path, author); err == nil {
			return r
		}
	}

	if heuristicLikelyIn(body, path) {
		return Result{
			Decision: InScope,
			Reason:   "heuristic: looks like correctness/completeness/ops engineering concern",
			Method:   "heuristic",
		}
	}
	return Result{
		Decision: OutOfScope,
		Reason:   "heuristic: not clearly in adversary mission (prefer ignore over false miss)",
		Method:   "heuristic",
	}
}

func heuristicOut(body, path, author, adversaryName string) (Result, bool) {
	lower := strings.ToLower(body)
	authorL := strings.ToLower(author)
	adv := strings.ToLower(adversaryName)

	// --- Never grade bot noise as gold for product adversaries ---
	if isReviewBot(authorL) {
		return Result{
			Decision: OutOfScope,
			Reason:   "bot/automated reviewer comment (not a human engineering review)",
			Method:   "heuristic",
		}, true
	}

	// Copilot / bot PR overview dumps (not actionable engineering findings)
	if isPROverviewBlob(body) {
		return Result{
			Decision: OutOfScope,
			Reason:   "PR overview / summary comment, not a specific engineering finding",
			Method:   "heuristic",
		}, true
	}

	// Shared non-defect filters (docs path, sed nits, LGTM, soft-OK, package docs, …)
	if reason, ok := globalNonDefectOut(body, path); ok {
		return Result{Decision: OutOfScope, Reason: reason, Method: "heuristic"}, true
	}

	if strings.Contains(body, "```suggestion") {
		if looksLikeDocOrCommentOnly(body) {
			return Result{
				Decision: OutOfScope,
				Reason:   "GitHub suggestion that only rewrites comment/documentation text",
				Method:   "heuristic",
			}, true
		}
	}

	// Approval / LGTM / positive satisfaction — not a defect to catch.
	// (Even long review bodies that praise the change and end with LGTM.)
	if isApprovalOrNonDefect(body) && !heuristicLikelyIn(body, path) {
		return Result{
			Decision: OutOfScope,
			Reason:   "approval / LGTM / non-defect observation (not a miss)",
			Method:   "heuristic",
		}, true
	}

	// Soft "I think it's ok" design notes without asking for a fix.
	if isSoftOKObservation(lower) && !heuristicLikelyIn(body, path) {
		return Result{
			Decision: OutOfScope,
			Reason:   "soft OK / non-blocking observation, not a required finding",
			Method:   "heuristic",
		}, true
	}

	// Package-doc / godoc nits (any length) — never eng-review gold.
	if isPackageDocNit(body) && !heuristicLikelyIn(body, path) {
		return Result{
			Decision: OutOfScope,
			Reason:   "package/godoc description nit (documentation only)",
			Method:   "heuristic",
		}, true
	}

	// Explicit nit: / Nit; prefix — style/docs unless strong defect language.
	if isExplicitNit(lower) && !heuristicLikelyIn(body, path) {
		return Result{
			Decision: OutOfScope,
			Reason:   "explicit nit / style-process feedback",
			Method:   "heuristic",
		}, true
	}

	if len(body) < 80 {
		for _, p := range []string{"lgtm", "ship it", "typo", "s/", "please rebase", "same"} {
			if strings.Contains(lower, p) && !heuristicLikelyIn(body, path) {
				return Result{
					Decision: OutOfScope,
					Reason:   "short style/process nit",
					Method:   "heuristic",
				}, true
			}
		}
	}

	if path != "" {
		pl := strings.ToLower(path)
		ext := strings.ToLower(filepath.Ext(path))
		if (ext == ".md" || strings.Contains(pl, "readme") ||
			strings.Contains(pl, "changelog")) && !heuristicLikelyIn(body, path) {
			return Result{
				Decision: OutOfScope,
				Reason:   "documentation path without engineering-risk language",
				Method:   "heuristic",
			}, true
		}

		// CI / GitHub Actions / workflow files → not engineering-review
		// (belongs to github-actions / CI specialists).
		if isCIPath(pl) && isEngineeringReview(adv) {
			return Result{
				Decision: OutOfScope,
				Reason:   "CI/workflow path — specialist adversary territory (e.g. github-actions), not engineering-review",
				Method:   "heuristic",
			}, true
		}
	}

	// CI/GHA content even without path (e.g. review body discussing workflows)
	if isEngineeringReview(adv) && isCIContent(lower) && !hasApplicationCodeSmell(lower) {
		return Result{
			Decision: OutOfScope,
			Reason:   "CI/GitHub Actions configuration concern — out of engineering-review mission",
			Method:   "heuristic",
		}, true
	}

	if strings.Contains(lower, "wording") || strings.Contains(lower, "rephrase") ||
		strings.Contains(lower, "godoc") || strings.Contains(lower, "doc comment") ||
		strings.Contains(lower, "grammar:") || strings.Contains(lower, "more description") {
		if !heuristicLikelyIn(body, path) {
			return Result{
				Decision: OutOfScope,
				Reason:   "documentation/wording feedback",
				Method:   "heuristic",
			}, true
		}
	}

	return Result{}, false
}

// globalNonDefectOut is used by the multi-adversary router before scoring.
// Only filters that apply to ALL adversaries (never specialist-owned).
func globalNonDefectOut(body, path string) (reason string, ok bool) {
	if isApprovalOrNonDefect(body) && !heuristicLikelyIn(body, path) {
		return "approval / LGTM / non-defect observation (not a miss)", true
	}
	lower := strings.ToLower(body)
	if isSoftOKObservation(lower) && !heuristicLikelyIn(body, path) {
		return "soft OK / non-blocking observation, not a required finding", true
	}
	if isPackageDocNit(body) && !heuristicLikelyIn(body, path) {
		return "package/godoc description nit (documentation only)", true
	}
	if isExplicitNit(lower) && !heuristicLikelyIn(body, path) {
		return "explicit nit / style-process feedback", true
	}
	if isSedStyleRewrite(body) && !heuristicLikelyIn(body, path) {
		return "sed-style wording rewrite (s/old/new/), not a product defect", true
	}
	if isTrivialProcessComment(lower) {
		return "trivial process / one-word comment, not a graded concern", true
	}
	if isProcessOrMergeLogistics(lower) && !heuristicLikelyIn(body, path) {
		return "process / merge / backlog logistics, not a product defect", true
	}
	// Commit-message rewording is never product gold (even if body quotes race language).
	if isCommitMessageWording(lower) {
		return "commit message / changelog wording, not a product defect", true
	}
	// Pure markdown/docs path without engineering-risk language → never gold
	// for product adversaries (docs nits on kustomize.md are not kustomize product gaps).
	if isDocumentationPath(path) && !heuristicLikelyIn(body, path) {
		return "documentation path without engineering-risk language", true
	}
	return "", false
}

// isCommitMessageWording: reviewer only asks to rephrase the commit message / PR title.
func isCommitMessageWording(lower string) bool {
	if !(strings.Contains(lower, "commit message") || strings.Contains(lower, "commit msg") ||
		strings.Contains(lower, "in the commit") || strings.Contains(lower, "pr title") ||
		strings.Contains(lower, "pull request title")) {
		return false
	}
	// "change X to Y in the commit message" without demanding code fix
	return strings.Contains(lower, "please change") || strings.Contains(lower, "can you please") ||
		strings.Contains(lower, "reword") || strings.Contains(lower, "rephrase") ||
		strings.Contains(lower, "or similar") || strings.Contains(lower, "misleading")
}

// isProcessOrMergeLogistics: backlog, backport order, personal todos — not product gold.
func isProcessOrMergeLogistics(lower string) bool {
	// Strong process signals (any one is enough when no defect language).
	process := []string{
		"backport", "back port", "do it on `main`", "do it on main",
		"todo item", "on that list", "my todo", "follow-up pr", "follow up pr",
		"separate pr", "follow-up issue", "can land later", "out of scope for this pr",
		"merge logistics", "please rebase", "needs rebase", "conflict",
		"claude suggested", // AI-assistant process note, not human product finding
	}
	for _, p := range process {
		if strings.Contains(lower, p) {
			return true
		}
	}
	// "If we want this" + deferral without demanding a fix in this change
	if strings.Contains(lower, "if we want") && (strings.Contains(lower, "todo") ||
		strings.Contains(lower, "later") || strings.Contains(lower, "list") ||
		strings.Contains(lower, "backport") || strings.Contains(lower, "main first")) {
		return true
	}
	return false
}

// isSedStyleRewrite detects s/old/new/ wording rewrites (classic review nits).
func isSedStyleRewrite(body string) bool {
	trim := strings.TrimSpace(body)
	// s/Providers/Generators/ or s/foo/bar/g
	if len(trim) >= 5 && (trim[0] == 's' || trim[0] == 'S') && trim[1] == '/' {
		return true
	}
	lower := strings.ToLower(trim)
	if strings.HasPrefix(lower, "s/") || strings.Contains(lower, "\ns/") {
		return true
	}
	return false
}

// containsWordASCII reports whole-word match for ASCII identifiers.
func containsWordASCII(s, w string) bool {
	if w == "" || !strings.Contains(s, w) {
		return false
	}
	for i := 0; ; {
		j := strings.Index(s[i:], w)
		if j < 0 {
			return false
		}
		j += i
		beforeOK := j == 0 || !isASCIIWordByte(s[j-1])
		after := j + len(w)
		afterOK := after >= len(s) || !isASCIIWordByte(s[after])
		if beforeOK && afterOK {
			return true
		}
		i = j + 1
	}
}

func isASCIIWordByte(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '_'
}

func isTrivialProcessComment(lower string) bool {
	t := strings.TrimSpace(lower)
	// Strip punctuation for one-word checks
	switch t {
	case "changes", "change", "ditto", "same", "nit", "nits", "some nits",
		"ok", "okay", "yes", "no", "done", "fixed", "sg", "sgtm", "ack",
		"+1", "-1", "fyi", "ptal", "bump", "rebase", "please rebase":
		return true
	}
	if len(t) < 12 && (t == "lgtm" || strings.HasPrefix(t, "lgtm ") || t == "ship it") {
		return true
	}
	return false
}

func isDocumentationPath(path string) bool {
	if path == "" {
		return false
	}
	pl := strings.ToLower(path)
	if strings.HasSuffix(pl, ".md") || strings.HasSuffix(pl, ".mdx") || strings.HasSuffix(pl, ".rst") || strings.HasSuffix(pl, ".adoc") {
		return true
	}
	return strings.Contains(pl, "/docs/") || strings.Contains(pl, "/doc/") ||
		strings.Contains(pl, "readme") || strings.Contains(pl, "changelog") ||
		strings.Contains(pl, "/book/") || strings.Contains(pl, "pages/reference")
}

// isApprovalOrNonDefect detects LGTM / satisfaction / praise review bodies
// that do not raise a concrete defect.
func isApprovalOrNonDefect(body string) bool {
	lower := strings.ToLower(strings.TrimSpace(body))
	if lower == "" {
		return false
	}
	// Strong approval markers (include bare APPROVE; "approved" alone is too easy to miss)
	if strings.Contains(lower, "lgtm") || strings.Contains(lower, "ship it") ||
		strings.Contains(lower, "looks good to me") || strings.Contains(lower, "approved") ||
		strings.Contains(lower, "🟢 approve") || strings.Contains(lower, ": approve") ||
		strings.Contains(lower, "assessment:") && strings.Contains(lower, "approve") {
		return true
	}
	// Whole-word APPROVE (bot assessment cards)
	if containsWordASCII(lower, "approve") && !containsDefectAsk(lower) {
		return true
	}
	praise := []string{
		"i'm more satisfied", "i am more satisfied", "more satisfied with this",
		"nice refactor", "looks good", "looks great", "great change",
		"nothing blocking", "not blocking", "non-blocking",
		"no logical path changes", "keeping truncation logic in a separate file is good",
	}
	hits := 0
	for _, p := range praise {
		if strings.Contains(lower, p) {
			hits++
		}
	}
	return hits >= 1 && !containsDefectAsk(lower)
}

// isSoftOKObservation: reviewer notes a design choice but accepts it.
func isSoftOKObservation(lower string) bool {
	okPhrases := []string{
		"i think its ok", "i think it's ok", "i think it is ok",
		"i think this is ok", "i think that's ok", "i think that is ok",
		"seems ok", "seems fine", "should be fine", "this is fine",
		"but i think its ok", "but i think it's ok",
		"you can resolve this", "no action needed",
	}
	for _, p := range okPhrases {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

func isExplicitNit(lower string) bool {
	trim := strings.TrimSpace(lower)
	if strings.HasPrefix(trim, "nit") {
		// nit, nit;, nit:, Nit;
		rest := strings.TrimPrefix(trim, "nit")
		if rest == "" || rest[0] == ':' || rest[0] == ';' || rest[0] == ',' || rest[0] == ' ' {
			return true
		}
	}
	return strings.Contains(lower, "\nnit;") || strings.Contains(lower, "\nnit:") ||
		strings.Contains(lower, "a `nit`") || strings.Contains(lower, "a nit ")
}

func isPackageDocNit(body string) bool {
	lower := strings.ToLower(body)
	if !(strings.Contains(lower, "package") || strings.Contains(lower, "godoc") ||
		strings.Contains(lower, "doc comment") || strings.Contains(lower, "package comment")) {
		return false
	}
	docish := strings.Contains(lower, "more description") ||
		strings.Contains(lower, "package comment") ||
		strings.Contains(lower, "doc comment") ||
		strings.Contains(lower, "godoc") ||
		(strings.Contains(lower, "description on package") || strings.Contains(lower, "package docs"))
	// Suggested package comment block in a fence
	if strings.Contains(body, "```go") && strings.Contains(lower, "// package ") {
		return true
	}
	return docish
}

func containsDefectAsk(lower string) bool {
	// Phrases that mean the reviewer is still flagging a real problem.
	asks := []string{
		"please fix", "must fix", "this is a bug", "this is broken",
		"data race", "deadlock", "goroutine leak", "will panic",
		"incorrect", "should not", "must not", "security issue",
	}
	for _, a := range asks {
		if strings.Contains(lower, a) {
			return true
		}
	}
	return false
}

func isReviewBot(author string) bool {
	if author == "" {
		return false
	}
	bots := []string{
		"copilot", "copilot-pull-request-reviewer", "github-actions",
		"dependabot", "renovate", "sonarcloud", "codecov", "snyk",
		"coderabbit", "cursor", "devin", "graphite", "mermaid",
		"docker-agent", "dockeragent", "claude", "chatgpt", "openai",
		"[bot]", "bot]", "-agent",
	}
	for _, b := range bots {
		if strings.Contains(author, b) {
			return true
		}
	}
	return strings.HasSuffix(author, "[bot]") || strings.HasSuffix(author, "-bot")
}

func isPROverviewBlob(body string) bool {
	lower := strings.ToLower(body)
	// Typical Copilot / auto summary headers
	markers := []string{
		"## pull request overview",
		"### pull request overview",
		"pull request overview",
		"## summary of changes",
		"## what this pr does",
		"## overview\n",
		"### assessment:",
		"## assessment:",
		"assessment: 🟢",
		"assessment: 🔴",
		"assessment: 🟡",
	}
	for _, m := range markers {
		if strings.Contains(lower, m) {
			return true
		}
	}
	// Long multi-section dump with no file path context often = overview
	if strings.Count(body, "##") >= 2 && len(body) > 400 {
		if strings.Contains(lower, "this pr ") || strings.Contains(lower, "this pull request") {
			return true
		}
	}
	return false
}

func isCIPath(pathLower string) bool {
	return strings.Contains(pathLower, ".github/workflows") ||
		strings.Contains(pathLower, ".github/actions") ||
		strings.HasSuffix(pathLower, ".yml") && (strings.Contains(pathLower, "workflow") || strings.Contains(pathLower, "ci") || strings.Contains(pathLower, "cd")) ||
		strings.HasSuffix(pathLower, ".yaml") && (strings.Contains(pathLower, "workflow") || strings.Contains(pathLower, "/ci/")) ||
		strings.Contains(pathLower, "cloudbuild") ||
		strings.Contains(pathLower, "buildkite") ||
		strings.Contains(pathLower, "circleci") ||
		strings.Contains(pathLower, "jenkinsfile") ||
		strings.Contains(pathLower, ".gitlab-ci")
}

func isCIContent(lower string) bool {
	keys := []string{
		"github actions", "workflow", "self-hosted runner", "--privileged",
		"codspeed", "actions/checkout", "runs-on:", "job container",
		"gha ", "ci job", "github workflow", "workflow_dispatch",
		"permissions:", "GITHUB_TOKEN",
	}
	n := 0
	for _, k := range keys {
		if strings.Contains(lower, strings.ToLower(k)) {
			n++
		}
	}
	return n >= 1 && (strings.Contains(lower, "workflow") || strings.Contains(lower, "runner") ||
		strings.Contains(lower, "github action") || strings.Contains(lower, "--privileged") ||
		strings.Contains(lower, "codspeed") || strings.Contains(lower, "container"))
}

func isEngineeringReview(adv string) bool {
	return adv == "" || strings.Contains(adv, "engineering-review") || strings.Contains(adv, "engineering_review")
}

func hasApplicationCodeSmell(lower string) bool {
	// Real product-code concerns that eng-review owns even if CI is mentioned.
	keys := []string{"goroutine", "data race", "deadlock", "nil pointer", "memory leak",
		"api contract", "rollback of the service", "caller", "mutex"}
	for _, k := range keys {
		if strings.Contains(lower, k) {
			return true
		}
	}
	return false
}

func looksLikeDocOrCommentOnly(body string) bool {
	s := body
	if i := strings.Index(s, "```suggestion"); i >= 0 {
		s = s[i+len("```suggestion"):]
	}
	if i := strings.Index(s, "```"); i >= 0 {
		s = s[:i]
	}
	lines := strings.Split(s, "\n")
	codeish := 0
	docish := 0
	for _, line := range lines {
		t := strings.TrimSpace(line)
		if t == "" {
			continue
		}
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "#") || strings.HasPrefix(t, "*") || strings.HasPrefix(t, "/*") {
			docish++
			continue
		}
		if !strings.ContainsAny(t, "{}();=") {
			docish++
			continue
		}
		codeish++
	}
	return docish > 0 && codeish == 0
}

func heuristicLikelyIn(body, path string) bool {
	lower := strings.ToLower(body)
	// Don't treat CI/security-in-workflow as eng-review in-scope.
	if isCIPath(strings.ToLower(path)) || (isCIContent(lower) && !hasApplicationCodeSmell(lower)) {
		return false
	}
	keywords := []string{
		"data race", "deadlock", "goroutine", "nil ", "panic", "data loss",
		"incorrect", "bug", "broken", "crash", "injection",
		"blast radius", "incomplete", "missing error", "ignored error",
		"context.background", "cancellation", "timeout", "concurrency",
		"thread-safe", "mutex", "compatibility", "breaking change",
		"resource leak", "double-close", "use-after", "memory leak",
	}
	for _, k := range keywords {
		if strings.Contains(lower, k) {
			return true
		}
	}
	// bare "leak" / "race" only if not CI context
	if (strings.Contains(lower, "leak") || strings.Contains(lower, " race")) && !isCIContent(lower) {
		return true
	}
	return false
}

type llmOut struct {
	Decision string `json:"decision"`
	Reason   string `json:"reason"`
}

func (c *Classifier) classifyLLM(body, path, author string) (Result, error) {
	prompt := fmt.Sprintf(`You classify whether a human PR review comment is IN SCOPE for the "%s" adversary.

## Adversary mission and scope
%s

## Human comment
Author: %s
Path: %s

Body:
---
%s
---

Return ONLY JSON: {"decision":"in_scope"|"out_of_scope"|"unclear","reason":"one short sentence"}
Rules:
- Bot authors (copilot, dependabot, etc.) → out_of_scope
- PR overview / "Pull request overview" summary dumps → out_of_scope
- Docs/comment wording, style nits, GitHub suggestion-only comment rewrites → out_of_scope
- CI/GitHub Actions/workflow YAML concerns → out_of_scope for engineering-review (specialist)
- Correctness, completeness, maintainability risk, operational risk in application code → in_scope
- If unsure → unclear
`, c.AdversaryName, c.MissionMarkdown, author, path, body)

	raw, err := callOpenAIJSON(prompt)
	if err != nil {
		return Result{}, err
	}
	var out llmOut
	if err := json.Unmarshal(raw, &out); err != nil {
		if i := bytes.IndexByte(raw, '{'); i >= 0 {
			if j := bytes.LastIndexByte(raw, '}'); j > i {
				_ = json.Unmarshal(raw[i:j+1], &out)
			}
		}
	}
	d := Decision(strings.ToLower(strings.TrimSpace(out.Decision)))
	switch d {
	case InScope, OutOfScope, Unclear:
		return Result{Decision: d, Reason: out.Reason, Method: "llm"}, nil
	default:
		return Result{Decision: Unclear, Reason: "llm returned unusable decision", Method: "llm"}, nil
	}
}

func callOpenAIJSON(userPrompt string) ([]byte, error) {
	key := os.Getenv("OPENAI_API_KEY")
	if key == "" {
		return nil, fmt.Errorf("no OPENAI_API_KEY")
	}
	model := os.Getenv("FACTORY_SCOPE_MODEL")
	if model == "" {
		model = "gpt-4o-mini"
	}
	payload := map[string]any{
		"model": model,
		"messages": []map[string]string{
			{"role": "system", "content": "You are a careful classifier. Output only JSON."},
			{"role": "user", "content": userPrompt},
		},
		"temperature": 0,
	}
	body, _ := json.Marshal(payload)
	cmd := exec.Command("curl", "-sS", "https://api.openai.com/v1/chat/completions",
		"-H", "Authorization: Bearer "+key,
		"-H", "Content-Type: application/json",
		"-d", string(body),
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("openai: %w (%s)", err, truncate(string(out), 200))
	}
	var resp struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		return nil, err
	}
	if resp.Error != nil {
		return nil, fmt.Errorf("openai: %s", resp.Error.Message)
	}
	if len(resp.Choices) == 0 {
		return nil, fmt.Errorf("openai: empty choices")
	}
	return []byte(resp.Choices[0].Message.Content), nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
