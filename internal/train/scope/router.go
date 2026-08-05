package scope

import (
	"fmt"
	"path/filepath"
	"strings"
)

// Candidate is an adversary that can own a human comment.
type Candidate struct {
	ID            string
	AdversaryName string // display / package id
	Mission       string
	Languages     []string
	FileGlobs     []string
}

// Route is the chosen owner for one human comment (or none).
type Route struct {
	// OwnerID is the package id (e.g. go-concurrency) or "" if none.
	OwnerID string
	// Decision for the winning owner (in_scope) or out_of_scope if none.
	Decision Decision
	Reason   string
	Method   string
	// Scores optional debug: adversary id → brief reason
	Rejected []string
}

// Router picks the best adversary for a human comment among candidates.
type Router struct {
	Candidates []Candidate
	UseLLM     bool
}

// RouteComment selects the single best adversary or none.
func (r *Router) RouteComment(body, path, author string) Route {
	body = strings.TrimSpace(body)
	if body == "" {
		return Route{Decision: OutOfScope, Reason: "empty comment", Method: "heuristic"}
	}
	// Global rejects (apply before any specialist/LLM routing)
	if isReviewBot(strings.ToLower(author)) {
		return Route{Decision: OutOfScope, Reason: "bot/automated reviewer", Method: "heuristic"}
	}
	if isPROverviewBlob(body) {
		return Route{Decision: OutOfScope, Reason: "PR overview / summary dump", Method: "heuristic"}
	}
	// Global non-defect filters only (LGTM, soft-OK, package-doc nits, explicit nits).
	// Do not run eng-review-specific CI outs here — specialists must still own those.
	// Do not let LLM "rescue" non-defects into engineering-review false gold.
	if reason, ok := globalNonDefectOut(body, path); ok {
		return Route{Decision: OutOfScope, Reason: reason, Method: "heuristic"}
	}

	type scored struct {
		id     string
		score  int
		reason string
		dec    Decision
	}
	var hits []scored
	var rejected []string

	for _, cand := range r.Candidates {
		clf := &Classifier{
			MissionMarkdown: cand.Mission,
			AdversaryName:   cand.AdversaryName,
			UseLLM:          false, // per-candidate LLM is expensive; optional second pass below
		}
		// Hard path affinity for specialists
		pathBoost := pathAffinity(path, cand)
		res := clf.Classify(body, path, author)
		if res.Decision != InScope && pathBoost < 50 {
			// Still allow strong path match to force specialist ownership even if generic heuristic said out
			if pathBoost >= 50 {
				// re-check with path-aware force for CI etc.
				if isCIPath(strings.ToLower(path)) && strings.Contains(strings.ToLower(cand.ID), "githubactions") {
					res = Result{Decision: InScope, Reason: "workflow path → github-actions", Method: "heuristic"}
				} else if strings.HasSuffix(strings.ToLower(path), ".go") && strings.HasPrefix(cand.ID, "go-") {
					// don't force all go specialists in-scope
				}
			}
		}
		if res.Decision != InScope {
			// Path-forced specialists:
			if force, reason := forceSpecialist(path, body, cand); force {
				res = Result{Decision: InScope, Reason: reason, Method: "heuristic"}
			} else {
				rejected = append(rejected, cand.ID+": "+res.Reason)
				continue
			}
		}
		sc := 10 + pathBoost + keywordBoost(body, path, cand)
		hits = append(hits, scored{id: cand.ID, score: sc, reason: res.Reason, dec: InScope})
	}

	if len(hits) == 0 {
		// Optional: LLM multi-choice when enabled
		if r.UseLLM && len(r.Candidates) > 0 {
			if route, err := r.routeLLM(body, path, author); err == nil && route.OwnerID != "" {
				return route
			}
		}
		return Route{
			Decision: OutOfScope,
			Reason:   "no adversary claimed this comment (or only out-of-scope)",
			Method:   "heuristic",
			Rejected: rejected,
		}
	}

	// Prefer specialists over engineering-review when scores close.
	best := hits[0]
	for _, h := range hits[1:] {
		if h.score > best.score {
			best = h
			continue
		}
		if h.score == best.score {
			// Prefer more specific id over engineering-review / complexity
			if isGeneralist(best.id) && !isGeneralist(h.id) {
				best = h
			}
		}
	}
	// If engineering-review and a specialist both hit, require specialist to be close
	if isGeneralist(best.id) {
		for _, h := range hits {
			if !isGeneralist(h.id) && h.score >= best.score-5 {
				best = h
				break
			}
		}
	}

	return Route{
		OwnerID:  best.id,
		Decision: InScope,
		Reason:   fmt.Sprintf("%s (score %d): %s", best.id, best.score, best.reason),
		Method:   "heuristic",
		Rejected: rejected,
	}
}

func isGeneralist(id string) bool {
	return id == "engineering-review" || id == "complexity"
}

func pathAffinity(path string, cand Candidate) int {
	if path == "" {
		return 0
	}
	pl := strings.ToLower(path)
	id := strings.ToLower(cand.ID)
	boost := 0
	if isCIPath(pl) && (strings.Contains(id, "githubactions") || strings.Contains(id, "gitlabci") || strings.Contains(id, "depotci")) {
		boost += 80
	}
	if (strings.Contains(pl, "dockerfile") || strings.HasPrefix(filepath.Base(pl), "dockerfile")) && strings.Contains(id, "dockerfile") {
		boost += 80
	}
	if strings.Contains(pl, "docker-compose") && strings.Contains(id, "dockercompose") {
		boost += 80
	}
	if (strings.Contains(pl, "chart") || strings.HasSuffix(pl, ".yaml") && strings.Contains(pl, "helm")) && id == "helm" {
		boost += 40
	}
	if strings.HasSuffix(pl, ".go") && (strings.HasPrefix(id, "go") || id == "go") {
		boost += 15
	}
	if strings.HasSuffix(pl, "_test.go") && id == "go-testing" {
		boost += 40
	}
	if (strings.HasSuffix(pl, ".ts") || strings.HasSuffix(pl, ".tsx")) && (strings.Contains(id, "typescript") || strings.Contains(id, "react") || strings.Contains(id, "next")) {
		boost += 15
	}
	if strings.HasSuffix(pl, ".py") && id == "python" {
		boost += 20
	}
	if strings.HasSuffix(pl, ".tf") && id == "terraform" {
		boost += 80
	}
	// glob match
	for _, g := range cand.FileGlobs {
		if globMatch(g, path) {
			boost += 25
			break
		}
	}
	return boost
}

func forceSpecialist(path, body string, cand Candidate) (bool, string) {
	pl := strings.ToLower(path)
	bl := strings.ToLower(body)
	id := strings.ToLower(cand.ID)
	if isCIPath(pl) && strings.Contains(id, "githubactions") {
		return true, "GitHub Actions workflow path"
	}
	if isCIContent(bl) && !hasApplicationCodeSmell(bl) && strings.Contains(id, "githubactions") {
		return true, "CI/GitHub Actions content"
	}
	if strings.Contains(pl, "dockerfile") && strings.Contains(id, "dockerfile") {
		return true, "Dockerfile path"
	}
	if strings.HasSuffix(pl, ".tf") && id == "terraform" {
		return true, "Terraform path"
	}
	return false, ""
}

func keywordBoost(body, path string, cand Candidate) int {
	bl := strings.ToLower(body)
	id := strings.ToLower(cand.ID)
	n := 0
	add := func(words ...string) {
		for _, w := range words {
			if strings.Contains(bl, w) {
				n += 8
			}
		}
	}
	switch {
	case id == "go-concurrency":
		// Word-aware: bare "race" must not match "trace".
		add("data race", "goroutine", "mutex", "channel", "deadlock", "concurrent",
			"waitgroup", "synchron", "serialization", "overlapping", "thread-safe", "race condition",
			"forceflush", "busy-spin", "busy spin", "concurrency invariant")
		if containsWord(bl, "race") && (strings.Contains(bl, "data race") || strings.Contains(bl, "race condition") ||
			strings.Contains(bl, "race-free") || strings.Contains(bl, "racy") ||
			strings.Contains(bl, "race detector") || strings.Contains(bl, "datarace")) {
			n += 8
		} else if containsWord(bl, "race") && !strings.Contains(bl, "trace") && !strings.Contains(bl, "stacktrace") {
			// "race" alone only if not clearly about tracing
			n += 4
		}
		// Concurrent API / lifecycle test gaps — go-concurrency owns these even on _test.go
		if isConcurrentAPITestGap(bl) {
			n += 40
		}
	case id == "go-security":
		add("auth", "tls", "crypto", "secret", "token", "permission", "ssrf", "xss")
	case id == "go-testing":
		add("test", "coverage", "regression", "assert", "testmain", "flaky")
		// Do not steal concurrent-API gaps from go-concurrency
		if isConcurrentAPITestGap(bl) {
			n -= 25
		}
	case id == "go-http":
		add("http", "middleware", "handler", "timeout", "request body")
	case id == "go-database":
		add("sql", "transaction", "database", "db.", "migration")
	case id == "go-observability":
		add("metric", "telemetry", "cardinality", "instrumentation", "span attribute", "log attribute")
	case strings.Contains(id, "githubactions"):
		add("workflow", "runner", "privileged", "github actions", "gha", "codspeed")
	case id == "secrets":
		add("api key", "private key", "password", "credential", "-----begin")
	case id == "engineering-review":
		add("incomplete", "maintainab", "abstraction", "blast radius", "rollback", "caller")
		n += 2 // slight base so pure eng issues still land
	case id == "typescript":
		add("type", "typescript", "promise", "async")
	case id == "python":
		add("pickle", "shell=true", "yaml.load", "verify=false")
	}
	if strings.HasSuffix(strings.ToLower(path), "_test.go") && id == "go-testing" && !isConcurrentAPITestGap(bl) {
		n += 15
	}
	if strings.HasSuffix(strings.ToLower(path), "_test.go") && id == "go-concurrency" &&
		(strings.Contains(bl, "concurrent") || containsWord(bl, "race") || strings.Contains(bl, "overlapping") || isConcurrentAPITestGap(bl)) {
		n += 25
	}
	return n
}

// isConcurrentAPITestGap detects missing tests for concurrent API guarantees
// (overlapping Export/Flush/Shutdown, serialization under race, etc.).
func isConcurrentAPITestGap(bl string) bool {
	keys := []string{
		"concurrency invariant", "overlapping export", "overlapping `export",
		"export`, `forceflush`", "export, forceflush", "forceflush`, and `shutdown",
		"export/forceflush", "exporter-serialization", "exporter guarantee",
		"invoked them concurrently", "race across", "max-active", "max active",
		"onemit", "forceflush", "shutdown` race", "shutdown race",
	}
	for _, k := range keys {
		if strings.Contains(bl, k) {
			return true
		}
	}
	// overlapping + (export|flush|shutdown)
	if strings.Contains(bl, "overlapping") &&
		(strings.Contains(bl, "export") || strings.Contains(bl, "flush") || strings.Contains(bl, "shutdown")) {
		return true
	}
	if strings.Contains(bl, "concurrent") && strings.Contains(bl, "test") &&
		(strings.Contains(bl, "export") || strings.Contains(bl, "shutdown") || strings.Contains(bl, "flush")) {
		return true
	}
	return false
}

// containsWord reports whether whole word w appears in s (ASCII word chars).
func containsWord(s, w string) bool {
	if w == "" || !strings.Contains(s, w) {
		return false
	}
	// Reject substrings like "race" inside "trace".
	for i := 0; ; {
		j := strings.Index(s[i:], w)
		if j < 0 {
			return false
		}
		j += i
		beforeOK := j == 0 || !isWordChar(s[j-1])
		after := j + len(w)
		afterOK := after >= len(s) || !isWordChar(s[after])
		if beforeOK && afterOK {
			return true
		}
		i = j + 1
	}
}

func isWordChar(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '_'
}

func globMatch(pattern, path string) bool {
	// Very small subset: **/*.go, *.yml, exact suffix
	pattern = strings.ReplaceAll(pattern, "**/", "")
	pattern = strings.ReplaceAll(pattern, "**/", "")
	ok, err := filepath.Match(pattern, filepath.Base(path))
	if err == nil && ok {
		return true
	}
	ok, err = filepath.Match(pattern, path)
	return err == nil && ok
}

func (r *Router) routeLLM(body, path, author string) (Route, error) {
	// Build id list
	var ids []string
	var scopes strings.Builder
	for _, c := range r.Candidates {
		ids = append(ids, c.ID)
		fmt.Fprintf(&scopes, "### %s\n%s\n\n", c.ID, truncate(c.Mission, 800))
	}
	prompt := fmt.Sprintf(`Pick which adversary package should own this human PR comment for grading, or none.

Author: %s
Path: %s
Comment:
---
%s
---

Adversaries (id → scope excerpt):
%s

Return ONLY JSON: {"owner_id":"<id or empty>","reason":"one sentence"}
Rules:
- Prefer the most specific specialist over engineering-review when both fit
- Bot overviews → owner_id empty
- CI/workflow → githubactions (if present)
- Go concurrency races/lifecycle → go-concurrency (NOT eng-review)
- LGTM / "looks good" / "I'm more satisfied" / praise without a defect → empty
- Explicit nits, package docs, godoc wording, s/old/new/ rewrites → empty
- Soft OK notes ("I think its ok", "seems fine") without asking for a fix → empty
- Comments on pure documentation paths (.md, /docs/, book pages) that are wording/reference edits → empty (not product gold)
- Path/file name containing a specialist keyword is NOT enough — comment must match that specialist's mission (e.g. kustomize = mutable images/secrets/dangerous patches, not docs wording)
- engineering-review only for staff residual judgment no specialist owns; never dump leftovers there
- When unsure whether this is a real defect → empty (prefer no false miss)
- If none fit → empty owner_id
Valid ids: %s or empty
`, author, path, body, scopes.String(), strings.Join(ids, ", "))

	raw, err := callOpenAIJSON(prompt)
	if err != nil {
		return Route{}, err
	}
	// minimal parse
	s := string(raw)
	owner := ""
	if i := strings.Index(s, `"owner_id"`); i >= 0 {
		rest := s[i:]
		// "owner_id": "foo"
		if j := strings.Index(rest, `"`); j >= 0 {
			rest = rest[j+1:]
			// skip owner_id
			if k := strings.Index(rest, `"`); k >= 0 {
				rest = rest[k+1:]
				if m := strings.Index(rest, `"`); m >= 0 {
					rest = rest[m+1:]
					if n := strings.Index(rest, `"`); n >= 0 {
						owner = strings.TrimSpace(rest[:n])
					}
				}
			}
		}
	}
	// simpler: look for known ids in response
	if owner == "" {
		low := strings.ToLower(s)
		for _, c := range r.Candidates {
			if strings.Contains(low, `"`+c.ID+`"`) {
				owner = c.ID
				break
			}
		}
	}
	if owner == "" || owner == "empty" || owner == "none" || owner == "null" {
		return Route{Decision: OutOfScope, Reason: "llm: no owner", Method: "llm"}, nil
	}
	return Route{OwnerID: owner, Decision: InScope, Reason: "llm routing", Method: "llm"}, nil
}
