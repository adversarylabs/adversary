package scope

import (
	"encoding/json"
	"fmt"
	"path"
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
	// callLLM is injectable for focused routing tests. Production uses
	// callOpenAIJSON when this is nil.
	callLLM func(string) ([]byte, error)
}

type routeDecision struct {
	OwnerID            string `json:"owner_id"`
	Reason             string `json:"reason"`
	Material           bool   `json:"material"`
	Actionable         bool   `json:"actionable"`
	ChangeLocal        bool   `json:"change_local"`
	EngineeringPrimary bool   `json:"engineering_primary"`
	NonBlocking        bool   `json:"non_blocking"`
}

// RouteComment selects the single best adversary or none.
func (r *Router) RouteComment(body, path, author string) Route {
	body = NormalizeReviewComment(body)
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
	// Conversation artifacts are never gold, even when a broad persona package is
	// among the candidates. Previously one such candidate disabled non-defect
	// filtering for every sibling and let status replies route into nits/engineering.
	if reason, ok := NonActionableHumanComment(body); ok {
		return Route{Decision: OutOfScope, Reason: reason, Method: "heuristic"}
	}
	// Global non-defect filters (LGTM, soft-OK, package-doc nits, explicit nits).
	// Broad generalists skip these entirely — their mission owns every human comment
	// that reaches routing (bots already rejected above; empty already rejected).
	hasBroad := false
	hasNits := false
	for _, cand := range r.Candidates {
		if BroadScopeMission(cand.ID, cand.Mission) {
			hasBroad = true
		}
		if isNitsCandidate(cand.ID) {
			hasNits = true
		}
	}
	if !hasBroad {
		// Do not run eng-review-specific CI outs here — specialists must still own those.
		// Do not let LLM "rescue" non-defects into engineering-review false gold.
		if reason, ok := globalNonDefectOut(body, path); ok {
			// Explicit nits are valid gold when the dedicated nits package is loaded.
			// Its candidate classifier below still rejects defect-shaped comments.
			if !(hasNits && reason == "explicit nit / style-process feedback") {
				return Route{Decision: OutOfScope, Reason: reason, Method: "heuristic"}
			}
		}
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
		if ok, reason := candidatePathEligible(path, cand); !ok {
			rejected = append(rejected, cand.ID+": "+reason)
			continue
		}

		clf := &Classifier{
			MissionMarkdown: cand.Mission,
			AdversaryName:   cand.AdversaryName,
			UseLLM:          false, // per-candidate LLM is expensive; optional second pass below
		}
		// Hard path affinity for specialists
		pathBoost := pathAffinity(path, cand)
		var res Result
		if isNitsCandidate(cand.ID) {
			res = classifyNitsCandidate(body, path)
		} else {
			res = clf.Classify(body, path, author)
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
			if route, err := r.routeLLM(body, path, author); err == nil {
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

	// Generic defect heuristics deliberately cast a wide net and several
	// same-language specialists may claim the same comment. When model routing is
	// available, use the actual mission texts as final arbitration. Broad persona
	// packages retain their explicit "everything" semantics without this gate.
	if r.UseLLM && !hasBroad {
		if route, err := r.routeLLM(body, path, author); err == nil {
			return route
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

func isNitsCandidate(id string) bool {
	id = strings.ToLower(strings.TrimSpace(id))
	return id == "nits" || strings.HasSuffix(id, "/nits") || strings.HasSuffix(id, "-nits")
}

// candidatePathEligible enforces the package's declared file surfaces before
// generic defect heuristics get a chance to claim a comment. Declared file
// globs are authoritative even when language inference says "any". Without a
// retained path, only language-neutral or legacy candidates remain eligible.
func candidatePathEligible(path string, cand Candidate) (bool, string) {
	if strings.TrimSpace(path) == "" {
		if len(cand.FileGlobs) > 0 && !hasUniversalFileGlob(cand.FileGlobs) {
			return false, fmt.Sprintf("no file path evidence for declared file globs %v", cand.FileGlobs)
		}
		if len(cand.Languages) == 0 || containsFold(cand.Languages, "any") {
			return true, ""
		}
		return false, fmt.Sprintf("no file path evidence for declared surfaces %v", cand.Languages)
	}
	if len(cand.FileGlobs) > 0 {
		for _, pattern := range cand.FileGlobs {
			if globMatch(pattern, path) {
				return true, ""
			}
		}
		return false, fmt.Sprintf("path %q does not match declared file globs", path)
	}
	if len(cand.Languages) == 0 || containsFold(cand.Languages, "any") {
		return true, ""
	}
	return false, fmt.Sprintf("path %q has no matching declared file surface %v", path, cand.Languages)
}

// candidateModelEligible is intentionally broader than candidatePathEligible.
// Runtime trigger/detection globs describe where an adversary currently runs;
// they are not the package's mission boundary. Training must be able to surface
// a same-language gap outside those globs so the resulting improvement can
// broaden activation. Cross-language and pathless mismatches still fail closed.
func candidateModelEligible(candidatePath string, cand Candidate) (bool, string) {
	if ok, _ := candidatePathEligible(candidatePath, cand); ok {
		return true, "exact runtime file surface"
	}
	if strings.TrimSpace(candidatePath) == "" {
		return false, "no file path evidence for same-language scope fallback"
	}
	for _, language := range cand.Languages {
		if strings.EqualFold(strings.TrimSpace(language), "any") {
			continue
		}
		if pathMatchesLanguage(candidatePath, language) {
			return true, fmt.Sprintf("same-language scope fallback (%s); current runtime globs do not match", language)
		}
	}
	return false, fmt.Sprintf("path %q does not match the candidate's runtime or language surface", candidatePath)
}

func pathMatchesLanguage(candidatePath, language string) bool {
	ext := strings.ToLower(filepath.Ext(candidatePath))
	base := strings.ToLower(filepath.Base(candidatePath))
	switch strings.ToLower(strings.TrimSpace(language)) {
	case "go":
		return ext == ".go"
	case "typescript":
		return ext == ".ts" || ext == ".tsx"
	case "javascript":
		return ext == ".js" || ext == ".jsx" || ext == ".mjs" || ext == ".cjs"
	case "python":
		return ext == ".py"
	case "rust":
		return ext == ".rs"
	case "java":
		return ext == ".java"
	case "ci":
		return isCIPath(strings.ToLower(candidatePath))
	case "dockerfile":
		return strings.Contains(base, "dockerfile")
	case "terraform":
		return ext == ".tf"
	default:
		return false
	}
}

func hasUniversalFileGlob(patterns []string) bool {
	for _, pattern := range patterns {
		switch strings.TrimSpace(pattern) {
		case "*", "**", "**/*":
			return true
		}
	}
	return false
}

func containsFold(values []string, want string) bool {
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), want) {
			return true
		}
	}
	return false
}

// classifyNitsCandidate keeps review/nits focused on non-blocking maintainer
// taste. The shared classifier intentionally recognizes material defects across
// languages, which is exactly what this package must not absorb.
func classifyNitsCandidate(body, path string) Result {
	_, _ = body, path
	return Result{
		Decision: OutOfScope,
		Reason:   "nits ownership requires scope-aware LLM confirmation of non-blocking intent",
		Method:   "heuristic",
	}
}

func isGeneralist(id string) bool {
	id = strings.ToLower(id)
	return id == "engineering-review" || id == "complexity" ||
		strings.HasPrefix(id, "person-") || strings.Contains(id, "torvalds")
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

func globMatch(pattern, candidatePath string) bool {
	pattern = strings.TrimSpace(strings.ReplaceAll(pattern, "\\", "/"))
	candidatePath = strings.TrimPrefix(strings.ReplaceAll(candidatePath, "\\", "/"), "./")
	if pattern == "" || candidatePath == "" {
		return false
	}

	// A basename-only pattern applies at any depth, matching common manifest
	// entries such as "*.go" without weakening path-qualified entries.
	if !strings.Contains(pattern, "/") {
		ok, err := path.Match(pattern, path.Base(candidatePath))
		return err == nil && ok
	}

	return matchGlobSegments(strings.Split(pattern, "/"), strings.Split(candidatePath, "/"))
}

func matchGlobSegments(pattern, candidate []string) bool {
	if len(pattern) == 0 {
		return len(candidate) == 0
	}
	if pattern[0] == "**" {
		if matchGlobSegments(pattern[1:], candidate) {
			return true
		}
		for i := range candidate {
			if matchGlobSegments(pattern[1:], candidate[i+1:]) {
				return true
			}
		}
		return false
	}
	if len(candidate) == 0 {
		return false
	}
	ok, err := path.Match(pattern[0], candidate[0])
	return err == nil && ok && matchGlobSegments(pattern[1:], candidate[1:])
}

func (r *Router) routeLLM(body, path, author string) (Route, error) {
	// Exact runtime globs remain the deterministic routing boundary. The scope
	// model may additionally consider same-language candidates so training can
	// discover that an adversary's current activation surface is too narrow.
	var eligible []Candidate
	eligibility := map[string]string{}
	for _, candidate := range r.Candidates {
		if ok, reason := candidateModelEligible(path, candidate); ok {
			eligible = append(eligible, candidate)
			eligibility[candidate.ID] = reason
		}
	}
	if len(eligible) == 0 {
		return Route{Decision: OutOfScope, Reason: "no adversary matches the retained file surface", Method: "llm"}, nil
	}

	var ids []string
	var scopes strings.Builder
	for _, c := range eligible {
		ids = append(ids, c.ID)
		fmt.Fprintf(&scopes, "### %s\nFile-surface evidence: %s\n%s\n\n", c.ID, eligibility[c.ID], truncate(c.Mission, 800))
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

Return ONLY JSON: {"owner_id":"<id or empty>","reason":"one sentence","material":true|false,"actionable":true|false,"change_local":true|false,"engineering_primary":true|false,"non_blocking":true|false}
Rules:
- Prefer the most specific specialist over engineering-review when both fit
- Bot overviews → owner_id empty
- CI/workflow → githubactions (if present)
- Go concurrency races/lifecycle → go-concurrency (NOT eng-review)
- LGTM / "looks good" / "I'm more satisfied" / praise without a defect → empty
- Author status replies ("Fixed in <sha>", "Updated", "Addressed") → empty, even when they explain the fix
- Rebuttals / resolutions ("don't need to worry", "no action needed", "working as intended") → empty unless they contain a new explicit review request
- Explanations and summaries without an unresolved request are conversation context, not gold → empty
- Explicit non-blocking taste → nits when present; package docs, godoc wording, and s/old/new/ rewrites → empty
- Soft OK notes ("I think its ok", "seems fine") without asking for a fix → empty
- Comments on pure documentation paths (.md, /docs/, book pages) that are wording/reference edits → empty (not product gold)
- Path/file name containing a specialist keyword is NOT enough — comment must match that specialist's mission (e.g. kustomize = mutable images/secrets/dangerous patches, not docs wording)
- Runtime trigger/detection globs describe current activation, not the package mission. A same-language candidate outside those globs may own the concern when its scope clearly matches; training may need to broaden activation.
- Judge the stated behavior, not the reviewer's emoji or gentle tone. Explicitly accepted input that is silently ignored or contradicted is a concrete present-day consequence.
- engineering-review only for staff residual judgment no specialist owns; never dump leftovers there
- nits only for pure maintainer taste with no correctness, security, API, or operational consequence; set non_blocking=true only for that case
- Any non-empty owner requires a concrete present-day consequence, a proportionate action, and a concern introduced/expanded/relied on by this change
- Pre-existing observations, hypothetical future traps, explanatory notes, and generic requests for tests → empty
- Set engineering_primary=true only when the primary issue is a broader engineering principle rather than language mechanics, framework convention, security, observability, infrastructure, pure complexity, or detailed test technique
- When unsure whether this is material and actionable → empty (prefer no false miss)
- If none fit → empty owner_id
Valid ids: %s or empty
`, author, path, body, scopes.String(), strings.Join(ids, ", "))

	call := r.callLLM
	if call == nil {
		call = callOpenAIJSON
	}
	raw, err := call(prompt)
	if err != nil {
		return Route{}, err
	}
	var out routeDecision
	if err := json.Unmarshal(raw, &out); err != nil {
		if i := strings.IndexByte(string(raw), '{'); i >= 0 {
			if j := strings.LastIndexByte(string(raw), '}'); j > i {
				_ = json.Unmarshal(raw[i:j+1], &out)
			}
		}
	}
	return routeFromLLMDecisionForPath(out, eligible, path), nil
}

func routeFromLLMDecisionForPath(out routeDecision, candidates []Candidate, path string) Route {
	route := routeFromLLMDecision(out, candidates)
	if route.OwnerID == "" {
		return route
	}
	for _, candidate := range candidates {
		if candidate.ID != route.OwnerID {
			continue
		}
		if ok, reason := candidateModelEligible(path, candidate); !ok {
			return Route{Decision: OutOfScope, Reason: "llm owner outside model-eligible file surface: " + reason, Method: "llm"}
		}
		return route
	}
	return Route{Decision: OutOfScope, Reason: "llm: unknown owner", Method: "llm"}
}

func routeFromLLMDecision(out routeDecision, candidates []Candidate) Route {
	owner := strings.TrimSpace(out.OwnerID)
	if owner == "" || owner == "empty" || owner == "none" || owner == "null" {
		reason := strings.TrimSpace(out.Reason)
		if reason == "" {
			reason = "llm: no owner"
		}
		return Route{Decision: OutOfScope, Reason: reason, Method: "llm"}
	}
	validOwner := false
	for _, candidate := range candidates {
		if owner == candidate.ID {
			validOwner = true
			break
		}
	}
	if !validOwner {
		return Route{Decision: OutOfScope, Reason: "llm: unknown owner", Method: "llm"}
	}
	if !out.Material || !out.Actionable || !out.ChangeLocal {
		return Route{Decision: OutOfScope, Reason: "llm gate: concern is not material, actionable, and change-local", Method: "llm"}
	}
	if isNitsCandidate(owner) && !out.NonBlocking {
		return Route{Decision: OutOfScope, Reason: "llm gate: nits owner is not explicitly non-blocking", Method: "llm"}
	}
	if isGeneralist(owner) && strings.Contains(strings.ToLower(owner), "engineering") && !out.EngineeringPrimary {
		return Route{Decision: OutOfScope, Reason: "llm gate: engineering-review is not the primary owner", Method: "llm"}
	}
	reason := strings.TrimSpace(out.Reason)
	if reason == "" {
		reason = "llm routing passed gold-quality gates"
	}
	return Route{OwnerID: owner, Decision: InScope, Reason: reason, Method: "llm"}
}
