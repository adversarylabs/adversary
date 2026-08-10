package scope

import (
	"strings"
	"testing"
)

func TestHeuristicSuggestionDocOutOfScope(t *testing.T) {
	c := &Classifier{AdversaryName: "engineering-review", UseLLM: false}
	body := "```suggestion\n// randomFloat64 returns a pseudo-random value uniformly selected from\n// {k / 2^53 | 1 <= k < 2^53}.\n```"
	r := c.Classify(body, "sdk/metric/exemplar/next_tracker.go", "alice")
	if r.Decision != OutOfScope {
		t.Fatalf("got %s (%s)", r.Decision, r.Reason)
	}
}

func TestHeuristicRaceInScope(t *testing.T) {
	c := &Classifier{AdversaryName: "go-concurrency", UseLLM: false}
	body := "There is a data race on the bounds slice when Observe is concurrent with View reconfiguration."
	r := c.Classify(body, "sdk/metric/histogram.go", "alice")
	if r.Decision != InScope {
		t.Fatalf("got %s (%s)", r.Decision, r.Reason)
	}
}

func TestHeuristicNilLeakInScope(t *testing.T) {
	c := &Classifier{AdversaryName: "go-concurrency", UseLLM: false}
	body := "This goroutine can leak after Shutdown if the context is not cancelled."
	r := c.Classify(body, "sdk/trace/span_processor.go", "bob")
	if r.Decision != InScope {
		t.Fatalf("got %s", r.Decision)
	}
}

func TestShortNitOutOfScope(t *testing.T) {
	c := &Classifier{UseLLM: false, AdversaryName: "engineering-review"}
	r := c.Classify("nit: rename this var", "foo.go", "alice")
	if r.Decision != OutOfScope {
		t.Fatalf("got %s", r.Decision)
	}
}

func TestBroadMissionNitInScope(t *testing.T) {
	mission := `# torvalds-adversary
## In scope
**Everything technical about the change.** Including nits.
## Out of scope
Almost nothing. Only exclude bot noise.
Default rule: if you are unsure whether something is in scope, it is in scope.
`
	c := &Classifier{
		AdversaryName:   "torvalds",
		MissionMarkdown: mission,
		UseLLM:          false,
	}
	r := c.Classify("nit: rename this var for clarity", "core/qt-ble.cpp", "torvalds")
	if r.Decision != InScope {
		t.Fatalf("broad mission nit should be in scope, got %s (%s)", r.Decision, r.Reason)
	}
}

func TestBroadMissionTorvaldsStyleCommentInScope(t *testing.T) {
	c := &Classifier{
		AdversaryName:   "torvalds",
		MissionMarkdown: "Everything is in scope. Do not exclude nits.",
		UseLLM:          false,
	}
	body := "Yeah, a lambda expression is certainly _conceptually_ the right thing to do.\n\nMaybe C++ compilers even do them right these days."
	r := c.Classify(body, "core/qt-ble.cpp", "torvalds")
	if r.Decision != InScope {
		t.Fatalf("got %s (%s)", r.Decision, r.Reason)
	}
}

func TestBroadMissionRejectsPraiseButKeepsNits(t *testing.T) {
	c := &Classifier{
		AdversaryName:   "torvalds",
		MissionMarkdown: "Everything is in scope.",
		UseLLM:          false,
	}
	// Even a person generalist learns review behavior, not conversation status.
	if r := c.Classify("LGTM", "foo.go", "torvalds"); r.Decision != OutOfScope {
		t.Fatalf("LGTM should not become gold, got %s (%s)", r.Decision, r.Reason)
	}
	if r := c.Classify("nit: rename this", "foo.go", "torvalds"); r.Decision != InScope {
		t.Fatalf("nit should be in scope, got %s", r.Decision)
	}
	if r := c.Classify("please fix the race", "foo.go", "dependabot[bot]"); r.Decision != OutOfScope {
		t.Fatalf("bot should stay out, got %s", r.Decision)
	}
}

func TestAutomatedReviewArtifactBehindHumanAccountIsOutOfScope(t *testing.T) {
	c := &Classifier{AdversaryName: "nits", UseLLM: false}
	body := "This is a correct, minimal fix applied consistently across all handlers.\n\n- Worth a grep for any remaining copy.\n\n<!-- hermes-pr-review da4eaa1 -->"
	r := c.Classify(body, "toolbar.tsx", "human-maintainer")
	if r.Decision != OutOfScope {
		t.Fatalf("embedded automation marker should prevent gold, got %s (%s)", r.Decision, r.Reason)
	}
}

func TestDeclarativePraiseSummaryIsOutOfScope(t *testing.T) {
	for _, body := range []string{
		"This is a correct, minimal fix applied consistently across all handlers.",
		"The fix is sound and well-scoped.",
		"The change is a safe cleanup with no behavior change.",
	} {
		if reason, ok := NonActionableHumanComment(body); !ok {
			t.Errorf("praise remained actionable: %q (%s)", body, reason)
		}
	}
}

func TestBroadScopeMissionDetection(t *testing.T) {
	if !BroadScopeMission("torvalds", "") {
		t.Fatal("torvalds id should be broad")
	}
	if BroadScopeMission("engineering-review", "everything is in scope") {
		t.Fatal("engineering-review must not be broad even if text matches")
	}
	if !BroadScopeMission("my-package", "if you are unsure whether something is in scope, it is in scope") {
		t.Fatal("mission text should mark package broad")
	}
}

func TestCopilotOverviewOutOfScope(t *testing.T) {
	c := &Classifier{AdversaryName: "engineering-review", UseLLM: false}
	body := `## Pull request overview
This PR updates the benchmark GitHub Actions workflow to restore CodSpeed benchmark execution after moving the job into a container environment.`
	r := c.Classify(body, "", "copilot-pull-request-reviewer[bot]")
	if r.Decision != OutOfScope {
		t.Fatalf("got %s (%s)", r.Decision, r.Reason)
	}
}

func TestGHAPrivilegedOutOfScopeForEngReview(t *testing.T) {
	c := &Classifier{AdversaryName: "engineering-review", UseLLM: false}
	body := "Using `--privileged` gives the job container broad access to the host, which is a high-risk configuration on a self-hosted runner. If CodSpeed only needs profiling/trace capabilities, prefer granting…"
	r := c.Classify(body, ".github/workflows/benchmark.yml", "Copilot")
	if r.Decision != OutOfScope {
		t.Fatalf("got %s (%s) — CI privileged belongs to github-actions, not eng-review", r.Decision, r.Reason)
	}
}

func TestHumanBotAuthorOutOfScope(t *testing.T) {
	c := &Classifier{AdversaryName: "engineering-review", UseLLM: false}
	// Even a "real" engineering sentence from a bot is ignored for gold.
	r := c.Classify("This goroutine can leak after Shutdown.", "main.go", "dependabot[bot]")
	if r.Decision != OutOfScope {
		t.Fatalf("got %s", r.Decision)
	}
}

func TestLGTMSatisfactionOutOfScope(t *testing.T) {
	c := &Classifier{AdversaryName: "engineering-review", UseLLM: false}
	body := "I'm more satisfied with this change compared to initial plans. Despite the size of the PR, its a simplified refactoring, which moves truncation logic in shared internal template package and repurpose it as `attrnorm`.\n\nKeeping truncation logic in a separate file is good.\n\nThere are no logical path changes apart from 1 small conditional logic as a result of unifying value truncation.\n\nA `nit` on package comment, but nothing blocking. LGTM"
	r := c.Classify(body, "", "ps-mir")
	if r.Decision != OutOfScope {
		t.Fatalf("LGTM/satisfaction should be out of scope, got %s (%s)", r.Decision, r.Reason)
	}
}

func TestNormalizeReviewCommentRemovesGuidanceButKeepsIntent(t *testing.T) {
	body := `<!-- Thoughts represent an idea that popped up from reviewing. These comments are non-blocking by nature, but they are extremely valuable. -->
**thought:** something about mounting the git directory feels weird. Would setting :ro make sense so the external directory is read-only and prevents permission collisions?`

	normalized := normalizeReviewComment(body)
	if strings.Contains(strings.ToLower(normalized), "non-blocking") {
		t.Fatalf("template guidance survived normalization: %q", normalized)
	}
	if !strings.Contains(normalized, "Would setting :ro") {
		t.Fatalf("reviewer intent was removed: %q", normalized)
	}
	if reason, rejected := NonActionableHumanComment(body); rejected {
		t.Fatalf("actionable review was rejected as %q before routing", reason)
	}
	if reason, rejected := globalNonDefectOut(normalized, "docker-compose.yml"); rejected {
		t.Fatalf("actionable review was rejected as %q after normalization", reason)
	}
}

func TestNormalizeReviewCommentPreservesAutomationProvenance(t *testing.T) {
	body := "Useful-looking review text.\n\n<!-- hermes-pr-review abc123 -->"
	if normalized := normalizeReviewComment(body); normalized != body {
		t.Fatalf("unknown provenance marker changed: %q", normalized)
	}
}

func TestContextDependentReviewFragmentIsNotGold(t *testing.T) {
	vague := `<!-- Questions are appropriate if you have a potential concern but are not quite sure if it's relevant or not. -->
**question:** should this be excised as well?`
	if reason, rejected := NonActionableHumanComment(vague); !rejected || !strings.Contains(reason, "context-dependent") {
		t.Fatalf("vague fragment was not rejected: rejected=%v reason=%q", rejected, reason)
	}

	causal := `<!-- Thoughts represent an idea that popped up from reviewing. These comments are non-blocking by nature. -->
**thought:** something about mounting the git directory feels weird. Would setting :ro make sense so the external directory is read-only and prevents permission collisions?`
	if reason, rejected := NonActionableHumanComment(causal); rejected {
		t.Fatalf("self-contained concern was rejected as %q", reason)
	}
}

func TestPackageDocNitOutOfScope(t *testing.T) {
	c := &Classifier{AdversaryName: "engineering-review", UseLLM: false}
	body := "Nit; more description on package\n```go\n// Package attrnorm normalizes attribute values by:\n//\n//   - Deduplication: resolves duplicate map keys\n```"
	r := c.Classify(body, "internal/shared/attrnorm/dedup.go.tmpl", "ps-mir")
	if r.Decision != OutOfScope {
		t.Fatalf("package doc nit should be out of scope, got %s (%s)", r.Decision, r.Reason)
	}
}

func TestSoftOKObservationOutOfScope(t *testing.T) {
	c := &Classifier{AdversaryName: "engineering-review", UseLLM: false}
	body := "Among all changes this is the only condition that gets added for trace. But i think its ok as there are no spec-level difference between span and log truncation semantics."
	r := c.Classify(body, "internal/shared/attrnorm/truncate.go.tmpl", "ps-mir")
	if r.Decision != OutOfScope {
		t.Fatalf("soft OK observation should be out of scope, got %s (%s)", r.Decision, r.Reason)
	}
}

func TestDocsPathSedNitOutOfScope(t *testing.T) {
	c := &Classifier{AdversaryName: "kustomize", UseLLM: false}
	body := "s/Providers/Generators/ everywhere.\n\nI think this horse left the barn."
	r := c.Classify(body, "docs/book/pages/reference/kustomize.md", "monopole")
	if r.Decision != OutOfScope {
		t.Fatalf("docs sed-nit should be out of scope, got %s (%s)", r.Decision, r.Reason)
	}
}

func TestDocsPathReferenceTextOutOfScope(t *testing.T) {
	// Doc-path comments without defect language are not product gold for any adversary.
	c := &Classifier{AdversaryName: "kustomize", UseLLM: false}
	body := "Teach kustomize about your custom resources by providing a CRD."
	r := c.Classify(body, "docs/book/pages/reference/kustomize.md", "monopole")
	if r.Decision != OutOfScope {
		t.Fatalf("docs-path reference wording should be out of scope, got %s (%s)", r.Decision, r.Reason)
	}
}

func TestGlobalNonDefectDocsPath(t *testing.T) {
	reason, ok := globalNonDefectOut(
		"Add a prefix to the names of all resources",
		"docs/book/pages/reference/kustomize.md",
	)
	if !ok {
		t.Fatal("expected docs path to be global non-defect")
	}
	if reason == "" {
		t.Fatal("expected reason")
	}
}

func TestProcessBackportTodoOutOfScope(t *testing.T) {
	c := &Classifier{AdversaryName: "engineering-review", UseLLM: false}
	body := "Claude suggested that tracking the upstream Makefile would make future backports more reliable. If we want this - do it on `main` first and backport.\n\nI have a todo item to fix a number of make related issues. It think this can go on that list."
	r := c.Classify(body, "Makefile", "jnewbigin")
	if r.Decision != OutOfScope {
		t.Fatalf("process/backport/todo should be out of scope, got %s (%s)", r.Decision, r.Reason)
	}
}

func TestDockerAgentApproveOutOfScope(t *testing.T) {
	c := &Classifier{AdversaryName: "githubactions", UseLLM: false}
	body := "### Assessment: 🟢 APPROVE\n\nThis PR replaces long-lived Docker Hub PAT secrets with short-lived OIDC tokens via registry-identities. This is a clear security improvement."
	r := c.Classify(body, ".github/workflows/publish.yml", "docker-agent")
	if r.Decision != OutOfScope {
		t.Fatalf("docker-agent APPROVE assessment must be out of scope, got %s (%s)", r.Decision, r.Reason)
	}
}

func TestRouterDockerAgentNotGHA(t *testing.T) {
	r := &Router{
		Candidates: []Candidate{
			{ID: "githubactions", AdversaryName: "githubactions", Mission: "GHA workflows"},
			{ID: "engineering-review", AdversaryName: "engineering-review", Mission: "staff"},
		},
		UseLLM: false,
	}
	route := r.RouteComment(
		"### Assessment: 🟢 APPROVE\n\nThis PR replaces long-lived Docker Hub PAT secrets with OIDC.",
		".github/workflows/publish.yml",
		"docker-agent",
	)
	if route.OwnerID != "" {
		t.Fatalf("APPROVE bot assessment must not own: %+v", route)
	}
}

func TestRouterProcessNotEngReview(t *testing.T) {
	r := &Router{
		Candidates: []Candidate{
			{ID: "engineering-review", AdversaryName: "engineering-review", Mission: "staff eng judgment"},
		},
		UseLLM: false,
	}
	route := r.RouteComment(
		"Claude suggested that tracking the upstream Makefile would make future backports more reliable. If we want this - do it on main first and backport. I have a todo item.",
		"Makefile",
		"jnewbigin",
	)
	if route.OwnerID != "" || route.Decision != OutOfScope {
		t.Fatalf("expected none, got owner=%q dec=%s reason=%s", route.OwnerID, route.Decision, route.Reason)
	}
}
