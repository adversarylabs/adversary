# Goal: Iterate adversary-factory until it both trusts its grades and suggests real product improvements

**Audience:** Coding agent (or human) with access to the `adversarylabs` monorepo siblings.  
**When:** After any in-flight `factory slice` finishes (or use a fresh `--data-root`).  
**Do not** file GitHub issues or publish adversary releases unless the human explicitly asks later.

---

## Mission

Run the live factory, read the plain-English story, fix **factory/routing/scope/labeling** bugs that produce false BAD results or mis-owned misses, re-run, and repeat until a run meets the definition of done below.

**Done is not “no false positives.”** Clean attribution is necessary but not sufficient. Success means the factory can also surface **at least one meaningful, correctly owned improvement** that a human would consider a fair gap for some sibling adversary (draft suggested issue only — do not auto-file).

**`engineering-review` is not a dumping ground.** If a suggested issue (or graded miss) lands on `engineering-review`, that package must be the **best** owner — staff/principal judgment that no specialist owns. Routing concurrency → eng-review, CI → eng-review, package-doc nits → eng-review, language mechanics → eng-review, or “default when unsure” → eng-review is a **failure mode**, not progress.

Outcomes that are **not** done:

1. **Noise-free but empty product signal** — everything ignored or GOOD with zero substantive suggested issues.
2. **Lots of “misses” that are really factory bugs** — bot gold, wrong owner, nits, CI misroutes, etc.
3. **Dump-to-eng-review** — any suggested issue or in-scope miss labeled `engineering-review` when a sibling specialist (`go-concurrency`, `githubactions`, `go`, `go-testing`, `go-security`, …) is a better fit, or when the comment should have been ignored entirely.

---

## Context (already built)

- **Repo:** `adversarylabs/adversary-factory` (private), sibling to `*-adversary` packages under `github.com/adversarylabs/`.
- **CLI:** `make build && ./bin/factory slice --data-root <dir>` (no `--source` required if siblings exist).
- **Outputs to read first:**  
  - stderr hunt progress  
  - `$DATA_ROOT/LATEST_STORY.md`  
  - `$DATA_ROOT/experiments/*/STORY.md`  
  - `$DATA_ROOT/experiments/*/SUGGESTED_ISSUES.md` (drafts only — do not auto-file)
- **Key behaviors:** multi-repo catalog (`config/repositories.json`), max-turns hunt, per-repo seen-PR state, multi-adversary routing via each package’s `docs/scope.md`, eng-review mission excludes bots/CI/docs nits (with remaining gaps).

---

## Definition of done

A single live run (or a short sequence of runs with the same `data-root`) is **done** when **all** of the following hold.

### 1. Operational

- [ ] `make build` succeeds.
- [ ] `./bin/factory slice --data-root <fresh-or-chosen-dir>` completes with exit 0 **or** a documented blocked exit (20) with a clear next action — not a crash.
- [ ] Hunt progress on stderr shows: loaded sibling count, repo/PR under try, keep/skip reason.
- [ ] Final CLI prints BOTTOM LINE + path to `STORY.md`.
- [ ] Story and suggested-issues files exist and are readable.

### 2. Attribution quality (necessary, not sufficient)

On the **final** story for that run:

- [ ] **No bot gold:** comments from Copilot / `*[bot]` / dependabot-style authors are never “in-scope miss.”
- [ ] **No PR-overview gold:** “Pull request overview” / summary dumps are never graded as misses.
- [ ] **No pure nit/docs gold:** explicit nits, grammar, godoc-only, comment-wording-only are out of scope / ignored.
- [ ] **CI/GHA comments** (workflow paths, `--privileged` runners, CodSpeed job config, etc.) are **not** attributed to `engineering-review`; they go to `githubactions` (or none), not eng-review misses.
- [ ] **Concurrency-invariant / concurrent API test gaps** on Go code are attributed to **`go-concurrency`** (or `go-testing` when purely test-harness), **never** only to `engineering-review`, when that is the clear fit.
- [ ] **Specialists before generalist:** CI → `githubactions` (etc.); Go concurrency/lifecycle → `go-concurrency`; language-surface TLS/shell/fs → `go`; pure tests harness → `go-testing`; secrets → `secrets` / `go-security` as appropriate. Prefer **out of scope / none** over parking leftover noise on eng-review.
- [ ] Story text for each gold line names the **owner adversary** (`gold → go-concurrency: …` / “Miss for `go-concurrency`”).
- [ ] Suggested issues titles/labels name the **owning** adversary package, not a wrong generalist.
- [ ] **Eng-review ownership bar (hard):** every miss or suggested issue owned by `engineering-review` must pass the eng-review best-owner test in §3a. If any fails, **not done** — fix routing/scope and re-run.

### 3. Product improvement (required for success)

At least **one** graded miss on the final run must be a **true product gap** for its owning adversary, with a corresponding draft suggested issue that is worth a human’s time.

**Meaningful improvement means all of:**

- [ ] **True gap, not factory bug:** a human engineer would agree the named adversary *should* have raised something like this, and the miss is not bot/CI/nit/misroute/LGTM/soft-OK noise.
- [ ] **Correct owner (best fit, not dump):** the suggested issue targets the **most specific** package that owns that concern. Matching story ownership is necessary but not enough if both story and issue are wrong.
- [ ] **Actionable draft:** `SUGGESTED_ISSUES.md` (or story equivalent) has a concrete title + body a maintainer could use — not vague “improve detection” fluff, not a dump of the human comment alone with no product ask.
- [ ] **In mission:** the gap sits inside that adversary’s `docs/scope.md` mission (or a justified scope tweak you made and documented). Out-of-mission “improvements” do not count.
- [ ] **At least one such issue** across the whole final experiment — any one adversary is enough; you do not need one per package. A specialist-owned meaningful issue is preferred when the gold is specialist-shaped.

#### 3a. When owner is `engineering-review` (mandatory extra bar)

`engineering-review` is the **staff/principal residual**: cross-cutting correctness, incompleteness, maintainability, blast radius, architectural fit — **only** when no specialist is the better owner.

For **every** graded miss and **every** suggested issue labeled `adversary:engineering-review` / titled `engineering-review: …`, **all** of the following must hold or the run is **not done**:

- [ ] **Best place, not leftover bin:** a human maintainer would file this against eng-review, not against `go-concurrency`, `githubactions`, `go`, `go-testing`, `go-security`, `go-observability`, or another sibling.
- [ ] **Not specialist-shaped:** the concern is not primarily concurrency/races/lifecycle, CI/workflows, secrets/auth deep-dive, pure language/TLS/shell/fs idioms, test-harness technique, or other scoped specialist missions.
- [ ] **Not noise:** not LGTM/approval, soft “I think it’s ok”, package-doc/godoc nits, bot/overview, pure style.
- [ ] **Mission fit:** aligns with eng-review `docs/scope.md` **in scope** (staff engineering judgment), not its out-of-scope list.
- [ ] **Evidence in the agent note:** one sentence defending *why eng-review is the best owner* (e.g. “incomplete remediation across callers — no specialist owns multi-path completeness”). If you cannot write that defense honestly, **re-route or ignore** — do not ship eng-review gold.

**Failure mode (explicit):** “Something looked like a miss, so we put it on engineering-review.” That is **failed**. Prefer specialist, or ignore, or keep hunting — never dump.

If the only “improvements” in a run are eng-review dumps that fail §3a, they **do not count** toward the product-improvement requirement.

If the only clean runs are all-GOOD / all-ignored with **zero** true product gaps, **keep hunting** (more turns/PRs, more repos, different data root) or improve discovery/selection until a real gap appears. Do **not** declare done on a sterile trustworthy run.

If every “miss” fails the meaningfulness bar or the eng-review best-owner bar, fix attribution/scope first, then re-run until a real, correctly owned gap remains after noise is stripped.

### 4. Consistency

- [ ] No contradictory story sections for the same case (e.g. “no in-scope gold” on r1/r2 while r3 holds all gold **without explanation**). Either fix multi-round labeling so gold attaches correctly per review round, or the story must explain rounds clearly without double-counting.
- [ ] “What engineering-review said” (or the owning adversary) is accurate: if the tool produced findings, they appear; if the run was blocked, the story says blocked — not “did not produce findings” when the real issue was model/checkout failure.
- [ ] Verdict logic: **GOOD** when no in-scope misses (including “everything ignored as out of scope”); **BAD/MIXED** only when in-scope misses or real unaligned findings exist for the **owning** adversary. A successful “done” run that carries a true product gap will typically be **BAD** or **MIXED**, not GOOD-only.

### 5. Evidence saved for the human

Under the data root (or a small note in the factory repo if appropriate):

- [ ] Path to final `STORY.md` and `SUGGESTED_ISSUES.md`.
- [ ] Explicit callout of **which** suggested issue is the “meaningful improvement” proof (adversary name + title + one-line why it is fair).
- [ ] Short agent note (can be end of chat or `docs/last-iteration-notes.md`) listing: what was wrong, what you changed (files), what the re-run showed, and the improvement proof above.

### Explicitly **not** required for done

- Filing GitHub issues or opening PRs on adversary packages (unless human asks).
- Auto-merging optimizer patches.
- Perfect recall on every PR / every adversary in the catalog.
- Implementing full multi-adversary **ensemble product** beyond: route comment → run owning adversary → grade that owner’s gold.
- Exhausting the entire repo catalog in one run.
- Multiple meaningful improvements (one is enough).

---

## Working loop (for the agent)

1. Prefer a **fresh** data root if previous state is noisy:  
   `--data-root /tmp/factory-validate-<date>`  
   Or keep one root and use hunt state intentionally (`--reset-discovery` only if needed).
2. Run:
   ```bash
   cd <path>/adversary-factory
   make build
   ./bin/factory slice --data-root <dir>
   ```
   Optional: `--max-turns 15 --max-prs 1` (defaults OK). Increase turns/PRs if clean but no product gap.
3. Read `LATEST_STORY.md` + `SUGGESTED_ISSUES.md` + stderr hunt log.
4. Classify each graded miss as: **true product gap** | **wrong owner / dump-to-eng-review** | **should have been ignored** | **tool blocked / empty review**.
5. For any item owned by `engineering-review`, apply §3a immediately. If it fails, treat as factory/routing bug — not product signal.
6. Fix factory (and `docs/scope.md` on the relevant adversary if mission text is wrong). Prefer:
   - `internal/scope/*` (heuristics, router — specialists over generalist)
   - `internal/collect/*` (label attachment, multi-round)
   - `internal/pipeline/*` (run owners, progress, story inputs)
   - sibling `*/docs/scope.md` (mission truth)
7. Re-run until attribution quality, eng-review best-owner bar, **and** at least one meaningful correctly owned suggested improvement all hold.
8. If attribution is clean but there is no true gap: keep discovering different PRs/repos; do not stop at “no false positives.” Do not invent eng-review issues to force a “done.”
9. Keep changes committed on `adversary-factory` main (and adversary `docs/scope.md` if edited) when the human’s environment allows; otherwise leave a clean working tree with clear summary.

---

## Known failure modes to watch (from prior runs)

| Symptom | Likely fix area |
|--------|------------------|
| Copilot “PR overview” as miss | Bot + overview heuristics in `scope` |
| GHA `--privileged` as eng-review miss | CI path/content → `githubactions` only |
| Concurrent test gap as eng-review only | Router keywords/path → `go-concurrency` (**failure:** dump-to-eng-review) |
| “Nit; package docs” as in-scope | Out-of-scope nit/docs heuristics (**not** eng-review or lang/go) |
| LGTM / “I think its ok” as miss | Approval / soft-OK heuristics → ignore |
| GHA/CI or races dumped on eng-review suggested issue | Specialist routing; eng-review only if §3a passes |
| Suggested issue title “data races” for non-race text | Whole-word class titles (e.g. “trace” ≠ “race”) |
| r1/r2 “no gold” but r3 has all gold | Casebuilder: attach comments/labels per review round |
| “did not produce findings” but adversary blocked | Surface blocked vs empty review in story |
| Always same PR | Discovery state under `$DATA_ROOT/state/discovery/` |
| Clean GOOD run, empty suggested issues | Not done — hunt more / raise max-turns until a real gap appears |
| Suggested issue is generic or wrong package | Rewrite draft + fix ownership routing |
| Everything hard lands on eng-review | Failure mode — re-route specialists or ignore; do not declare done |

---

## Success one-liner

**Done when a live `factory slice` produces a story where every graded miss is a fair miss for the *best* owner (specialists before eng-review; eng-review only when it truly is best), noise is correctly ignored, *and* at least one suggested issue is a meaningful product improvement a human would file on that same package — never a dump into `engineering-review`.**
