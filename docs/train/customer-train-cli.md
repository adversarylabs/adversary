# Customer `adversary train` CLI — product sketch

**Status:** design only (not implemented).  
**CLI name:** **`train`** (not `factory`). No backward-compat aliases required.  
**Goal:** After the internal adversary-factory loop is trustworthy, ship it as first-class `adversary train …` so a customer can improve **their own** adversaries using **their own** PR review history.

Related: [goal-factory-iteration.md](./goal-factory-iteration.md) (internal quality bar).

**What “train” means here:** walk review history, grade local packages against human gold, draft improvements (stories + suggested issues). It does **not** imply silent model-weight fine-tunes in v1 (see non-goals). Help text should stay honest: *train from your team’s review history*.

---

## One-line value prop

**Train an adversary on how *your* team already reviews code** — by replaying human PR comments against local packages, grading misses, and drafting suggested improvements (never auto-filed).

Not “train on the open web.” Not “scan one PR once.” **History + state + multi-adversary scope.**

---

## Design principle: config over magic commands

**Sources of history live in a committed config file**, not a pile of `train source add …` subcommands.

| Prefer | Avoid |
|--------|--------|
| `adversary.train.yaml` in the workspace, **checked into git** | Imperative “source” subcommands that mutate hidden state |
| `adversary train init` that **stubs** the config for the user to edit | Magic discovery of “where history lives” with no file to review |
| `adversary train run` / `run --adversary X` reading that config | A second CLI dialect just to manage the repo list |

Why:

- **Reviewable** — PR the sources list like any other policy  
- **Shareable** — team clones the adversary workspace and gets the same history targets  
- **Less magic** — open the file; see org, repos, filters, authors  
- **Scriptable** — edit YAML in CI or codegen if needed  

CLI stays small: **init (stub config) → edit config → run (one adversary or all) → story / issues**.

---

## Who is the user?

| Persona | Intent |
|--------|--------|
| **Platform / DevEx** | “Everything for this monorepo / org” — fleet of packages, broad sources. |
| **Domain owner** | “Database is *this* package” — one specialist; only its mission grades. |
| **Security / compliance** | Fleet of specialists; never dump leftovers into a generalist. |

All of them need:

1. A **local adversary workspace** (one or many packages with clear `docs/scope.md`).  
2. A **committed train config** listing history sources (org, repos, filters, authors).  
3. **Durable runtime state** (gitignored) so re-runs don’t re-grade the same PR rounds.  
4. **Stories + draft issues** they can accept, edit, or ignore.

---

## Mental model

```
┌─────────────────────────────────────────────────────────┐
│  Workspace (committed)                                  │
│  adversary.train.yaml   ← sources + adversary roots     │
│  adversaries/*/docs/scope.md + package code             │
└────────────────────────────┬────────────────────────────┘
                             │ train run reads config
                             ▼
┌─────────────────────────────────────────────────────────┐
│  Code host (their credentials)                          │
│  orgs / repos from config → PR history                  │
└────────────────────────────┬────────────────────────────┘
                             │ grade with 1 or all adversaries
                             ▼
┌─────────────────────────────────────────────────────────┐
│  Runtime state (gitignored)                             │
│  .adversary-train/  seen PRs · stories · drafts         │
└─────────────────────────────────────────────────────────┘
```

**Config = policy (commit it).**  
**State = progress (gitignore it).**  
**Scope.md = mission (commit it).**

---

## Official catalog vs home-grown (critical product rule)

Train must **not** turn every customer into a second `go-security` / `engineering-review`. Human comments often *look* like those domains. Without a clear split, routing will invent local clones and draft “improve my generalist” forever.

### Two roles in one pass

| Role | Who | Participates in grade? | Gets train drafts? |
|------|-----|------------------------|--------------------|
| **Official** | Adversary Labs packages from the registry (`go/security`, `go/testing`, `engineering-review`, …) | **Yes** — run them; they may **catch** gold | **No** — never suggested issues / patches for official |
| **Local (home-grown)** | Packages under the workspace (`adversaries/*` or `path: .`) | **Yes** | **Yes** — only these are trainable |

So:

1. User **creates** local adversaries (SDK / `adversary init`) and edits `docs/scope.md` for **their** niche.  
2. User **trains** those locals (one package or all locals in a pass; regularly).  
3. Train **downloads / uses the official catalog** as a **read-only jury** on the same history.  
4. If **official** `go-testing` already catches the human concern, that is **not** a miss for the home-grown package — **do not** draft a local improvement from that gold.  
5. Product default: **local overrides official** when both claim a comment (same mission shape or same id alias) — the customer’s package owns grading *and* training for that gold.

### Why official is present during train

Without official in the room, every security-shaped human comment becomes “miss for my local generalist” → pressure to reinvent official packages.

With official catching:

- Local packages stay **narrow** (company rules, domain, policy).  
- Train only proposes changes when **no included official** (and no better local) covered the gold.  
- Day-to-day `adversary run` can still use official + local together the same way.

### Local overrides official

| Situation | Behavior |
|-----------|----------|
| Local package id / name intentionally replaces an official (e.g. company `security`) | **Local wins** routing and train drafts; optional: still run official for comparison metrics only (v2) |
| Local and official both in-scope for a comment | **Prefer local** if configured as override / same surface; else **most specific** specialist; never double-count as two misses |
| Official catches, local does not | **Not a local miss** — no train draft for local |
| Local catches, official does not | Local win (good); no train draft |
| Neither catches, gold fits local mission only | **Local miss** → draft for local |
| Neither catches, gold fits official only | **Not a train target** — optionally note “covered by official catalog if enabled” in story; **do not** draft “add go-security clone to workspace” |

### What users are supported to do

| Workflow | Supported? |
|----------|------------|
| Create home-grown adversary, train **only** it | Yes — `train run --adversary my-policy` |
| Create several locals, train **all** locals in one pass (and on a schedule) | Yes — default `train run` over `adversaries.root` |
| Use official during train so gold isn’t mis-attributed | Yes — default on, configurable |
| Train / improve official packages from customer history | **No** — official is never a train draft target |
| Disable some official packages they don’t want in the jury | Yes — config include/exclude |
| **Catalog author (Adversary Labs):** train local checkouts of packages that *publish as* official, with registry jury off | Yes — see below |

### Catalog author mode (first-party)

You author the official packages. For your own train loop you do **not** need the registry copies in the jury (they would duplicate the same missions). Instead:

1. **`official.enabled: false`** (or `exclude` everything) — no registry jury.  
2. Point **`adversaries.root`** at your monorepo siblings (or a workspace that lists every package you ship): local `go-concurrency-adversary`, `engineering-review-adversary`, etc.  
3. Each has **`docs/scope.md`**; routing picks best owner among those locals.  
4. **`train run`** / regular re-runs draft improvements **for those locals** — the same trees you later pack/push as official.  
5. Optional: `sources` = public OSS catalog and/or internal repos; `authors_*` as needed.

Example:

```yaml
# Adversary Labs monorepo — train the packages we publish
version: 1

adversaries:
  root: ..   # or explicit list of sibling paths when supported
  # If root is the monorepo parent, train discovers each *-adversary with docs/scope.md
  # Prefer an explicit workspace that only contains shippable packages.

official:
  enabled: false   # locals ARE the catalog-in-development; don't also pull registry twins

sources:
  host: github.com
  # repos: [open-telemetry/opentelemetry-go, ...]  # or org / allowlist
```

**Customers** keep `official.enabled: true` so home-grown packages stay narrow.  
**You** flip official off and train the local set that becomes official on release.

No special CLI flag required for v1 — config is enough. Optional later: `adversary train init --catalog-author` stubs this shape.

---

## Workspace layout

```text
~/work/my-adversaries/                 # train workspace root (git repo)
  adversary.train.yaml                 # COMMIT — sources + adversary roots + run defaults
  adversaries/
    engineering-review/
      adversary.yaml
      docs/scope.md                    # COMMIT — required
      src/ …
    go-database/
      adversary.yaml
      docs/scope.md
      src/ …
  .adversary-train/                    # GITIGNORE — runtime only
    state/discovery/
    runs/
    experiments/
    LATEST_STORY.md
  .gitignore                           # includes .adversary-train/
```

Single-adversary workspace:

```text
~/work/my-db-adversary/
  adversary.train.yaml
  adversary.yaml
  docs/scope.md
  src/ …
  .adversary-train/                    # gitignored
```

---

## Config file (`adversary.train.yaml`)

This is the **source of truth** for history and workspace layout. No separate “sources” CLI surface.

### Stub generated by init

```yaml
# adversary.train.yaml — edit and commit
# Generated by: adversary train init
# Docs: https://… (link when shipped)

version: 1

# Local (home-grown) packages — the only ones that receive train drafts.
adversaries:
  # Multi-package workspace:
  root: ./adversaries
  # Single package at workspace root instead:
  # path: .
  # Optional: locals that replace an official package id (local always wins).
  # overrides:
  #   go/security: my-security      # local package id / directory name

# Official catalog — grade-only jury (downloaded/cached; never trained).
# Default: use official catalog so home-grown packages don't absorb every
# security/eng-review-shaped human comment as a local miss.
official:
  enabled: true
  # Pull/cache latest official packages before a train run (or use store).
  # auto_pull: true
  # Pin a catalog channel if needed:
  # channel: latest
  #
  # Include/exclude official package ids (registry names).
  # Empty include = all official packages available to the product.
  # exclude wins over include if both list the same id.
  # include:
  #   - go/testing
  #   - go/security
  #   - githubactions
  # exclude:
  #   - engineering-review    # e.g. customer doesn't want official generalist in the jury
  #   - complexity

# History to train against (customer org/repos — not Adversary Labs public catalog).
sources:
  host: github.com
  # Pick one primary mode (or combine carefully):
  # org: acme
  # repos:
  #   - acme/payments-api
  #   - acme/ledger
  repos: []
  # Optional filters (apply to all listed sources):
  # languages: [go]
  # since: "2024-01-01"

  # Author filters on human review comments (logins, case-insensitive).
  # Built-in bot ignore still applies (Copilot, dependabot, *[bot], etc.).
  # authors_ignore:           # never treat as gold (bad actor, noisy reviewer, …)
  #   - sketchy-contractor
  # authors_only:             # if non-empty, ONLY these authors count as gold
  #   - staff-eng-alice       # e.g. staff+ comments only
  #   - staff-eng-bob
  # authors_only and authors_ignore: ignore wins if someone appears in both.

# Run defaults (CLI flags can override for one-shot runs).
run:
  max_prs: 50
  max_turns: 200
  # history_order: newest_first   # or oldest_first
  # only: []                      # default: all packages under adversaries.root / path

# Runtime state (do not commit).
state_dir: .adversary-train
```

### Sources: org, repo, filters

| Field | Meaning |
|-------|---------|
| `sources.host` | `github.com` (later: GitLab host, etc.) |
| `sources.org` | Walk repos under the org (optional allowlist below). |
| `sources.repos` | Explicit `owner/name` list (most common for v1). |
| `sources.languages` | Optional language filter when discovering / selecting PRs. |
| `sources.since` | Optional lower bound on PR activity. |
| `sources.repos_allowlist` | When `org` is set, optional restrict to these names. |
| `sources.authors_ignore` | Logins whose comments are **never** gold (blocklist). |
| `sources.authors_only` | If non-empty, **only** these logins can be gold (allowlist). |

**State is always per `owner/repo`**, even when `org` is set (never one blob of “org progress” that can’t resume cleanly).

### Author filters (gold quality)

Train grades **human review comments**. Customers need control over *whose* comments count:

| Goal | Config |
|------|--------|
| Drop a bad actor / noisy reviewer | `authors_ignore: [that-login]` |
| Only train from staff+ / tech leads | `authors_only: [alice, bob, …]` |
| Both | Allowlist first; **ignore always wins** if a login is in both lists |

**Rules:**

1. **Built-in bot reject still applies** (Copilot, dependabot, `*[bot]`, assessment bots, etc.) — config does not re-enable bots.  
2. Filters apply when labeling gold / routing, **before** miss grading.  
3. Logins are **case-insensitive**; match GitHub (or host) username, not display name.  
4. Empty `authors_only` = no allowlist (all non-ignored, non-bot humans eligible).  
5. Empty `authors_ignore` = no extra blocklist beyond bots / global non-defects.  
6. A PR with only ignored authors may still be **marked seen** (so history walks forward) but produces **no in-scope gold**.  
7. Optional later: per-source author lists under each repo entry if org-wide defaults are too coarse.

Examples:

```yaml
# Only senior reviewers
sources:
  host: github.com
  repos: [acme/payments-api]
  authors_only:
    - jsmith          # staff eng
    - mlee            # principal

# Exclude one noisy account, keep everyone else
sources:
  host: github.com
  org: acme
  authors_ignore:
    - former-contractor
    - intern-spam-bot-not-marked-bot
```

### Local adversaries: one or all (trainable)

| Config | CLI | Behavior |
|--------|-----|----------|
| `adversaries.root: ./adversaries` | `train run` | Train-eligible: **all locals** with `docs/scope.md` |
| same | `train run --adversary go-database` | Train-eligible: **only** that local |
| `adversaries.path: .` | `train run` | Single local at workspace root |
| `run.only: [go-database]` | `train run` | Default local filter; CLI can override |
| `adversaries.overrides` | — | Local id replaces official id for ownership |

Official packages still run as **jury** (if `official.enabled`) even when `--adversary` narrows train drafts to one local.

### Official catalog: include / exclude

| Field | Meaning |
|-------|---------|
| `official.enabled` | If false, train with locals only (higher risk of cloning official missions). |
| `official.auto_pull` | Ensure official packages are present/fresh in the local store before run. |
| `official.include` | If non-empty, only these official ids join the jury. |
| `official.exclude` | Drop these official ids even if include is empty/all. **Exclude wins.** |
| `adversaries.overrides` | Map official id → local package that owns that surface. |

Examples:

```yaml
# Full official jury, train all locals
official:
  enabled: true

# No official engineering-review generalist — customer brings their own staff bar
official:
  enabled: true
  exclude:
    - engineering-review

# Only testing + security as official; everything else local
official:
  enabled: true
  include:
    - go/testing
    - go/security

# Company security package replaces official go/security
adversaries:
  root: ./adversaries
  overrides:
    go/security: acme-security
official:
  enabled: true
  # go/security still may be excluded from jury if fully replaced:
  exclude:
    - go/security
```

### Routing + miss attribution (train pass)

Order of decisions for each human comment (after bots / authors / non-defects):

1. **Local override** — if an override maps this surface to a local package, owner = local.  
2. **Best specialist** among **included official + all loaded locals** (scope.md / heuristics).  
3. Prefer **local over official** when scores tie or missions overlap (customer ownership).  
4. Prefer **specific official** over vague local generalist when local scope is empty/template.  
5. **Catch check:** run all owners that are in-scope for grading; if **any official** findings match the gold, do **not** emit a train draft for locals on that gold.  
6. **Train draft** only if: gold in-scope for a **local** train-eligible package, that local missed, and no official catch covered it.  
7. **Never** emit suggested issues with `adversary:go/security` (official) as the improvement target.

Story should still *show* “official go-testing caught this” so the user understands why local wasn’t trained.

---

## CLI shape (minimal)

Under **`adversary`**. Intentionally few commands. **No `factory` subcommand** and no compat aliases.

Suggested parent help line:

```text
train      Train adversary packages from PR review history (draft gaps; stateful)
run        Review a repository with an installed or local adversary
```

### `adversary train init`

```bash
# Multi-adversary workspace: stub config + gitignore + state dir
adversary train init
adversary train init --path ~/work/my-adversaries

# Single existing package
adversary train init --path ~/work/my-db-adversary
```

**Does:**

- Write **`adversary.train.yaml`** stub (if missing) with commented examples for org/repos/authors  
- Ensure `.adversary-train/` exists  
- Add `.adversary-train/` to `.gitignore`  
- Optionally detect `adversaries/` vs single-package and set `adversaries.root` / `path`  

**Does not:**

- Call the code host  
- Register “sources” in hidden state  
- Require a chain of `source add` commands  

User **edits the YAML** (or opens a PR) to set `org` / `repos` / authors.

### `adversary train run`

```bash
cd ~/work/my-adversaries

# All adversaries from config; history from config sources
adversary train run

# One adversary only (domain owner)
adversary train run --adversary go-database

# Budget overrides (optional; defaults from config)
adversary train run --max-prs 100 --max-turns 300

# Resume is default (state dir). Explicit reset:
adversary train run --reset-discovery

# Debug only — not the product default
adversary train run --pr 4242 --repo acme/payments-api
```

**Semantics:**

- Read **`adversary.train.yaml`** (fail clearly if missing or empty sources).  
- Ensure **official catalog** is available per `official.*` (pull/cache); run them as grade-only jury.  
- Walk **unseen** history for configured sources until budget.  
- **Train-eligible** set: one local (`--adversary`) or all locals (default).  
- Draft suggested issues **only** for train-eligible locals that missed gold **not** already caught by an included official.  
- Append story + issues; update **gitignored** state.

### Inspect

```bash
adversary train story       # LATEST_STORY.md
adversary train issues      # draft suggested issues
adversary train status      # config summary + state counts + loaded packages
```

No `train source` command group.

---

## State model (progress only — not sources)

State under `state_dir` (default `.adversary-train/`), **gitignored**.

```text
state/discovery/{host}/{owner}/{repo}.json
```

```json
{
  "seen_pull_requests": {
    "8611": { "last_seen_at": "...", "rounds": [1, 2, 3] },
    "8620": { "last_seen_at": "...", "rounds": [1, 2] }
  }
}
```

| Committed | Not committed |
|-----------|----------------|
| `adversary.train.yaml` | `.adversary-train/state/**` |
| `adversaries/**/docs/scope.md` | run artifacts, LATEST_STORY (optional to commit later) |
| package source | |

Re-runs skip seen PR/rounds. `--reset-discovery` is explicit and loud.

---

## What a full-history run does

1. Load config → sources + **local** train set + **official** jury set (include/exclude).  
2. Auto-pull / resolve official packages into the local store as needed (not train targets).  
3. For each repo in sources (expand `org` if set), list PRs with human review activity.  
4. Skip anything in discovery state.  
5. Until budget: collect → filter authors → route (local override / best owner) → run locals **and** included official → judge:  
   - official catch ⇒ no local train draft for that gold  
   - local miss only ⇒ draft for that local  
6. **Save state**; print BOTTOM LINE + paths.

---

## Example sessions

### Platform team

```bash
mkdir acme-adversaries && cd acme-adversaries
adversary train init
# edit adversary.train.yaml:
#   adversaries.root: ./adversaries
#   sources.org: acme
#   # or sources.repos: [acme/payments-api, acme/ledger]
# add packages under adversaries/*/ with docs/scope.md

adversary train run
adversary train story
# next week
adversary train run
```

### Database team (one package)

```bash
cd go-database-adversary   # already has docs/scope.md
adversary train init
# edit adversary.train.yaml:
#   adversaries.path: .
#   sources.repos:
#     - acme/payments-api
#     - acme/ledger

adversary train run
# or from a multi workspace:
# adversary train run --adversary go-database
```

### Debug one PR

```bash
adversary train run --repo acme/payments-api --pr 4242 --force
```

---

## Outputs

| Artifact | Purpose |
|----------|---------|
| `LATEST_STORY.md` | Plain English human vs adversary |
| `SUGGESTED_ISSUES.md` | Drafts for the **owning local package** |
| `state/discovery/…` | Resume without rehashing |

Never auto-merge adversary code or auto-file GitHub issues without an explicit later command.

---

## Privacy & trust

- History uses **their** credentials against **their** org/repos from **their** config.  
- Config is local/committed by them; default no upload of review bodies to Adversary Labs.  
- Public OSS catalog stays **our** internal tool.

---

## Mapping to today’s internal factory

| Today (internal) | Customer CLI (target) |
|------------------|------------------------|
| Separate **`adversary-factory`** repo + `./bin/factory slice` | **`adversary train …` inside the main `adversary` CLI** — this project goes away |
| `config/repositories.json` | **`adversary.train.yaml` `sources`** (committed in the customer workspace) |
| Sibling `*-adversary` checkouts under monorepo | `adversaries.root` or `adversaries.path` |
| `$DATA_ROOT/state/discovery` | `.adversary-train/state/discovery` (gitignored) |
| Ad-hoc catalog / flags | **Edit YAML** (stub from `train init`) |

### Implementation path (important)

**`adversary-factory` is temporary R&D / scaffolding.** When productized, the project is **deleted** (or archived)—not kept as a long-lived library that `adversary` wraps. No need to preserve a `factory` CLI name.

1. **Now** — prove quality with the private `adversary-factory` binary and these docs.  
2. **Productize** — move the engine (collect → case → scope/route → run → grade → story/issues + discovery state) **into the `adversary` repo** as first-class **`adversary train`** commands and packages.  
3. **Delete** standalone `adversary-factory` once the CLI owns behavior and tests.  
4. Customer install is only **`adversary`** — config + `train init|run|story|…`. No second binary.

End state: **one CLI, one product repo to ship.**

---

## Non-goals (v1)

- `adversary train source add|list|rm` command family  
- `adversary factory …` or other compat aliases  
- **Training / drafting improvements for official catalog packages**  
- Encouraging locals that re-implement official missions when an included official already caught the gold  
- Auto fine-tuning of model weights (unless explicitly added later under the same name)  
- Auto-filing on application repos  
- Replacing `adversary run` for day-to-day review  

---

## Open questions

1. History order default: newest-first vs oldest-first?  
2. Org expansion: all repos vs require `repos_allowlist` for safety?  
3. Config filename locked as `adversary.train.yaml` vs `.adversary/train.yaml`?  
4. Should `run` refuse to start if `sources.repos` and `sources.org` are both empty? (yes)  
5. Exact `--help` wording so “train” is not mistaken for offline GPU fine-tunes?  
6. Default official jury: full catalog vs curated default exclude list?  
7. When local override maps `go/security` → `acme-security`, still shadow-run official for metrics?

---

## Success for this design

1. Customer commits **`adversary.train.yaml`** (sources, authors, local roots, official include/exclude).  
2. `train init` only **stubs** that file + gitignore — no magic source registry.  
3. `train run` walks **unseen** history; **official jury** runs but is **never** a train draft target.  
4. Official catch **suppresses** local drafts for that gold (no pressure to clone go-security / eng-review).  
5. **Local overrides official** when the customer replaces a surface.  
6. `train run` / `train run --adversary <id>` cover **all locals vs one**.  
7. Next week’s run does **not** reprocess the same PR rounds (state, not config).

When the internal loop is honest enough, fold it into **`adversary train`** (config-first surface) and **retire this repo**.
