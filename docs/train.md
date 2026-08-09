# Train home-built adversaries

**Train** walks **your** PR review history, grades **local** (home-grown) adversary
packages against human review comments, and drafts improvements you can accept
or ignore. It does **not** fine-tune model weights.

Use this when you maintain packages you own (`adversary init`, private
specialists, personas) and want them to learn from how *your team* already reviews code.

| Role | Who | Graded? | Gets train drafts? |
|------|-----|---------|---------------------|
| **Local (home-grown)** | Packages under your workspace | Yes | **Yes** |
| **Local composition (`uses`)** | Members declared in a local package’s `adversary.yaml` | Yes (always with that product) | **No** (unless also a local train package) |
| **Official catalog jury** | Registry packages via `official.enabled` | Optional **jury** | **No** — never trained |

**Official jury** (`official.enabled`) is only the optional catalog corpus so gold
is not mis-attributed when a published specialist already covers it. Turning it
**off** focuses train (no extra catalog packages).

**Composition is separate:** each local package’s `adversary.yaml` `uses` graph is
**always** expanded when that package is graded — independent of
`official.enabled`. Persona / language packs (e.g. torvalds + `lang/go`, or
`lang/go` + `go/*`) are graded as **products**. Drafts still target the **local**
owner, never registry composition leaves.

Drafts and apply issues only target **local** package ids.

Related design notes (internal quality bar, full product sketch):
[docs/train/](./train/). This page is the **user guide for implemented CLI**.

## Prerequisites

1. **Local package(s)** with `adversary.yaml` and a scope file:
   - Prefer `agent/scope.md` or `docs/scope.md` (mission: what is a fair miss).
2. **GitHub token** for history and automatic improvement issues:
   - `ADVERSARY_GITHUB_TOKEN`, `GITHUB_TOKEN`, or `GH_TOKEN`
   - Read access to orgs/repos you train on; `issues:write` on each **package**
     repo. Use `train run --no-issues` for a local-only run.
3. Packages you care about are **local checkouts**, not only catalog pulls.

## End-to-end workflow

```text
  adversary train init [--single-package | --all-adversaries]
           │
           ▼
  Edit adversary.train.yaml   ← commit this (policy)
           │
           ▼
  adversary train run         ← routes gold, grades locals, opens deduped issues
           │
           ▼
  adversary train results ls / inspect <id>  ← evidence + manual controls
           │
           ▼
  Implement detection + bank voice gold → re-run train
```

Runtime state lives under **`.adversary-train/`** (gitignored by `train init`).
Re-runs resume discovery (seen PRs) unless you reset.

## 1. Init

### Single package (most home-built cases)

From the package root (directory with `adversary.yaml`):

```sh
cd my-policy-adversary
adversary train init --single-package
# or: adversary train init   # auto-detects path: . when adversary.yaml is at root
```

Config gets `adversaries.path: .`.

### Multi-package workspace

```sh
cd my-adversaries-workspace
mkdir -p adversaries
# put packages under adversaries/foo, adversaries/bar, …
adversary train init
```

Config gets `adversaries.root: ./adversaries`.

### Sibling adversary repositories

When the workspace directory contains many sibling `*-adversary` repositories:

```sh
cd ~/work/adversarylabs
adversary train init --all-adversaries
```

This writes `adversaries.root: .` and `run.exclude: [torvalds]`. One history
discovery pass routes each human comment to the best matching local adversary,
or to none when no scope is a good fit.

`train init` also creates `.adversary-train/` and adds it to `.gitignore`.

## 2. Edit `adversary.train.yaml`

Commit this file. Example shapes:

### A) Train from an org/repo list

```yaml
version: 1

adversaries:
  path: .                 # or root: ./adversaries

official:
  enabled: true           # jury on (default); never drafts for official ids
  # exclude:
  #   - engineering-review

sources:
  host: github.com
  org: acme                 # and/or:
  # repos:
  #   - acme/service
  #   - acme/lib
  # languages: [go]
  # since: "2024-01-01"
  # authors_only: [staff-alice]   # optional gold filter
  # authors_ignore: [noisy-bot]

run:
  max_prs: 50
  max_turns: 200
  concurrency: 4
  # only: [engineering-review]
  # exclude: [torvalds]

issues:
  enabled: true             # default; false keeps eligible results local

state_dir: .adversary-train
```

### B) Train from a reviewer’s history (no repo list)

```yaml
sources:
  host: github.com
  discovery: author_reviews
  authors_only:
    - torvalds              # GitHub login(s)
  # orgs: [subsurface]      # optional bound
  # author_roles: [reviewed-by]  # or commenter, author
```

Useful for persona packages: gold from a maintainer’s real reviews.

### Local overrides

If your local package **replaces** an official id for routing:

```yaml
adversaries:
  path: .
  overrides:
    go/security: my-security   # local id wins when both would match
```

## 3. Run

```sh
# From the workspace (where adversary.train.yaml lives)
adversary train run

# Only one local package id
adversary train run --adversary my-policy

# Explicitly route across every local package except selected exclusions
adversary train run --all-adversaries --exclude-adversary torvalds

# Cap work / debug one PR
adversary train run --max-prs 10
adversary train run --owner acme --repo service --pr 123

# Forget seen PRs and hunt again
adversary train run --reset-discovery
# or: adversary train reset
```

What happens:

1. Discover PRs from config (repos or author_reviews).  
2. Collect human review comments (gold).  
3. Route each comment to the single best matching local package, or none.
4. Run the selected local packages (and optional official jury) against the change.
5. Grade and write evidence into SQLite under `.adversary-train/`.
6. Use the configured review model to turn clustered misses into concise,
   maintainer-style briefs: the intended capability, why it matters, generalized
   examples, counterexamples, and observable acceptance criteria.
7. Open deduplicated issues for consolidated drafts and false-positive fixes.

If no model credential is available, train keeps working with a concise
deterministic fallback. It does not fall back to the old comment-shaped issue
template.

Raw human rows and individual misses never auto-open issues. They remain local
evidence for clustering and inspection. `--no-issues` disables all issue writes.

Official catches **suppress** local “miss” drafts for that concern (don’t train
your package to clone the catalog).

## 4. Results inbox and manual controls

```sh
adversary train results ls
adversary train results inspect <id>
adversary train results apply <id>
adversary train results apply --all
adversary train results apply --all --no-issue   # local draft only
adversary train results apply --all --no-git     # skip branch/commit helpers
# Bulk apply opens clustered draft / false-positive issues, not one issue per comment.
adversary train results apply --all --include-individual-issues  # also file each miss
adversary train results apply --all --include-human-issues  # also file human-gold issues
adversary train results dismiss <id>
```

Also:

```sh
adversary train status    # config + packages + discovery summary
adversary train story     # latest story markdown (if present)
```

### Apply output (what you implement)

For each applied result:

| Artifact | Purpose |
|----------|---------|
| `docs/train-drafts/<id>.md` | Local miss brief: spirit, when to post, variance |
| GitHub issue on **package** remote | The synthesized brief nearly verbatim, plus a compact provenance footer (unless `--no-issue`) |

Human wording is detection evidence for policy and specialist packages. Only
persona packages bank a short excerpt in `agent/voice.md`; automatically
appending every policy miss would couple detector content to rewrite voice.

Implement:

1. **Detection** — fire this *class* when appropriate (scope + rules/tests).
2. **Voice** — bank human wording for rewrite cadence only for persona packages.
3. **Tests/fixtures** for the class, not one PR-specific sentence.

Do **not** bank synthetic train draft titles or false-positive rows into voice.

## 5. Scope: what is a fair miss?

Train routing uses each package’s **scope** document. Edit before training:

- `agent/scope.md` or `docs/scope.md`  
- Clear **in scope** / **out of scope** so multi-package workspaces don’t all
  claim every comment  

Home-built packages should be **narrow enough** that factory/train can tell them
apart. A generalist persona (e.g. whole-diff maintainer) is valid when that *is*
the product; specialists should not dump leftovers onto a random sibling.

## 6. Composition, voice, and train

| Feature | Role in train |
|---------|----------------|
| **`uses` composition** | **Always** expanded when grading a local package that declares `uses` (product run). Not gated by `official.enabled`. |
| **`agent/voice.md`** | Persona packages bank human cadence; policy/specialist packages keep gold as detection evidence |
| **Official jury** | Optional catalog packages for catch/suppress only; disable to focus |

When train runs `adversary run <local-package>`, the CLI expands that package’s
`uses` and merges findings for the grade. Multi-member JSON is folded into one
review for the local owner. If any composition member fails or returns unusable
output, train fails that review instead of grading the remaining members as a
complete product.

Train drafts improve **your** package tree. Shipping still uses `pack` / `push`
when you publish.

## 7. Auth and hosts

- History and issues use the **direct GitHub HTTP API** (no `gh` CLI required).  
- Token: `ADVERSARY_GITHUB_TOKEN` → `GITHUB_TOKEN` → `GH_TOKEN`.  
- `sources.host: github.com` is the supported host for v1.

## 8. Reset and hygiene

```sh
adversary train reset              # clear seen-PR discovery (re-hunt)
# see train reset --help for results inbox options
```

- **Commit** `adversary.train.yaml` and scope/voice/src changes.  
- **Ignore** `.adversary-train/`.  
- Re-run train after implementing applies to confirm miss rate drops for that class.

## 9. Common pitfalls

| Symptom | Likely cause |
|---------|----------------|
| No in-scope gold | Scope too narrow, or authors/repos filters exclude real reviews |
| Everything out of scope | Scope missing or package not discovered (`path` / `root` wrong) |
| Drafts want you to clone `go/security` | Official jury off, or local scope steals catalog gold — enable jury / narrow scope |
| Voice bank polluted | Applied policy/specialist gold or synthetic rows; only persona packages bank **human** wording |
| Automatic issue creation fails | Token lacks `issues:write` on a package remote — fix access and rerun/apply, or use `train run --no-issues` |

## Command cheat sheet

```sh
adversary train init [--single-package | --all-adversaries] [--path DIR] [--force]
adversary train run [--adversary ID | --all-adversaries] [--exclude-adversary ID] [--no-issues] [--path DIR]
adversary train results ls|inspect|apply|dismiss
adversary train status
adversary train story
adversary train reset
```

## Related

- [Comment voice](./voice.md) — bank gold; rewrite on GitHub post  
- [Composition](./composition.md) — `uses` entrypoints  
- [GitHub review posting](./github-review-posting.md) — post with persona voice  
- [docs/train/customer-train-cli.md](./train/customer-train-cli.md) — longer product sketch  
- [docs/train/quality-bar.md](./train/quality-bar.md) — internal factory quality bar  
