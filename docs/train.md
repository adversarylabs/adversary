# Train home-built adversaries

**Train** walks **your** PR review history, grades **local** (home-grown) adversary
packages against human review comments, and drafts improvements you can accept
or ignore. It does **not** fine-tune model weights.

Use this when you maintain packages you own (`adversary init`, private
specialists, personas) and want them to learn from how *your team* already reviews code.

| Role | Who | Graded? | Gets train drafts? |
|------|-----|---------|---------------------|
| **Local (home-grown)** | Packages under your workspace | Yes | **Yes** |
| **Official catalog** | Registry packages (`go/security`, …) | Optional **jury** | **No** — never trained |

Official packages may still **run** so gold is not mis-attributed to your local
package when the catalog already covers it. Drafts and apply issues only target
**local** package ids.

Related design notes (internal quality bar, full product sketch):
[docs/train/](./train/). This page is the **user guide for implemented CLI**.

## Prerequisites

1. **Local package(s)** with `adversary.yaml` and a scope file:
   - Prefer `agent/scope.md` or `docs/scope.md` (mission: what is a fair miss).
2. **GitHub token** for history and (optionally) apply issues:
   - `ADVERSARY_GITHUB_TOKEN`, `GITHUB_TOKEN`, or `GH_TOKEN`
   - Read access to orgs/repos you train on; `issues:write` on the **package**
     repo if you use `train results apply` without `--no-issue`.
3. Packages you care about are **local checkouts**, not only catalog pulls.

## End-to-end workflow

```text
  adversary train init [--single-package]
           │
           ▼
  Edit adversary.train.yaml   ← commit this (policy)
           │
           ▼
  adversary train run         ← grades locals vs human gold
           │
           ▼
  adversary train results ls / inspect <id>
           │
           ▼
  adversary train results apply <id>
           │
           ├── docs/train-drafts/<id>.md in the package
           └── GitHub issue (agent-ready) on the package remote
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
3. Run local packages (and optional official jury) against the change.  
4. Grade: miss / match / false positive style signals for **locals**.  
5. Write results into the train inbox (SQLite under `.adversary-train/`).  

Official catches **suppress** local “miss” drafts for that concern (don’t train
your package to clone the catalog).

## 4. Results inbox

```sh
adversary train results ls
adversary train results inspect <id>
adversary train results apply <id>
adversary train results apply --all
adversary train results apply --all --no-issue   # local draft only
adversary train results apply --all --no-git     # skip branch/commit helpers
# By default apply opens GitHub issues for misses/FPs only (not every human-gold row).
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
| GitHub issue on **package** remote | Agent-ready task (unless `--no-issue`) |

For **human** miss/human gold, issues also require **voice banking**: append a
short human excerpt to `agent/voice.md` example bank (style few-shot only)—not
a hard-coded finding string in `src/`. See [comment voice](./voice.md).

Implement:

1. **Detection** — fire this *class* when appropriate (scope + rules/tests).  
2. **Voice** — bank human wording for rewrite cadence (persona packages).  
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
| **`uses` composition** | Run entrypoints expand members for *product* review; train still grades **local package ids** that own scope/drafts |
| **`agent/voice.md`** | Bank human gold on apply; CLI rewrite uses voice at `--github-review` time |
| **Official jury** | Catches gold so you don’t re-implement catalog specialists locally |

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
| Voice bank polluted | Applied draft/FP rows; only bank **human** miss/human gold |
| Apply issue fails | Token lacks `issues:write` on package remote — use `--no-issue` for local draft |

## Command cheat sheet

```sh
adversary train init [--single-package] [--path DIR] [--force]
adversary train run [--adversary ID] [--max-prs N] [--reset-discovery] [--path DIR]
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
