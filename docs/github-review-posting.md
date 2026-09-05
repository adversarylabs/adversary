# GitHub PR review posting

`adversary run` can project findings into GitHub pull request review comments
using **direct HTTP** (REST + GraphQL). It does **not** shell out to `gh`.

## Quick start

```bash
export GH_TOKEN=…   # or GITHUB_TOKEN / ADVERSARY_GITHUB_TOKEN

# Analyze a PR (sets base/head + workspace; does not post)
adversary run https://github.com/owner/repo/pull/123

# Plan only (no mutation)
adversary run https://github.com/owner/repo/pull/123 \
  --github-review --github-dry-run --github-plan-file plan.json

# Create a pending review (default)
adversary run https://github.com/owner/repo/pull/123 --github-review

# Submit as informational COMMENT (visible to authors)
adversary run https://github.com/owner/repo/pull/123 --github-review --github-submit
```

## Flags

| Flag | Meaning |
| --- | --- |
| `--github-review` | Opt-in: build plan; post unless dry-run |
| `--github-dry-run` | Plan/place only; never mutate GitHub |
| `--github-plan-file PATH` | Write `CommentPlan` JSON |
| `--github-pr N` | PR number (or use PR URL / Actions env) |
| `--github-repo owner/name` | Repository (or use PR URL / `GITHUB_REPOSITORY`) |
| `--github-submit` | Submit review as `COMMENT` (default leaves **pending**) |
| `--github-include-summary=false` | Omit the persistent aggregate assessment/opinion while retaining finding comments and execution-failure notices |
| `--github-min-severity` | `info`\|`low`\|`medium`\|`high`\|`critical` (default: all) |
| `--github-api-url` | GraphQL endpoint override |
| `--github-rest-url` | REST base override |

Posting is **never** enabled solely because a PR URL was passed.

## Auth

Token resolution order:

1. `ADVERSARY_GITHUB_TOKEN`
2. `GITHUB_TOKEN`
3. `GH_TOKEN`

The CLI does not read `gh auth`’s on-disk store. Optionally:
`export GH_TOKEN=$(gh auth token)`.

## Comment voice

When `--github-review` is set, comment bodies use a **product voice**: core rules
and optional example few-shots from the package, applied by LLM rewrite when a
model provider is configured.

Full guide: **[Comment voice](./voice.md)** (layout, train banking, composition).

### Resolve order (first hit wins)

1. **Local adversary package roots** (path args that look like packages), in order:
   - `agent/voice.md` (preferred)
   - `train/voice.md`
   - `voice.md`
   - `VOICE.md` (legacy)
2. **Review target** (`--path`), same relative names
3. Else the **CLI-embedded** default prompt

Example: `adversary run ./torvalds-adversary --path ../app --github-review` loads
`./torvalds-adversary/agent/voice.md` when present.

With **composition** (`uses`), the **CLI entry** package owns rewrite voice—not
each specialist member. See [composition](./composition.md).

Without a model provider configured, a deterministic **template** body is used.
Analysis model flags (`--model-provider` / `--model`) are shared when LLM rewrite
is available.

## Placement

Inline threads require the evidence `file` + `line` to sit on the PR **diff**
(REST PR file patches). Lines not on a hunk are demoted to the review body.
There is no nearest-line guessing.

## Exit codes

Hard posting failures (auth/network/mutation) map to exit class **4**, even when
findings exist (class 1). Soft placement skips do not change the exit class.

## Incomplete reviews

When review jobs fail, the CLI still posts usable findings, but adds a
**Partial Adversary review** notice naming failed reviewers, their scopes, and
bounded failure diagnostics. This notice also appears when no job returned
findings, and is not disabled by `--github-include-summary=false`. Known provider
and GitHub credentials are redacted; full diagnostics remain in the CI logs.

The notice is host-generated and is never rewritten by the model. Findings keep
normal inline placement and off-diff fallback. A findings-only exit does not
produce a failure notice. Posting a partial review does not turn an execution
failure into success; all-failed compositions retain the underlying error class.

## Content policy

- Visible **findings** only (never observations, positives, or suppressed details)
- Execution failures add an explicit partial-run notice, separate from findings
- Empty plan → no GitHub mutation
- The aggregate summary synthesizes actual findings only; clean adversaries never add review-body noise
- Max 50 inline comments; overflow goes to the review body

## Train without `gh`

`adversary train` collect/discover/org expansion uses the same direct GitHub
HTTP client. Set a token env var; install of the `gh` CLI is not required.
