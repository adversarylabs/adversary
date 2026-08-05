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

When `--github-review` is set, comment bodies use a product voice. Search order
(first hit wins):

1. **Local adversary package roots** (path args that look like packages), in order:
   - `agent/voice.md` (preferred)
   - `train/voice.md`
   - `voice.md`
   - `VOICE.md` (legacy)
2. **Review target** (`--path`), same relative names
3. Else the **CLI-embedded** default prompt

Example: `adversary run ./torvalds-adversary --path ../app --github-review` loads
`./torvalds-adversary/agent/voice.md` when present.

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

## Content policy

- Visible **findings** only (never observations, positives, or suppressed details)
- Empty plan → no GitHub mutation
- Max 50 inline comments; overflow goes to the review body

## Train without `gh`

`adversary train` collect/discover/org expansion uses the same direct GitHub
HTTP client. Set a token env var; install of the `gh` CLI is not required.
