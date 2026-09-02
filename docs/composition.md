# Adversary composition (`uses`)

Packages can declare other adversaries to run when they are selected. This is
how **persona** packs (`person/torvalds`) and **language** packs (`go`) ship a
product name without reimplementing every detector.

## Manifest

```yaml
name: person/torvalds
version: 0.0.1
description: Maintainer persona — specialists under Torvalds voice

uses:
  - name: review/engineering
  - name: go                    # meta-package; expands further
  - name: go/concurrency
    version: "0.1.0"            # optional exact tag → go/concurrency:0.1.0
  - path: ../local-specialist   # relative to this package root

runtime:
  name: node
  version: "22"
  command: [dist/index.js]      # optional thin rules (e.g. ship signal)
```

Rules:

- Each `uses` entry has **exactly one** of `name` or `path`.
- `version` is only valid with `name`, and must be an **exact tag** (no `^`/`~` ranges yet).
- Relative `path` is resolved from the declaring package directory.

## CLI

```sh
# Expand uses, run root + members
adversary run person/torvalds --path ./app --github-review

# Language pack
adversary run go --path ./myservice

# Default product: review/code plus its specialists
adversary run --path ./app
```

Expansion is **transitive** (depth cap 8), **deduped**, and **cycle-safe**.
Missing members fail the run (fail closed). Registry members are auto-pulled
when not installed, same as a direct `adversary run <ref>`.

One-root compositions execute with bounded parallelism (five reviewers by
default; configurable with `--compose-concurrency`). The root generalist sees
the full change. Each child receives only changed files selected by its
declarative manifest, while retaining access to the repository graph for
context. The CLI emits one result, conservatively deduplicates overlapping
findings, and records every contributing reviewer in finding metadata.

Progress shows the expanded set when composition adds members:

```text
Compose: expanded 1 → 5 adversaries
  · person/torvalds
  · review/engineering
  · go
  · go/concurrency
  · go/security
```

## Voice

GitHub comment rewrite uses the **CLI entry package** voice (`agent/voice.md`
with its example bank), not each member’s voice. See **[Comment voice](./voice.md)**
for file layout, train banking, and rewrite behavior.

| You run | Voice source | Detectors |
|---------|--------------|-----------|
| `person/torvalds` / `./torvalds-adversary` | that package’s `agent/voice.md` | members in `uses` (+ root if any) |
| `lang/go` | go package voice if any, else CLI default | go-* members |
| `go/concurrency` | that package only | leaf only |

Findings record their contributing adversary ids in `compositionSources`
metadata; bodies can be rewritten with the entry persona.

## Suggested products

| Package | Role |
|---------|------|
| `person/torvalds` | Persona: voice banks + `uses` specialists |
| `go` | Language pack: all `go/*` specialists |
| `go/concurrency` | Leaf detector |

Train should fix **leaves** for detection misses and bank **persona** voice for
wording; meta packages only change the default member set.

## Flags

| Flag | Meaning |
|------|---------|
| `--compose-concurrency` | Maximum composed reviewers running concurrently (default 5) |

`adversary run` with no refs selects `review/code` and expands its composition.
`--all` retains catalog-wide automatic selection. The internal `--no-compose`
compatibility flag remains available to controlled training and evaluation
workflows, but is intentionally hidden from normal CLI help.

## Related

- [Train home-built adversaries](./train.md) — improve local packages from review history  
- [Comment voice](./voice.md) — `agent/voice.md`, example banks, rewrite  
- [GitHub PR review posting](./github-review-posting.md) — posting flags
