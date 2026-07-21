# Automatic adversary detection

`adversary auto` resolves one Git change, asks locally runnable adversaries
whether that change applies to them, explains the selection, and runs the
selected set. Detection never purchases, subscribes to, pulls, or installs an
adversary. The current runnable inventory is the content-addressed local store,
plus local or installed references explicitly supplied with `--include`.

## Change selection

```sh
adversary auto                         # staged, unstaged, and untracked files
adversary auto main                    # merge-base(main, HEAD) through HEAD
adversary auto main...HEAD             # explicit merge-base range
adversary auto --repo ../project
```

With no positional argument in CI, the CLI uses captured base/head pairs when
available. `ADVERSARY_BASE_REF` and `ADVERSARY_HEAD_REF` take precedence,
followed by GitHub, GitLab merge-request, and Buildkite pull-request variables.
The checkout must contain both commits and enough history to compute their
merge base.

Git resolution happens once. Every detector and selected review receives the
same versioned context through `ADVERSARY_CHANGE_CONTEXT`; adversaries do not
independently recalculate the diff. The context includes change mode, refs,
merge base, and structured added, modified, deleted, renamed, copied, or
untracked paths. Repository files are enumerated only when an available
adversary declares `detection.repository_files`.

## Detection declarations

Each adversary owns its matching logic. There is no filename-to-adversary map
in the CLI. Common cases use a side-effect-free manifest declaration:

```yaml
detection:
  files:
    - Dockerfile
    - "**/Dockerfile"
    - "**/*.dockerfile"
  repository_files:
    - .dockerignore
  change_types:
    - added
    - modified
    - renamed
```

`files` matches changed paths. `repository_files` records repository
applicability but does not by itself make an unrelated change applicable. When
both are present, a repository can match while a README-only change is skipped.
`change_types` optionally limits changed-path matching. Existing
`triggers.files_changed` is used as a declarative fallback for older
adversaries that do not declare `detection`.

Complex detection can declare a Node entrypoint:

```yaml
detection:
  files: ["src/**"]
  entrypoint: dist/detect.js
```

The detector reads `ADVERSARY_DETECTION_INPUT`, writes the strict
`adversary.detection.v1` result to `ADVERSARY_DETECTION_OUTPUT`, and returns
only applicability, confidence, reasons, and optional relevant files plus
repository/change match booleans. It cannot emit findings. Declarative fields
remain a safe fallback if programmatic detection cannot run.

Programmatic detection is adversary code. It uses the same immutable digest,
publisher trust decision, executor, permission policy, capability checks, and
timeout boundary as review execution. Unknown publishers cannot run a detector
on `HostExecutor` unless the user supplies `--allow-unsafe-host-execution`; safe
declarative matching does not execute publisher code.

## Selection controls

Medium confidence is the default threshold. High and medium applicable results
run; low-confidence results are visible with `--explain` but do not run unless
the threshold is lowered or they are included explicitly.

```sh
adversary auto --dry-run
adversary auto --explain
adversary auto --min-confidence high
adversary auto --min-confidence medium
adversary auto --min-confidence low
adversary auto --include security --include complexity
adversary auto --exclude repository
adversary auto --all
```

`--include` forces a runnable adversary even when its detector fails.
`--exclude` wins over automatic matching, `--include`, and `--all`. `--all`
bypasses detector execution and selects the complete runnable inventory.
Selected results are ordered by confidence and then stable alphabetical name.
Detector failure is isolated to that adversary and shown with `--explain`.

If nothing applies, the command prints:

```text
No relevant adversaries detected for this change.
```

That is a successful review. Otherwise the command runs every selected
adversary, aggregates blocking findings, and returns the existing nonzero
findings status after all selected reviews finish.

Repository applicability, change applicability, automatic selection, and an
explicit `adversary run <reference>` are distinct. Repository applicability
says the technology exists somewhere in the repository. Change applicability
says the resolved change intersects the adversary's scope. Automatic selection
applies the confidence threshold and include/exclude policy. Explicit `run`
continues to run the named adversary directly.
