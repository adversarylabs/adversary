# CLI output contract

This document records the CLI-017 migration decision.

Commands that return machine-readable data accept `--format json` and emit one
JSON document on stdout. The document is an envelope with `schemaVersion: 1`,
a `command` discriminator, and a command-specific `data` object; it never serializes internal repository,
OCI, API, or runtime structs. Progress, diagnostics, and deprecation warnings
go to stderr. `--format text` is the default. Invalid formats and conflicting
legacy/new flags are rejected before command work begins.

The deprecated `--json` flags remain temporarily available and preserve their
legacy shapes where one existed. In particular, `pack --json` remains the
schema-version 1 pack DTO without inventory fields. `pack --format json` emits
schema version 2, whose strict DTO adds the deterministic file inventory and
path-only secret-risk warnings. `pack --check --format json` is the separate
schema-version 1 `pack-check` discriminator. Legacy flags conflict with an explicit `--format`.

Pack preflight resolves entrypoints without executing them. Named Node runtimes
and named process commands containing a path separator must use a contained,
package-relative command whose first element exists in the packed inventory.
A bare named-process command such as `python3` is deliberately deferred to
runtime `PATH` resolution. Image commands are resolved inside their declared
image, so preflight does not look for those paths on the host or in the package.

Secret-risk warnings inspect paths only, never file contents. The conservative
heuristic recognizes common dotfiles (`.npmrc`, `.pypirc`, `.netrc`, `.env`),
private-key extensions, SSH key names, kubeconfig paths, and common AWS, GCP,
and Azure credential basenames. It is advisory: warnings alone exit zero, and
operators must still review the complete inventory. Example/template suffixes
and merely similar words are intentionally not classified.
The deprecated `--debug` alias enables `--verbose` and warns on stderr.

`inspect --format json` describes a resolved stored artifact. Inspecting a
local source path is execution-plan validation and remains text-only until a
separate execution-plan schema is designed; the command fails rather than
silently returning a different JSON shape.

Text tables sanitize control characters and line breaks. This migration emits
no ANSI color under any circumstances, so output is stable and uncolored for
interactive and noninteractive use and inherently honors `NO_COLOR`.

The CLI ships completion generation for bash, zsh, fish, and PowerShell. Man
pages are not checked in: Cobra help is the canonical source and release
packaging may generate man pages from the pinned binary in a future additive
change.

CLI-017 is complete. `cmd/root.go` is a thin process/composition edge, while
each command or closely related command domain has its own source file.
Handlers resolve standard input, output, and error streams from the executing
Cobra command with `cmd.InOrStdin()`, `cmd.OutOrStdout()`, and
`cmd.ErrOrStderr()`. A subcommand may therefore override any stream without
being bypassed by writers captured when the command tree was constructed.
Source-invariant tests keep process-global streams at the process edge, reject
captured constructor streams, and bound the size and responsibilities of the
composition root. Root and version help are checked as golden fixtures.

## Rollback

The structural cleanup can be rolled back independently by reverting its
commit: it intentionally changes no command names, flags, DTOs, or runtime
behavior. Do not roll back to constructor-captured streams selectively, since
that would make subcommand-local redirection unreliable. The earlier output
migration can still be rolled back by removing `--format`, the output DTOs,
and completion command while retaining legacy text and `--json` behavior. The
output envelope version must never be silently reused for an incompatible
shape; a future incompatible change increments `schemaVersion`.
