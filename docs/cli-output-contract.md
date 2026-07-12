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

`validate --format json` uses the schema-version 1 `validate` discriminator.
Its strict DTO reports the canonical manifest version, validation status, and
an array of stable issue codes. Both successful and unsuccessful validation
emit exactly one JSON document on stdout; unsuccessful validation also returns
nonzero so automation cannot confuse a diagnostic document with success. The
published schema and fixtures cover both outcomes. `validate` has no deprecated
`--json` alias.

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

Terminal review output reports nonzero suppressed observation and finding
counts without revealing hidden details. The visible `Findings` count and exit
semantics continue to describe only visible findings. When the caller requests
suppressed details and the runtime includes `suppressedFindings`, those details
are rendered after visible findings, in producer order, with the factual label
`suppressed; reason unavailable`. Review protocol v1 has no per-finding
suppression-reason field. The caller enforces `--include-suppressed`: absent
that option, optional details supplied by a runtime are removed before either
text or JSON output while aggregate counts remain. JSON otherwise retains the
canonical protocol fields, so text and JSON carry the same counts and included
details without double counting. Zero suppression counts remain quiet.

All runtime-controlled strings are sanitized only at the terminal-rendering
boundary. ESC/CSI, carriage returns, C0/C1 controls, Unicode line/paragraph
separators, and terminal-dangerous bidirectional controls (ALM, LRM/RLM,
embeddings, overrides, and isolates) cannot overwrite, reorder, or inject
terminal lines. Explicit paragraph fields may retain LF layout. Other Unicode
format characters are preserved: in particular ZWNJ and ZWJ retain legitimate
Persian shaping and emoji graphemes, and BOM/zero-width no-break space is not
treated as a terminal command. JSON output is not terminal-sanitized and
retains the validated protocol data when suppressed-detail disclosure was
requested.

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

The suppression presentation and `validate` schema branch are additive
contract closures. Reverting their closure commit restores the previous human
rendering and published-schema coverage without changing protocol decoding,
visible-finding exit behavior, or manifest validation itself.
