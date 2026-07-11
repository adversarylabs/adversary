# CLI output contract

This document records the CLI-017 migration decision.

Commands that return machine-readable data accept `--format json` and emit one
JSON document on stdout. The document is an envelope with `schemaVersion: 1`,
a `command` discriminator, and a command-specific `data` object; it never serializes internal repository,
OCI, API, or runtime structs. Progress, diagnostics, and deprecation warnings
go to stderr. `--format text` is the default. Invalid formats and conflicting
legacy/new flags are rejected before command work begins.

The deprecated `--json` flags remain temporarily available and preserve their
legacy shapes where one existed. They conflict with an explicit `--format`.
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

CLI-017 is not complete in this behavior migration. Replacing captured writer
arguments with `cmd.OutOrStdout()`, `cmd.ErrOrStderr()`, and `cmd.InOrStdin()` is
explicitly assigned to the subsequent structural cleanup PR, together with
splitting `cmd/root.go`. That PR must preserve this output contract.

## Rollback

The migration can be rolled back by removing `--format`, the output DTOs, and
completion command while retaining legacy text and `--json` behavior. The
output envelope version must never be silently reused for an incompatible
shape; a future incompatible change increments `schemaVersion`.
