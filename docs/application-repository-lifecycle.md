# Application boundary and repository lifecycle (CLI-024, CLI-012)

This additive phase begins, but does not complete, CLI-024 by introducing `internal/application` ports and
`internal/dependencies` function adapters. `App` is constructed with explicit
stdin/stdout/stderr, clock, environment, configuration, paths, HTTP,
credentials, registry, repository, resolver, runtime, browser, and TTY
dependencies. Missing dependencies return typed contextual errors. The new
layer performs no process-global lookup and supplies no implicit defaults, so
tests and future embedders can construct every boundary without mutating global
state.

Command migration is deliberately a later PR. Its sequence is: construct real
adapters at the process edge; migrate read-only commands; migrate authentication
and registry commands; migrate artifact mutation and run; then remove old
constructors. During migration `cmd` owns flag/UI translation,
`internal/application` owns use-case orchestration, adapters own external side
effects, and `pkg/repository` owns persistence invariants. No command behavior
changes in this phase.

Repository lifecycle APIs add CAS reference deletion, deterministic GC
plan/apply reports, dry runs, full check/repair reports, and named migration
status/checkpoints. References are the reachability roots. Planning validates
every bounded reference and committed record; corruption fails closed. Apply
verifies the plan hash, complete committed-record generation, protected-content
set, and exact reference snapshot under the lifecycle lock,
preflights every candidate before mutation, then locks each digest/content
object. Reachable records, content, and materializations are never deleted.
Materialized trees are unsealed only immediately before rooted deletion.
Imports, materialization, reference changes, and GC share the explicit
global/digest/materialization/content lock order. Before mutation, apply writes
a durable journal; materialization, commit, record, and unique-content actions
are idempotent and resume from the journal after interruption. Checkpoint
writers use per-name locks, validate digests/counts, and expose monotonic CAS
updates for concurrent workers. All scans paginate stably and persisted reads
have explicit bounds rather than silently truncating reports.
GC completes materialization, commit, and record removal for every candidate
before beginning one global, deduplicated content pass. Each content action is
journaled independently as pending, deleted, or retained. Reachability is
recomputed before every deletion, so a record imported between recovery runs
can protect shared content even after another candidate was partially cleaned.
Protection includes every current committed record outside the journal delete
set, not only reference targets; an unreferenced import is therefore preserved
while its lifecycle decision remains pending.

`Materialize` guarantees a complete path only at return time; it is not a
runtime-use lease. `LeaseMaterialized` and `WithMaterialized` retain the same
cross-process materialization lock until `Close` or callback return, preventing
GC from deleting an artifact in use. The next migration must wire runner
execution to this lease before exposing any GC command. Until then lifecycle GC
remains an internal API and must not be reachable from CLI startup or
maintenance commands.
The `WithMaterialized` callback is a pure runtime-use boundary: it must not call
repository methods or take a nested lease because it already owns the
cross-process materialization lock. Runner migration must resolve repository
state before entering the callback and perform only runtime I/O inside it.

Alias indexes are discovery hints rather than reachability roots. GC may leave
digest tombstones in an alias list; resolution already filters uncommitted
digests and fails closed on ambiguity. Rebuilding compact alias indexes is
deferred to the command migration/maintenance UI because deleting an alias
without recording its original reference provenance can erase a still-useful
name. This trades small bounded index growth for identity safety.

Rollback reverts these additive packages and methods. Existing repository data
and schemas are unchanged. A GC apply cannot be rolled back from repository
metadata alone, so callers must display and persist the dry-run plan before
apply; content remains recoverable only from its registry/source. Command
migration must therefore ship GC as opt-in maintenance, never an implicit
startup action.
