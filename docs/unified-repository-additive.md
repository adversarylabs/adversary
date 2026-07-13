# Unified repository additive phase

This additive change addresses the storage foundation of CLI-002 and CLI-012.
`pkg/repository` is a single content-addressed API for importing locally packed
or already verified pulled artifacts, including their exact bounded raw OCI
manifest bytes. Immutable records are derived from the manifest descriptors and
config identity rather than caller metadata. Content and records are keyed by exact
digests; canonical references and aliases use hashes of their exact UTF-8 bytes.
Short aliases retain every candidate and fail as ambiguous instead of choosing
by filesystem or iteration order.

Reference updates are explicit compare-and-swap operations protected by
interprocess locks. Content, records, references, and alias indexes publish via
private temporary files and platform-specific atomic replacement (including
Windows `MoveFileEx` replacement for mutable indexes). Immutable content uses
no-replace publication. Temporary files are flushed before publication and
affected parent directories are flushed after link/rename and temporary-name
removal. Windows retains `MOVEFILE_WRITE_THROUGH`; directory flushing is best
effort because directory handles do not consistently support
`FlushFileBuffers`. A durable digest commit precedes index reconciliation;
The configured repository root must be created durably by its caller before
opening the repository. Initialization creates rooted child directories and
flushes that provisioned root before the first content or index publication;
this makes root-parent durability an explicit provisioning responsibility.
aliases are reconciled before the exact reference is committed last, so an
interrupted retry is idempotent and an exact ref never exposes a partial index
transaction. Records contain only identities and
digests—derived paths are always recomputed relative to the configured root.
Verification reports missing and corrupt content; repair accepts only bytes
whose digest matches the requested object and replaces corruption only while
holding that content digest's lock. Verification streams through a hard bound.
Materialization reloads the canonical record by digest (ignoring caller-supplied
fields), reverifies under lock, and reuses the bounded,
sealed archive policy and publishes under a digest lock.

Migration hooks are intentionally explicit: callers may use `ImportPacked` for
legacy local artifacts and `ImportPulled` only after registry verification.
This PR does not switch CLI commands or delete either legacy store. A migration
PR must import, compare results, then change readers; cleanup follows only after
rollback confidence. Rollback of this additive phase is removal of the package
and its repository directory, with no legacy data changes.

Migration requires a positive page limit and enumerates committed immutable
records in digest order using bounded
directory pages and a globally smallest-N selection above the digest cursor, persist named
checkpoints, and reconcile bounded batches. These operations are idempotent, so
a migration may resume after an interrupted import or index update. Malformed
reference and alias indexes fail closed and can be rebuilt from records and
explicit source-reference input.
Uncommitted orphan records left by a crash are skipped explicitly; a malformed
or tampered committed record fails reconciliation instead of being skipped.

Intentional limits: referrer/signature trust remains governed by the artifact
trust decision, and cross-device repository moves are unsupported. Reference
replacement uses compare-and-swap; ambiguity errors require an exact reference
or digest rather than an inferred policy choice.
