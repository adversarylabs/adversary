# Unified resolver migration (CLI-002, CLI-012)

Run, inspect, list, push, and pull now share the unified repository through the
resolver service. Resolution precedence is deterministic: an existing
filesystem package, an exact digest, a fully qualified registry reference, an
exact local name and tag, then an unambiguous short alias. Ambiguous aliases
fail and require an exact reference or digest. Human and JSON inspection output
include the canonical input reference and immutable digest.

Pack and verified pull results are written transactionally only to the unified
repository; legacy stores are neither runtime inputs nor dual-write targets. Pulling a new
reference for content already present performs a compare-and-swap reference
registration without redownloading; repository payloads can be repushed without
depending on a legacy absolute path. Materialization uses the same bounded and
sealed archive path. Vendored SDK preparation occurs in a deterministic derived
execution tree before sealing; immutable source content is not mutated.

PR 8 was the migration boundary. Operators with legacy local-store records had
to enumerate and import those records before upgrading past that release, or
re-pull their exact registry references afterward. The older extracted cache
cannot reconstruct the exact raw OCI manifest and therefore was intentionally
excluded from automatic migration. A missing unified-repository record now
fails as not found; commands and the resolver never inspect or mutate legacy
directories.

Rollback reverts command and resolver wiring; legacy data is left untouched and
unified content remains digest-addressed. Retired store paths remain classified
as artifact-controlled for host-execution safety, but no legacy package code is
linked and those paths are never read for resolution. Intentional limitations
are the same-user filesystem authority and publisher-identity decisions
documented in the artifact trust model.

Exact digest/reference corruption and I/O errors fail closed and never trigger
legacy fallback. Canonical output is queried from durable reference indexes;
short aliases are never presented as invented identities. Reference
registration uses observed-old compare-and-swap and reports conflicts.
