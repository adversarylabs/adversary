# Unified resolver migration (CLI-002, CLI-012)

Run, inspect, list, push, and pull now share the unified repository through the
resolver service. Resolution precedence is deterministic: an existing
filesystem package, an exact digest, a fully qualified registry reference, an
exact local name and tag, then an unambiguous short alias. Ambiguous aliases
fail and require an exact reference or digest. Human and JSON inspection output
include the canonical input reference and immutable digest.

Pack and verified pull results are written transactionally only to the unified
repository; legacy stores are migration inputs, not dual-write targets. Pulling a new
reference for content already present performs a compare-and-swap reference
registration without redownloading; repository payloads can be repushed without
depending on a legacy absolute path. Materialization uses the same bounded and
sealed archive path. Vendored SDK preparation occurs in a deterministic derived
execution tree before sealing; immutable source content is not mutated.

Legacy local-store records migrate only on a true repository miss by re-reading their verified OCI
payload and importing it under a canonical name and tag. The older cache cannot
reconstruct the exact raw OCI manifest from extracted files, so it remains a
read-only fallback during this migration phase; an exact registry pull supplies
the lossless migration path. Repository enumeration/checkpoints remain the safe
bulk migration and reconciliation mechanism.

Rollback reverts command wiring; neither legacy store is deleted and unified
content remains digest-addressed. The cleanup phase must wait until migration
telemetry shows no legacy-only records. Intentional limitations are the
same-user filesystem authority and publisher-identity decisions documented in
the artifact trust model.

Exact digest/reference corruption and I/O errors fail closed and never trigger
legacy fallback. Canonical output is queried from durable reference indexes;
short aliases are never presented as invented identities. Reference
registration uses observed-old compare-and-swap and reports conflicts.
