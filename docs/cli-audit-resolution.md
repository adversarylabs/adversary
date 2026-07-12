# CLI audit resolution matrix

This index maps every audit finding to current implementation/decision
evidence. PR links are stable review records; repository documents and tests
are the maintained contract after merge. Entries marked pending are not a
closure claim and must be updated by their final remediation PR.

| ID | Resolution evidence |
| --- | --- |
| CLI-001 | PR #2; `docs/trust-model.md`; host-boundary security tests |
| CLI-002 | PRs #7, #8, and #9 plus artifact-identity closure PR; unified repository migration, injected qualification defaults, authenticated derived alias indexes, journaled import rollback, CAS latest retargeting, restart stability, and ambiguity/tamper tests. Rollback: revert the closure PR; existing durable refs remain readable, while shorthand again follows process registry configuration. |
| CLI-003 | PR #4; OAuth state/PKCE/device-flow tests |
| CLI-004 | PRs #1, #2, #16, and #17; strict protocol, JSON purity, output-bound, DTO, and unsafe-execution tests |
| CLI-005 | PR #6; bounded ingestion and archive regression tests |
| CLI-006 | PR #5 and manifest-runtime closure PR; `docs/artifact-trust-and-limits.md`, digest tests, and deterministic OCI runtime-image validation. Rollback: revert the closure PR to restore the former permissive image string check. |
| CLI-007 | PRs #15 and #16; `docs/build-and-git-contract.md` and build/git tests |
| CLI-008 | PRs #10 and #22; `docs/network-oci-policy.md`, production API-client, fallback-tag, and transport tests |
| CLI-009 | PRs #10 and #22; OCI fallback integrity, auth/redirect/debug-redaction tests |
| CLI-010 | PR #4; `docs/auth-credential-storage.md` and locked-store tests |
| CLI-011 | PRs #3, #23, and manifest-runtime closure PR; canonical `validate` surface, exactly-one runtime identity, environment-independent image-reference validation, semantic runtime/path/project checks, schema/parser parity, and malformed YAML policy corpus. Rollback: revert the closure PR; manifests relying on both runtime identities were ambiguous and are intentionally not compatible. |
| CLI-012 | PRs #5, #6, #7, #8, #9, #11, and #12; staged repository migration and publication tests |
| CLI-013 | PRs #1 and #23 plus output-contract closure PR; canonical input/review and error schemas, Go/TypeScript validation, version rejection, ordering parity tests, caller-enforced suppressed-detail disclosure, and control-sequence-safe suppression terminal goldens. Rollback: revert the output-contract closure PR to remove the additive terminal presentation without changing protocol decoding. |
| CLI-014 | PR #16; lifecycle contracts and signal tests |
| CLI-015 | PR #15; deterministic git/build decision and regression tests |
| CLI-016 | PRs #3 and #23; atomic init, deterministic TypeScript lockfile/`npm ci`, and injected render/write cleanup tests |
| CLI-017 | PRs #17 and #18 plus output-contract and artifact-identity closure PRs; `docs/cli-output-contract.md`, versioned inspect v2 schema, canonical repository-derived identity, help/suppression/terminal-injection goldens, strict `validate` fixtures, schema-negative tests, and stdout-purity tests. Rollback: revert the closure PRs to remove additive schema branches; deprecated JSON shapes remain unchanged. |
| CLI-018 | PR #19; `docs/platform-runtime-support.md`, native CI matrix |
| CLI-019 | PRs #6 and #24 through #26; production pack, repository import/payload/repair, OCI upload, and OCI download/materialization use bounded repeatable sources with explicit leases/cleanup; PR #26 removes the legacy byte-slice compatibility APIs |
| CLI-020 | PRs #6 and #27 plus artifact-identity closure PR; sealed publication, non-mutating `pack --check`, immutable config-backed `inspect --files`, inspect v2 file DTO/schema, deterministic inventories, corruption failure, path-only secret-risk warnings, and traversal close-error tests. Rollback: remove additive inspection surfaces; packed config and repository content remain compatible. |
| CLI-021 | Final CI/release-hardening PR; required native, quality, race, coverage, cross-build, generated-template, CLI-smoke, tooling, and release-contract gates aggregate as `ci / test` |
| CLI-022 | PR #20 and final CI/release-hardening PR; channel-isolated publication, pinned workflows/tools, deterministic archives, SBOM, attestation, and the job-scoped GitHub permission decision in `docs/release.md` |
| CLI-023 | PRs #2, #19, and #20; README, trust/platform/config/output/license/compatibility decisions; a final-audit follow-up remains pending |
| CLI-024 | PRs #11 through #14 and #28; application/process dependency injection evidence; a final-audit follow-up remains pending |

Rollback notes are recorded in each linked PR and its maintained decision
document. `scripts/test-release-contract.sh` prevents release, formula, license,
version, and README command-surface drift.

## CLI-019 bounded-memory decision

Artifact layers are never represented by a production `[]byte`: packing writes
an owned temporary source, repository import/repair and payload leases copy or
open verified sources, and OCI upload/download use repeatable file-backed
sources. Command flows call these source APIs directly, so there is no
compatibility fallback.

Small control-plane documents intentionally remain byte slices because their
parsers and JSON/YAML encoders require complete documents. They are rejected
above fixed ingestion limits: OCI image manifests at 4 MiB, configs and
adversary manifests at 1 MiB. These limits do not apply to package layers,
which are streamed with a 256 MiB compressed-ingestion ceiling.

`BenchmarkCreateStreamingLargeLayer` exercises a 64 MiB incompressible layer,
and `TestCreateStreamingAllocationStaysBoundedForIncompressibleLayer` enforces
that total allocations stay below 8 MiB. Repository source tests use a 12 MiB
random layer and assert the packed artifact carries only an owned source;
repository and OCI tests also cover repeatable reads, size/digest mismatch,
overflow, stalled readers, cleanup on failure, and post-close invalidation.
