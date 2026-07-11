# CLI audit resolution matrix

This index maps every audit finding to its merged implementation/decision
evidence. PR links are stable review records; repository documents and tests
are the maintained contract after merge.

| ID | Resolution evidence |
| --- | --- |
| CLI-001 | PR #2; `docs/trust-model.md`; host-boundary security tests |
| CLI-002 | PRs #7, #8, and #9; unified repository migration and cleanup records |
| CLI-003 | PR #4; OAuth state/PKCE/device-flow tests |
| CLI-004 | PRs #1, #2, #16, and #17; strict protocol, JSON purity, output-bound, DTO, and unsafe-execution tests |
| CLI-005 | PR #6; bounded ingestion and archive regression tests |
| CLI-006 | PR #5; `docs/artifact-trust-and-limits.md` and digest tests |
| CLI-007 | PRs #15 and #16; `docs/build-and-git-contract.md` and build/git tests |
| CLI-008 | PRs #10 and #21; `docs/network-oci-policy.md`, production API-client, fallback-tag, and transport tests |
| CLI-009 | PRs #10 and #21; OCI fallback integrity, auth/redirect/debug-redaction tests |
| CLI-010 | PR #4; `docs/auth-credential-storage.md` and locked-store tests |
| CLI-011 | PR #3 and contracts-closure PR; canonical `validate` surface, semantic runtime/path/project checks, and malformed YAML policy corpus |
| CLI-012 | PRs #5, #6, #7, #8, #9, #11, and #12; staged repository migration and publication tests |
| CLI-013 | PR #1 and contracts-closure PR; canonical input/review plus error schemas, Go/TypeScript validation, version rejection, and ordering parity tests |
| CLI-014 | PR #16; lifecycle contracts and signal tests |
| CLI-015 | PR #15; deterministic git/build decision and regression tests |
| CLI-016 | PR #3 and contracts-closure PR; atomic init, deterministic TypeScript lockfile/`npm ci`, and injected render/write cleanup tests |
| CLI-017 | PRs #17 and #18; `docs/cli-output-contract.md`, help goldens, DTO tests |
| CLI-018 | PR #19; `docs/platform-runtime-support.md`, native CI matrix |
| CLI-019 | PR #6 plus streaming additive/migration/cleanup PRs; production pack, repository import/payload/repair, OCI upload, and OCI download/materialization use bounded repeatable sources with explicit leases/cleanup; the cleanup PR removes the legacy byte-slice compatibility APIs |
| CLI-020 | PR #6; sealed publication and cross-process locking tests |
| CLI-021 | PRs #1, #8, #9, #11, #12, and #15 through #19; versioned protocol, resolver, build, lifecycle, output, and platform contracts |
| CLI-022 | Release-hardening PR; pinned workflows, deterministic archive test, SBOM and attestation policy in `docs/release.md` |
| CLI-023 | PRs #2, #19, and release/docs PR; README, trust/platform/config/output/license/compatibility decisions |
| CLI-024 | PRs #11 through #14 and release/docs PR; cleanup status plus SECURITY, CONTRIBUTING, dependency and release hygiene |

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
