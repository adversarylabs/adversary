# CLI audit resolution matrix

This index maps every CLI audit finding to merged review records and maintained
repository evidence. Pull-request links are the historical review trail; the
linked decisions, schemas, tests, and verification script are the current
contract.

| ID | Merged pull requests | Maintained resolution evidence |
| --- | --- | --- |
| CLI-001 | [#2](https://github.com/adversarylabs/adversary/pull/2) | `docs/trust-model.md` and host-execution fail-closed tests document that acknowledgement is not isolation. |
| CLI-002 | [#7](https://github.com/adversarylabs/adversary/pull/7), [#8](https://github.com/adversarylabs/adversary/pull/8), [#9](https://github.com/adversarylabs/adversary/pull/9), [#32](https://github.com/adversarylabs/adversary/pull/32) | The unified repository owns qualification defaults, authenticated aliases, failure-atomic import journals, CAS reference updates, and restart-stable identity. Ambiguous or tampered aliases fail closed. |
| CLI-003 | [#4](https://github.com/adversarylabs/adversary/pull/4), [#39](https://github.com/adversarylabs/adversary/pull/39), [#40](https://github.com/adversarylabs/adversary/pull/40) | OAuth state, PKCE, exact loopback redirect, single-claim callback, failure cleanup, terminal premature server exits, and device-flow regression tests cover authentication boundaries. |
| CLI-004 | [#1](https://github.com/adversarylabs/adversary/pull/1), [#2](https://github.com/adversarylabs/adversary/pull/2), [#16](https://github.com/adversarylabs/adversary/pull/16), [#17](https://github.com/adversarylabs/adversary/pull/17) | Strict protocol decoding, JSON stdout purity, bounded output, typed errors, and unsafe-host-execution acknowledgement are enforced by tests and `docs/trust-model.md`. |
| CLI-005 | [#5](https://github.com/adversarylabs/adversary/pull/5), [#6](https://github.com/adversarylabs/adversary/pull/6), [#37](https://github.com/adversarylabs/adversary/pull/37) | `docs/artifact-trust-and-limits.md` records hard network/archive limits, type rejection, staging, sealing, strict metadata/inventory cross-checks, and rollback behavior; adversarial archive and pre-publication failure tests enforce them. |
| CLI-006 | [#5](https://github.com/adversarylabs/adversary/pull/5), [#30](https://github.com/adversarylabs/adversary/pull/30) | Descriptor digests/sizes and config identity are cross-checked; runtime images use deterministic canonical OCI-reference validation. |
| CLI-007 | [#15](https://github.com/adversarylabs/adversary/pull/15), [#16](https://github.com/adversarylabs/adversary/pull/16), [#33](https://github.com/adversarylabs/adversary/pull/33), [#38](https://github.com/adversarylabs/adversary/pull/38) | Builds are explicit, transactional, isolated from the source tree, and use captured executable/environment/process and canonical build-state dependencies for both pack and run. See `docs/build-and-git-contract.md`. |
| CLI-008 | [#10](https://github.com/adversarylabs/adversary/pull/10), [#22](https://github.com/adversarylabs/adversary/pull/22), [#41](https://github.com/adversarylabs/adversary/pull/41) | `docs/network-oci-policy.md` and API-client tests enforce bounded clients, request-cancelable credential helpers, safe retries, redirect/realm policy, and sanitized failures. |
| CLI-009 | [#10](https://github.com/adversarylabs/adversary/pull/10), [#22](https://github.com/adversarylabs/adversary/pull/22) | OCI fallback tags, digest/size verification, credential scope, redirects, and debug redaction are covered by deterministic registry tests. |
| CLI-010 | [#4](https://github.com/adversarylabs/adversary/pull/4) | `docs/auth-credential-storage.md` records the scoped, locked, owner-only credential decision and its same-user residual risk. |
| CLI-011 | [#3](https://github.com/adversarylabs/adversary/pull/3), [#23](https://github.com/adversarylabs/adversary/pull/23), [#30](https://github.com/adversarylabs/adversary/pull/30) | `validate` uses the canonical parser/schema, requires exactly one runtime identity, and checks semantic paths, projects, and environment-independent image references. |
| CLI-012 | [#5](https://github.com/adversarylabs/adversary/pull/5), [#6](https://github.com/adversarylabs/adversary/pull/6), [#7](https://github.com/adversarylabs/adversary/pull/7), [#8](https://github.com/adversarylabs/adversary/pull/8), [#9](https://github.com/adversarylabs/adversary/pull/9), [#11](https://github.com/adversarylabs/adversary/pull/11), [#12](https://github.com/adversarylabs/adversary/pull/12) | Repository publication, leases, lifecycle journals, migration checkpoints, check/GC behavior, and unified resolver migration are durable and regression-tested. |
| CLI-013 | [#1](https://github.com/adversarylabs/adversary/pull/1), [#23](https://github.com/adversarylabs/adversary/pull/23), [#31](https://github.com/adversarylabs/adversary/pull/31), [#42](https://github.com/adversarylabs/adversary/pull/42), `sdk-contract-migration PR` | Versioned input/review/error schemas have Go/TypeScript parity, strict version rejection, caller-controlled suppression disclosure, terminal-control sanitization, and a staged migration from the legacy TypeScript rule-summary return to the canonical review envelope. |
| CLI-014 | [#16](https://github.com/adversarylabs/adversary/pull/16) | `docs/process-lifecycle-and-exit-contract.md` defines cancellation, Unix process-group termination, cleanup, timeouts, typed exits, and the documented Windows limit. |
| CLI-015 | [#15](https://github.com/adversarylabs/adversary/pull/15) | Typed Git changes preserve NUL-delimited paths, rename/copy identity, three-dot semantics, shallow-history errors, and safe glob compilation. |
| CLI-016 | [#3](https://github.com/adversarylabs/adversary/pull/3), [#23](https://github.com/adversarylabs/adversary/pull/23) | Project initialization is atomic and injected; generated TypeScript uses a deterministic lockfile and `npm ci`, with render/write cleanup tests. |
| CLI-017 | [#17](https://github.com/adversarylabs/adversary/pull/17), [#18](https://github.com/adversarylabs/adversary/pull/18), [#31](https://github.com/adversarylabs/adversary/pull/31), [#32](https://github.com/adversarylabs/adversary/pull/32) | `docs/cli-output-contract.md`, versioned schemas/fixtures, command-scoped streams, canonical repository identity, inspect inventory v2, suppression goldens, and stdout-purity tests define the automation surface. |
| CLI-018 | [#19](https://github.com/adversarylabs/adversary/pull/19) | `docs/platform-runtime-support.md` records the OS/runtime matrix, captured executable discovery, data/config locations, and native CI coverage. |
| CLI-019 | [#6](https://github.com/adversarylabs/adversary/pull/6), [#24](https://github.com/adversarylabs/adversary/pull/24), [#25](https://github.com/adversarylabs/adversary/pull/25), [#26](https://github.com/adversarylabs/adversary/pull/26) | Production package layers use bounded repeatable sources, owned temporary files, and repository leases end to end; whole-layer compatibility APIs were removed. |
| CLI-020 | [#6](https://github.com/adversarylabs/adversary/pull/6), [#27](https://github.com/adversarylabs/adversary/pull/27), [#32](https://github.com/adversarylabs/adversary/pull/32), [#37](https://github.com/adversarylabs/adversary/pull/37) | Publication is sealed; `pack --check` is non-mutating; inspect v2 exposes an inventory only after exact extracted path/mode/size/hash verification against strict immutable config metadata. |
| CLI-021 | [#1](https://github.com/adversarylabs/adversary/pull/1), [#29](https://github.com/adversarylabs/adversary/pull/29), [#34](https://github.com/adversarylabs/adversary/pull/34), [#37](https://github.com/adversarylabs/adversary/pull/37) | `.depot/workflows/ci.yml` makes native tests, formatting, module verification, vet, race, coverage, five cross-builds, TypeScript/template and CLI smoke tests, security tooling, release contracts, and artifact transaction regressions dependencies of `ci / test`. |
| CLI-022 | [#1](https://github.com/adversarylabs/adversary/pull/1), [#20](https://github.com/adversarylabs/adversary/pull/20), [#29](https://github.com/adversarylabs/adversary/pull/29), [#34](https://github.com/adversarylabs/adversary/pull/34) | `docs/release.md` records pinned tools/actions, deterministic archives, checksums, SBOMs, attestations, isolated publication credentials, draft-first verification, and job-scoped permissions. |
| CLI-023 | [#2](https://github.com/adversarylabs/adversary/pull/2), [#19](https://github.com/adversarylabs/adversary/pull/19), [#20](https://github.com/adversarylabs/adversary/pull/20), [#29](https://github.com/adversarylabs/adversary/pull/29), [#34](https://github.com/adversarylabs/adversary/pull/34), [#37](https://github.com/adversarylabs/adversary/pull/37) | Maintained decisions cover installation, configuration precedence, trust, output/exits, storage, platform compatibility, and release provenance. Stored artifacts are revalidated before inventory, republish, or execution so pre-gate content cannot bypass the documented trust boundary. |
| CLI-024 | [#11](https://github.com/adversarylabs/adversary/pull/11), [#12](https://github.com/adversarylabs/adversary/pull/12), [#13](https://github.com/adversarylabs/adversary/pull/13), [#14](https://github.com/adversarylabs/adversary/pull/14), [#28](https://github.com/adversarylabs/adversary/pull/28), [#33](https://github.com/adversarylabs/adversary/pull/33), [#38](https://github.com/adversarylabs/adversary/pull/38), [#39](https://github.com/adversarylabs/adversary/pull/39), [#40](https://github.com/adversarylabs/adversary/pull/40) | Every production command receives `application.App`; projects, references, credentials, browser authentication, runtime processes, filesystems, persistent/coordination paths, environment, and streams cross replaceable ports. Hermetic and alias-aware AST tests reject ambient dependency regressions. |

## Rollback and compatibility

The linked PRs contain change-specific rollback notes. The maintained decisions
also identify the compatibility boundary before rollback: schema additions keep
their prior versions, repository records and content paths remain readable,
streaming and composition changes do not migrate stored data, and release/build
policy changes can be reverted without changing artifact formats. Security
hardening must be reverted as a coherent unit; selectively restoring ambient
credential, execution, parsing, or alias behavior would restore the audit risk.

`scripts/test-release-contract.sh` guards release, formula, license, version,
and README command-surface drift. `scripts/ci-verify.sh` is the shared local/CI
entry point for the complete verification contract.

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

## Completion status and intentional limitations

CLI-001 through CLI-024 have an implementation or an explicit repository
decision above. The following are deliberate boundaries, not unfinished audit
claims:

- Host adversaries are not sandboxed; unsupported network, filesystem, and
  environment restrictions fail closed.
- Artifact digests prove integrity, not publisher authenticity. No publisher
  trust-root/signature policy has been selected.
- Windows terminates the direct child but does not yet supervise a descendant
  tree with a Job Object.
- Release archives target Linux and macOS on amd64/arm64. Windows is tested and
  source-build supported, but has no packaged release.
- Credential files are owner-only but not encrypted against the same OS user;
  no native keyring backend is selected.
- Multi-platform OCI indexes, referrer pagination, and resumable uploads remain
  intentionally unsupported under the fail-closed policy in
  `docs/network-oci-policy.md`.
- The repository owner has not selected a source license. `LICENSE` therefore
  grants no reuse rights and the Homebrew formula makes no license claim.

Changing any boundary requires its own reviewed compatibility, trust, or legal
decision; its absence is not implied support.
