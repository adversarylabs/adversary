# Authentication credential storage decision

Status: accepted for CLI-010 (2026-07-10).

The CLI continues to use a hardened file-backed credential store for this release instead of making an operating-system keyring mandatory. Desktop keyrings are preferable when available, but a mandatory cross-platform keyring introduces new native/runtime dependencies and can fail in headless Linux, containers, SSH sessions, and CI. Silently falling back from a keyring would also make credential location and deletion behavior difficult to reason about.

The fallback is now deliberately constrained: its directory and files are private, symlinks are rejected, updates are serialized across processes and use an fsync/atomic-rename/fsync sequence, malformed data is surfaced, expiration includes clock skew, and credentials are scoped to normalized API service and profile. The registry host is retained in the record so OCI lookup can migrate without duplicating tokens; legacy registry-keyed records remain readable.

Residual risk: a file token is available to any process running as the same OS user and is not encrypted at rest. Filesystem permissions do not protect against a compromised user session or privileged administrator.

Migration path: add an explicit credential-backend setting and maintained native keyring adapter in an additive release; copy a credential only after the keyring write is verified; retain file reads during a deprecation window; then remove the file token after successful server validation. Headless users must be able to select the documented file backend explicitly. Rollback of this change is safe at the config schema level because unknown `registry_host` fields are ignored and legacy registry-keyed records remain supported.
