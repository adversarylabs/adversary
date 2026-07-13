# Execution trust model

Audit decisions: CLI-001, CLI-004, and the execution portion of CLI-023.
Installation, platform compatibility, output/exit, artifact, and release trust
are maintained in the README and the linked decision records in
`docs/cli-audit-resolution.md`.

Adversary currently executes Node.js and shell commands directly as the CLI user. Host execution is not a sandbox: child code can access the user's filesystem, repository, environment, processes, and network with the user's authority. Manifest filesystem and environment permissions are declarations, not enforceable host-process boundaries.

The CLI therefore fails closed when `--no-network`, `permissions.network: false`, or manifest filesystem/environment restrictions request a boundary that the host executor cannot enforce. Installed and pulled artifacts require `--allow-unsafe-host-execution`; an explicit local project path does not, because selecting that path is already a direct choice of local code. `--shell` is an explicitly unsafe developer mode and also requires the acknowledgement. Incompatible claims such as `--shell --no-network` are rejected.

The current manifest representation cannot distinguish an omitted permission
list from an explicitly empty list. The compatibility decision is therefore
that empty filesystem and environment lists mean “no restriction requested”;
any non-empty list fails closed under host execution. A future schema version
may distinguish an explicit empty allowlist, but the current version does not
claim that meaning.

The acknowledgement is not isolation and must only be used for trusted code.
An isolated executor would require a separate reviewed policy for read-only
repository access, bounded writable output, environment allowlisting, network
access, resource limits, and identity. No such executor is currently claimed.

Review output is a separate trust boundary. Child logs go to stderr; stdout contains only the selected review rendering. Missing, empty, invalid, or output larger than 16 MiB is a protocol failure. `--keep-temp` reports its path on stderr so JSON stdout remains one parseable document.

Rollback: reverting the fail-closed checks restores legacy host execution but also restores the misleading security behavior documented by CLI-001. Reverting only the acknowledgement flag is not safe for pulled artifacts.
