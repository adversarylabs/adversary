# Execution trust model

Audit decisions: CLI-001 and CLI-004. This is partial CLI-023 documentation limited to execution and output trust; installation, compatibility, and exit contracts remain to be documented by later work.

Adversary currently executes Node.js and shell commands directly as the CLI user. Host execution is not a sandbox: child code can access the user's filesystem, repository, environment, processes, and network with the user's authority. Manifest filesystem and environment permissions are declarations, not enforceable host-process boundaries.

The CLI therefore fails closed when `--no-network`, `permissions.network: false`, or manifest filesystem/environment restrictions request a boundary that the host executor cannot enforce. Installed and pulled artifacts require `--allow-unsafe-host-execution`; an explicit local project path does not, because selecting that path is already a direct choice of local code. `--shell` is an explicitly unsafe developer mode and also requires the acknowledgement. Incompatible claims such as `--shell --no-network` are rejected.

The current manifest representation cannot distinguish an omitted permission list from an explicitly empty list. Until the canonical manifest migration preserves that distinction, empty filesystem and environment lists mean “no restriction requested”; any non-empty list fails closed under host execution. This avoids claiming enforcement that does not exist while retaining compatibility with manifests that serialize optional lists as empty. A later parser/runtime contract must define whether an explicit empty allowlist instead means “allow nothing.”

The acknowledgement is not isolation and must only be used for trusted code. A later additive change may introduce a replaceable isolated executor with read-only repository access, bounded writable output, environment allowlisting, network policy, resource limits, and an unprivileged identity. Until then, the CLI will not claim those protections.

Review output is a separate trust boundary. Child logs go to stderr; stdout contains only the selected review rendering. Missing, empty, invalid, or output larger than 16 MiB is a protocol failure. `--keep-temp` reports its path on stderr so JSON stdout remains one parseable document.

Rollback: reverting the fail-closed checks restores legacy host execution but also restores the misleading security behavior documented by CLI-001. Reverting only the acknowledgement flag is not safe for pulled artifacts.
