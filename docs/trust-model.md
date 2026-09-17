# Execution trust model

Audit decisions: CLI-001, CLI-004, and the execution portion of CLI-023.
Installation, platform compatibility, output/exit, artifact, and release trust
are maintained in the README and the linked decision records in
`docs/cli-audit-resolution.md`.

Execution is decided in distinct stages: publisher trust, requested manifest/CLI
permissions, selected executor, executor capabilities, permission policy, then
launch. Trust does not imply a capability, and selecting an executor does not
silently weaken a mandatory permission.

`HostExecutor` is a first-class backend. Its child environment is fail-closed:
only basic runtime variables, CLI-owned `ADVERSARY_*` values, and variables
named by `permissions.environment.allow` are passed to the adversary. Ambient
environment credentials are not inherited by default.

It is the default for explicit local source projects, which are trusted by the
developer's direct path selection and run without a warning or unsafe flag. It
is also acceptable for installed artifacts that carry a **verified official
signature** or a hosted private artifact whose platform-delegated team
signature matches the registry, exact repository, and digest. See
[artifact signatures](official-signatures.md). Path allowlists and registry
hostnames alone do not grant trust. Trusted remote execution reports the
publisher, immutable digest, and selected backend without an alarm-style
warning. Team membership is not inferred from publisher names.

Installed artifacts without a valid official or namespace signature are
**untrusted**. Host
execution is blocked unless the user passes `--allow-unsafe-host-execution` or
confirms interactively on a TTY. The override prints an explicit warning with
the adversary identity and runs as an unrestricted host process. Mutable remote
references resolve once through the unified repository; the resulting digest is
passed to the executor and reported before launch.

Host execution is not a sandbox: child code can access the user's filesystem,
repository, allowed process environment, processes, and network with the user's
authority. Its
capability report therefore claims none of the filesystem, environment,
network, CPU, memory, or process isolation boundaries. `--no-network`,
and manifest permissions with `enforcement: required` fail before launch with
HostExecutor when their boundary is unsupported. Manifest permissions default
to advisory: they describe the portable boundary preferred by a stronger
executor without blocking trusted local HostExecutor development. The portable manifest accepts
`permissions.environment.allow`. Incompatible requests such as
`--shell --no-network` remain rejected.

Generated and checked-in local examples mark their portable isolation requests
as advisory so they run on HostExecutor. Authors who require enforcement use:

```yaml
permissions:
  enforcement: required
  network: false
```

`--no-network` is always mandatory regardless of the manifest mode.

Empty filesystem and environment lists request no isolation boundary. Non-empty
lists request the corresponding boundary and, when enforcement is required,
fail closed if the selected executor cannot provide it.

The acknowledgement is not isolation. `NativeSandboxExecutor` and
`ContainerExecutor` are reserved backend identities, but this change does not
claim either implementation. Linux Landlock remains the first native-sandbox
target. macOS sandboxing is an independent future backend and is not a
prerequisite for local host execution.

Review output is a separate trust boundary. Child logs go to stderr; stdout contains only the selected review rendering. Missing, empty, invalid, or output larger than 16 MiB is a protocol failure. `--keep-temp` reports its path on stderr so JSON stdout remains one parseable document.

Rollback: the trust/executor separation can be reverted without changing stored
artifacts or manifests, but doing so restores the single combined host gate and
the high-friction trusted-publisher behavior. Removing only capability checks is
not a safe rollback because mandatory permissions would become advisory.
