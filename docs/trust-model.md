# Execution trust model

Audit decisions: CLI-001, CLI-004, and the execution portion of CLI-023.
Installation, platform compatibility, output/exit, artifact, and release trust
are maintained in the README and the linked decision records in
`docs/cli-audit-resolution.md`.

Execution is decided in distinct stages: publisher trust, requested manifest/CLI
permissions, selected executor, executor capabilities, permission policy, then
launch. Trust does not imply a capability, and selecting an executor does not
silently weaken a mandatory permission.

`HostExecutor` is a first-class backend.
It is the default for explicit local source projects, which are trusted by the
developer's direct path selection and run without a warning or unsafe flag. It
is also acceptable for installed artifacts from publishers trusted by the
replaceable publisher policy. The built-in policy trusts `adversarylabs` only
on the official registry; a lookalike namespace on another registry is
unknown. Trusted remote execution reports the publisher, immutable digest, and
selected backend without an alarm-style warning. Team membership is not inferred
from publisher names; future organization trust must come from authenticated
identity supplied by the registry or an enterprise trust store.

Installed artifacts from unknown publishers require a sandbox executor or
`--allow-unsafe-host-execution`. The latter prints an explicit warning naming
the unknown publisher and resolved digest. Mutable remote references resolve
once through the unified repository; the resulting digest is passed to the
executor and reported before launch.

Host execution is not a sandbox: child code can access the user's filesystem,
repository, environment, processes, and network with the user's authority. Its
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
