# Process lifecycle and exit contract

This record resolves CLI-014 and completes the runtime handoff for CLI-007.

## Cancellation and deadlines (CLI-014)

The executable installs one interrupt-aware context at the process edge. Cobra
passes that context through application services to Git, builds, network calls,
and adversary execution. `run --timeout` bounds only the adversary child;
`--build-timeout` independently bounds an explicitly requested local build.
Network clients retain the independently bounded dial, TLS, response-header,
retry, and two-minute total-operation deadlines established by CLI-008. A
future command-surface change may add per-command network budgets, but this PR
does not expose a flag that cannot yet be wired consistently.

On Unix, every host adversary starts in a new process group. Cancellation sends
TERM to the group, allows 750 milliseconds for graceful shutdown, then sends
KILL to the group and waits for the direct child. Temporary input and output are
removed only after that wait completes. Reaping a cooperative direct child does
not shorten the group grace: detached group members still receive the full 750
milliseconds before KILL. Cleanup failures are non-fatal and are reported with
`--verbose`; `--keep-temp` is the explicit preservation mechanism.

Windows does not yet use a Job Object. Cancellation kills and waits for the
direct child, and Windows adversaries must not detach descendants. This is an
intentional, fail-documented platform limitation; Job Object supervision is the
required future resolution before claiming descendant-tree termination there.

## Local build policy (CLI-007)

`adversary run` no longer mutates a local source tree implicitly. Existing
`dist` output is used by default and missing output fails before a temporary run
directory or child is created. `--build` explicitly requests the transactional
builder and `--build-timeout` bounds it. The retired `--no-build` spelling is a
deprecated no-op kept for script compatibility; combining it with `--build` is
rejected before work begins.

## Stable process status

The executable is the only layer that converts errors to process status:

| Code | Meaning |
| ---: | --- |
| 0 | Successful run with no findings |
| 1 | Valid adversary result containing findings |
| 2 | Usage, configuration, or local policy error |
| 3 | Adversary/protocol failure or execution timeout |
| 4 | Network or authentication failure |
| 130 | User interrupt |

A child process's exit status is preserved in the typed diagnostic while the
CLI returns class 3. Libraries return typed errors and never call `os.Exit`.
Cobra argument and flag failures, local configuration, findings, child exits,
protocol failures, and API/OCI failures cross the process edge as typed errors;
error message text never participates in status classification.
Cobra usage remains silenced after parsing so errors are printed exactly once.

## Verification and rollback

Regression coverage includes descendant termination, timeout propagation, child
status preservation, exit-class mapping, explicit-build behavior, normal and
canceled cleanup, verbose cleanup failures, and Windows cross-compilation.

Rollback can revert this change as one unit. Doing so restores implicit local
builds and direct-child-only cancellation; it does not alter artifact formats,
repository state, manifests, or network protocols. The `--no-build` compatibility
flag can be removed in a later breaking CLI release after deprecation telemetry.
