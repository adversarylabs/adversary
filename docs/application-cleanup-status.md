# Application composition boundary (CLI-024)

CLI-024 is complete. Every production command is constructed from an explicit
`application.App`. Authentication persistence, Adversary Labs API operations,
and OCI registry creation are strongly typed ports/factories; login, logout,
search, whoami, push, pull, and default namespace selection do not construct or
discover dependencies inside handlers.

`cmd/app.go` is the production composition edge. It reads environment-backed
flag defaults once, validates and binds the config/API/registry factories, and
injects argv, stdio, the environment snapshot, home and temporary directories,
the data root, clock, filesystem, build operation, shell lookup, and Node
discovery into the runtime service. It also resolves Git and every bare runtime
command from that captured `PATH` and injects the process launcher and helper
output runner used for Git queries, Node version probes, browser launch, and
adversary execution. The environment snapshot is immutable; runtime-owned
variables replace inherited collisions, including case-insensitively on
Windows. Empty or relative `PATH` entries fail closed, and a resolver must
return an absolute canonical path. `PATH` aliases are never launched: the
composition edge canonicalizes them, validates the target, and passes that
target to probes and launchers. Explicit paths validate before canonicalization
and therefore reject symlink components.

Structured command output remains on the application's stdout. Both stdout and
stderr from an adversary child are diagnostic streams and are routed to the
application's stderr so JSON output remains machine-parseable. Runtime
resolution, Git, discovery, environment, and lifecycle policy do not consult
ambient process state. `internal/adversary` limits `os`, `os/exec`, and timer
access to explicitly named concrete adapters; an AST/import-path regression
guard enforces that boundary across the business runtime-policy files. Tests
can replace the process launcher, output runner, executor, clock, filesystem,
build ports, paths, environment, and streams without launching a real process
or touching the process home or temporary directory.

Registry authorization decisions use `oci.RegistryError` status and distribution
error codes. Handler behavior no longer depends on matching human-readable error
strings. Factory binding identities fail closed when auth, API, and registry
dependencies belong to different configurations.

Rollback may restore the previous composition commit without changing repository
formats, credential schemas, remote API contracts, or command output. It would
restore ambient runtime discovery and therefore re-open CLI-024.
