# Application composition boundary (CLI-024)

CLI-024 is complete. Every production command is constructed from an explicit
`application.App`. Authentication persistence, Adversary Labs API operations,
and OCI registry creation are strongly typed ports/factories; login, logout,
search, whoami, push, pull, and default namespace selection do not construct or
discover dependencies inside handlers.

Project creation, manifest/project validation, pack preflight, and package
building are owned by the injected `Projects` port. Handlers do not call the
filesystem, template renderer, manifest loader, or builder directly. Reference
parsing is injected with registry and namespace defaults captured during App
construction, so later environment changes cannot make pack, push, pull, and
repository qualification disagree.

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

Docker credential discovery receives the captured home directory and an
explicit helper-process adapter. Credential requests never rediscover HOME,
PATH, or process execution policy. Dead mandatory Config, Paths, HTTP,
Credentials, and Environment App fields were removed. An AST regression guard
rejects ambient environment, home, temporary-directory, process, filesystem,
project, build, manifest, and reference-parser calls from command handlers.

The pack service receives immutable environment entries, canonical npm/Node/
Docker executable paths, and a bounded context-aware process runner captured by
the composition root. Both `pack` and runtime-requested project builds use this
same dependency; changing HOME or PATH after App construction cannot change the
selected tools. Package filesystem work remains in the explicit concrete pack
adapter, while build policy has no ambient environment or process-discovery
edge.

Docker config opening rejects symlinks, FIFOs, devices, directories, and handle
identity changes. Unix uses `O_NOFOLLOW|O_NONBLOCK`; Windows opens the reparse
point itself with `FILE_FLAG_OPEN_REPARSE_POINT` and rejects non-regular handles.
Credential helper and build-probe output are bounded, cancellation has a finite
wait policy, and helper errors never include credential input or stderr.

Rollback may restore the previous composition commit without changing repository
formats, credential schemas, remote API contracts, or command output. Docker
credential lookup would again discover the live process home and helpers, and
project/reference handlers would again bypass App composition; rollback
therefore re-opens CLI-024.
