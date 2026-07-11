# Application composition boundary (CLI-024)

CLI-024 is complete. Every production command is constructed from an explicit
`application.App`. Authentication persistence, Adversary Labs API operations,
and OCI registry creation are strongly typed ports/factories; login, logout,
search, whoami, push, pull, and default namespace selection do not construct or
discover dependencies inside handlers.

`cmd/app.go` is the sole production process edge. It reads environment-backed
flag defaults once, validates and binds the config/API/registry factories,
selects the HTTP client and credential stores, and owns argv, stdio, OS signals,
browser/runtime process launch, temporary paths, and terminal detection. These
operations are intentionally process-specific and are not application-domain
ports. Tests construct an explicit App; the convenience root constructor exists
in a `_test.go` file only.

Registry authorization decisions use `oci.RegistryError` status and distribution
error codes. Handler behavior no longer depends on matching human-readable error
strings. Factory binding identities fail closed when auth, API, and registry
dependencies belong to different configurations.

Rollback may restore the previous composition commit without changing repository
formats, credential schemas, remote API contracts, or command output. It would
restore handler-local process discovery and therefore re-open CLI-024.
