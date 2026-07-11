# Application and lifecycle command migration (CLI-024, CLI-012)

The process entry point now constructs one `application.App` dependency graph
and passes it into command construction. The lifecycle command family consumes
its injected streams and repository; existing command constructors remain as a
compatibility shim for tests while the remaining command families migrate in a
follow-up composition cleanup.

`adversary store check [--json]` reports repository integrity and fails closed
when corrupt. `store gc` is a dry run by default; destructive application
requires both `--apply` and `--yes`. `store ref-delete` requires the expected
digest and `--yes`, preserving CAS semantics. `store migration-status [--json]`
reports the stable checkpoint/full-count state. JSON modes write only one JSON
document to stdout. Repair is intentionally not exposed yet: accepting
arbitrary local repair bytes needs a source-authentication and size-policy UI;
the bounded verified repository API remains available for the later command.

Repository-backed runs reacquire `LeaseMaterialized` after resolution and hold
it through the complete runner operation. No repository method is called while
the lease is held; runtime execution is the pure consumer. Consequently GC
blocks while an artifact is active. GC commands are registered only on the
App-backed process composition where lease-enabled runner wiring is active.
The App resolver is constructed from the exact same repository value and is
injected into run and inspect. Resolution returns the canonical record; the
runner leases that digest from the same repository and supplies only the lease
path to runtime. App-backed paths never consult `DefaultResolver`, `HOME`, or a
second repository after composition.
App-backed construction validates this binding before any handler runs. A
resolver without the internal bound-resolver capability, or a resolver whose
repository identity differs from the injected repository, returns a typed
`invalid-dependency` error. Only the legacy compatibility constructor permits
Runner's nil-resolver fallback.

Rollback reverts the App-backed constructor and store command registration.
Repository formats and lifecycle journals are unchanged. Large-scale removal
of legacy command-local environment, clock, browser, HTTP, and configuration
lookups remains the next CLI-024 cleanup PR; this migration does not claim that
all legacy handlers are dependency-pure.
