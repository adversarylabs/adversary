# Application composition cleanup status (CLI-024)

This cleanup migrates artifact resolution and repository access for run,
inspect, pack, list, push, and pull to the single App-bound resolver. Login now
uses the App's stdin, TTY, browser, clock, and timer ports. These migrated paths
no longer construct repository or interaction dependencies inside handlers.

The production composition edge in `cmd/app.go` still constructs the concrete
browser, runtime, environment, clock, stdio, and resolver adapters. Separately,
some production handlers in `cmd/root.go` still resolve API defaults and create
authentication or OCI clients from process-global configuration. Those are
remaining cleanup work, not composition-edge-only access.

CLI-024 is not yet complete. Authentication and registry helpers still create
the typed Adversary Labs config store/API client and registry client directly;
the current generic string `Config` and HTTP ports cannot represent scoped auth
CAS, registry token authorities, or client construction safely. A follow-up
must add typed AuthStore/API/Registry factories, migrate login/logout/search/
whoami and namespace/debug lookup, then remove the legacy `NewRootCommand`
test compatibility constructor. Until then production uses the App constructor,
while legacy tests may explicitly exercise the compatibility path.

Remaining direct/default inventory in `cmd/root.go` is explicit:

- legacy-only `DefaultResolver`, `os.Stdin`, system clock, browser, and TTY
  fallback behind `NewRootCommand`;
- `ResolveAPIURL` environment-derived flag defaults;
- `DefaultConfigStore` in login/logout/search/whoami and push authentication;
- direct Adversary Labs API client and OCI registry/credential factories;
- `ADVERSARY_OCI_DEBUG`, `ADVERSARY_REGISTRY_NAMESPACE`, and process stderr
  used by registry construction/push naming.

Production `Execute` owns stdio, environment, HTTP default transport, system
clock, browser process launch, TTY file descriptor access, runtime process
execution, and initial resolver construction only in `cmd/app.go`. These are
composition-edge adapters, not handler lookups. Signals and argv remain process
edge responsibilities outside the App graph.

Rollback restores handler-local resolver and input/browser/clock construction.
No repository, credential, or command-output schema changes are introduced.
