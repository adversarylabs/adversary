# Network and OCI policy (CLI-008, CLI-009)

API, registry, token, redirect, and nested artifact requests use explicit
clients with bounded connect, TLS-handshake, response-header, idle, and total
operation deadlines. Safe GET/HEAD requests retry transient gateway failures
and rate limits at most twice with bounded backoff; mutating requests are not
retried because an interrupted monolithic upload is not provably resumable.
Responses are bounded and registry failures use a typed, sanitized error.

Authorization and cookies are removed on cross-origin redirects and HTTPS
downgrades are rejected. Bearer realms and upload locations reject userinfo,
fragments, insecure non-loopback HTTP, and cross-origin upload destinations.
Stored registry credentials are sent to token endpoints only when the realm is
same-origin with a matching service, or when configuration explicitly binds the
registry, token origin, and service. Docker Hub's
`registry-1.docker.io`/`auth.docker.io`/`registry.docker.io` binding is the sole
built-in exception. Other untrusted cross-origin realms receive anonymous token
requests and never stored Basic or bearer credentials.
API URLs require HTTPS except for loopback development. Plain registry HTTP is
an explicit `PlainHTTP` choice and is limited to loopback. Proxy environment
variables and the platform CA pool remain supported; custom enterprise CAs use
the platform trust configuration.

Mutable tags are read once and the verified digest pins all subsequent blob and
referrer requests. Manifest and server-provided digests, blob sizes/digests,
and referrer subjects are verified. Pull supports both the Referrers API and
the standard digest-derived fallback tag. Docker inline credentials,
per-registry helpers, and `credsStore` are read on demand without copying or
persisting helper secrets. Bearer challenges are case-insensitive and support
quoted commas and escapes; Docker reference normalization continues to use the
maintained Distribution reference parser.

SHA-256 is the default algorithm for artifacts produced by this CLI. OCI
manifests, descriptors, and references using registered SHA-384 or SHA-512
digests are also verified without rewriting their identity. The requested
manifest digest remains the repository record identity across pull, import,
repair, and materialization. Referrer fallback tags retain the existing literal
SHA-256 convention. SHA-384 also fits that convention; SHA-512 uses a
domain-separated SHA-256 projection of the canonical subject digest so the
deterministic fallback remains within the OCI 128-character tag limit.

Intentional compatibility limits: multi-platform indexes are rejected because
Adversary artifacts are runtime packages rather than platform container images,
and silently selecting a platform could change signed content. Referrers
pagination is not followed in this release. A response carrying `Link` is not
partially consumed: the client uses the deterministic digest-derived fallback
tag instead. Accepting arbitrary `Link` targets would expand the credential
boundary. Missing or unsupported Referrers endpoints and empty results use the
same fallback. Uploads remain monolithic because
restartable chunk state needs durable transaction semantics; the 256 MiB layer
limit bounds the current request. These choices fail closed and retain the
fallback-tag interoperability path.

Registries may return a canonical manifest digest using a different supported
algorithm than the retained local record. Push verifies that identity against
the uploaded manifest bytes, commits an equivalent unreferenced local record,
and registers the explicit remote reference only after the adversary-manifest
referrer succeeds. This prevents the expected missing-local-record failure
after successful publication while preserving the original generic reference.
The payload lease is closed before local mutation; referrer or reference-CAS
failure may leave an unreferenced verified record for normal GC, but never
retargets the remote reference locally.

Digest equivalence does not merge explicit remote identities. A remote
reference and its digest resolve the registry-returned record, while generic
name aliases deterministically resolve equivalent local identities. Equivalence
requires the same exact verified manifest bytes and attached adversary-manifest
digest; the persisted canonical alias is only a root preference and need not
remain live after GC. Ordinary same-name collisions remain errors.

Live GHCR, Docker Hub, Harbor, and CNCF Distribution conformance runs are
deferred because release CI has no approved external credentials or durable
service fixtures. The deterministic fake registry suite instead exercises
Distribution authentication, redirects, rate limiting, digest mutation,
referrers and fallback tags, and Docker credential helpers; the local-registry
pack/push/pull/run lifecycle is a required gate. Adding credentialed live jobs
requires a separate CI-secret and third-party availability decision so forks
cannot exfiltrate registry credentials and releases are not blocked by an
uncontrolled external outage.

Rollback is a revert of the client construction and registry policy changes.
No credential or repository schema changes are made, and helper credentials are
never persisted. Reverting also restores the timeout, redirect, realm, upload,
and mutable-tag risks described by CLI-008 and CLI-009.
After a SHA-384/512 record has been imported, however, reverting only the
algorithm-consistency change would make that otherwise valid record unreadable
or unverifiable. Remove or migrate such records to SHA-256 identities before
rollback; existing SHA-256 records and references require no migration.
