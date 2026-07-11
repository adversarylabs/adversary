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
