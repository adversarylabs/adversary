# Official catalog signatures

## Model

Host execution trusts an installed adversary when a valid **official signature**
verifies for its content digest using a public key embedded in the CLI.

| Concept | Mechanism |
|---------|-----------|
| What is signed | Immutable artifact digest (`sha256:…`) |
| Algorithm | Ed25519 |
| Where signature lives | OCI referrer on the catalog registry + local store copy after pull |
| Who verifies | `adversary` CLI only (no Notation/Cosign required for users) |
| Who signs | Release CI with `ADVERSARY_OFFICIAL_SIGNING_SEED` |

Registry hostname and path domain allowlists are **not** the trust decision.
Delivery is separate from endorsement.

## Envelope

Media type: `application/vnd.adversarylabs.official-signature.v1+json`

```json
{
  "specVersion": 1,
  "subjectDigest": "sha256:…",
  "keyID": "official-v1",
  "signedAt": "2026-08-01T12:00:00Z",
  "signature": "<base64 ed25519 signature>"
}
```

Signed message (exact bytes):

```text
adversarylabs-official-sig-v1
<subjectDigest>
<keyID>
<signedAt>
```

## CLI verify path

1. `adversary pull` resolves digest, installs content, fetches the signature
   referrer, verifies with the embedded keyring, stores under
   `official-signatures/` in the local repository.
2. `adversary run` sets `OfficialSigned` when
   `HasVerifiedOfficialSignature(digest)` is true, then allows `HostExecutor`.

## CI sign path

```bash
export ADVERSARY_OFFICIAL_SIGNING_SEED=<hex seed matching official-v1 public key>
go run ./scripts/sign-official -digest "sha256:…" -out /tmp/sig.json
# Attach referrer to the published artifact (registry push of
# OfficialSignatureMediaType subject = image digest).
```

Private seeds are never shipped in the CLI. Rotate by adding `official-v2` to
the keyring and re-signing catalog packages.

## Notation / TUF

- **Notation/Cosign**: optional later for CI interop; verify stays in-process via
  this package so users do not install extra tools.
- **TUF**: later for key rotation and catalog metadata; not required for MVP.

## Migration

Until catalog packages are signed and re-pulled, host execution of remote
packages requires `--allow-unsafe-host-execution` or a sandbox. Local source
projects remain trusted by path selection.
