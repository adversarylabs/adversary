# Official catalog signatures

## Model

Host execution trusts an installed adversary when a valid **official signature**
verifies for its content digest using a public key **baked into that CLI
binary**.

| Concept | Mechanism |
|---------|-----------|
| What is signed | Immutable artifact digest (`sha256:…`) |
| Algorithm | Ed25519 |
| Where signature lives | OCI referrer on the catalog registry + local store copy after pull |
| Who verifies | `adversary` CLI only (no Notation/Cosign required for users) |
| Who signs | CI / local tooling with `ADVERSARY_OFFICIAL_SIGNING_SEED` |

Public keys are committed and compiled in. Private seeds are never committed.

## Dev vs prod keys (separate binaries)

| | **Dev / default `go build`** | **Release (`-tags release`)** |
|--|------------------------------|-------------------------------|
| Build | no special tags | `-tags release` (used by release scripts) |
| Public key in binary | `official-dev` only | `official-prod` only |
| Default key id | `official-dev` | `official-prod` |
| Private seed | local/dev secret only | prod CI secret only |
| Signs | local/staging catalog | `registry.adversarylabs.ai` |

A **released** CLI cannot verify packages signed with the **dev** key, because
that public key is not present in the binary. An env var alone would still ship
both keys; **build tags** keep them out of the wrong artifact.

```bash
# Everyday development (dev key only)
go build -o adversary .

# Release-shaped binary (prod key only) — matches Homebrew/release builds
go build -tags release -o adversary .
```

Sign with the matching key id:

```bash
# Dev catalog
export ADVERSARY_OFFICIAL_SIGNING_SEED  # dev seed from secrets manager
go run ./scripts/sign-official -digest "sha256:…" -key-id official-dev -out sig.json

# Prod catalog (release CI)
export ADVERSARY_OFFICIAL_SIGNING_SEED  # prod seed from CI secrets
go run ./scripts/sign-official -digest "sha256:…" -key-id official-prod -out sig.json
```

Files:

- `pkg/officialsig/keys_dev.go` — `//go:build !release` (dev public key)
- `pkg/officialsig/keys_release.go` — `//go:build release` (prod public key)
- `pkg/officialsig/keys_common.go` — key id constants only

## Envelope

Media type: `application/vnd.adversarylabs.official-signature.v1+json`

```json
{
  "specVersion": 1,
  "subjectDigest": "sha256:…",
  "keyID": "official-prod",
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
   referrer, verifies with this binary’s keyring, stores under
   `official-signatures/` in the local repository.
2. `adversary run` sets `OfficialSigned` when verification succeeds, then allows
   `HostExecutor`.

## Secrets

| Secret | Where |
|--------|--------|
| Prod seed | Prod CI / Doppler prd only |
| Dev seed | Doppler dev / 1Password for local catalog publishers |
| Public keys | Repo (safe to commit) |

**Never commit private seeds.** Tests use `GenerateKey` + `SetKeyringForTest`.

## Notation / TUF

- **Notation/Cosign**: optional later for CI interop; users still only need this CLI.
- **TUF**: later for key rotation without shipping a new binary for every key id.

## Migration

Until catalog packages are signed and re-pulled, remote host exec needs
`--allow-unsafe-host-execution` or a sandbox. Local source projects remain
trusted by path selection.
