# Artifact signatures

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

## Private team namespace signatures

`adversary push` automatically requests a server-side signature when the target
is the authenticated team's private namespace on the configured Adversary Labs
registry. The platform returns a digest signature and a root-endorsed public
team key; the publisher attaches both as OCI referrers. No private key leaves
the platform.

On pull, the CLI fetches the authenticated platform root, verifies the team
delegation, and then verifies that the signature matches the registry hostname,
exact `team/repository`, and immutable digest. The verified evidence is cached
for offline execution of that digest. A copy on GHCR does not match the signed
registry and remains untrusted.

This establishes authorized team provenance and artifact integrity. It does not
mean Adversary Labs reviewed the package's code.

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

Same secret **name** in every environment; **values** differ by env:

| Name | Doppler `dev` | Doppler `prd` | Depot (CLI release / sign) |
|------|---------------|---------------|----------------------------|
| `ADVERSARY_OFFICIAL_SIGNING_SEED` | dev seed (64 hex) | prod seed (64 hex) | **prod seed** (copy from Doppler prd) |
| `ADVERSARY_OFFICIAL_PUBLIC_KEY` | dev public hex | prod public hex | optional |
| `ADVERSARY_OFFICIAL_KEY_ID` | `official-dev` | `official-prod` | optional |

```bash
# Local (from a package repo with make sign-dev — Doppler wraps the seed):
adversary push … localhost:8787/adversarylabs/adversary:0.0.22
make sign-dev REF=localhost:8787/adversarylabs/adversary:0.0.22

# Or invoke CLI directly (flag or env for the seed):
adversary sign localhost:8787/adversarylabs/adversary:0.0.22 \
  --seed "$ADVERSARY_OFFICIAL_SIGNING_SEED" --key-id official-dev

# Prod CI: inject ADVERSARY_OFFICIAL_SIGNING_SEED, then after push:
adversary sign registry.adversarylabs.ai/adversarylabs/adversary:0.0.22 \
  --key-id official-prod
```

Seed resolution: `--seed` flag, else env `ADVERSARY_OFFICIAL_SIGNING_SEED`.

**Never commit private seeds.** Tests use `GenerateKey` + `SetKeyringForTest`.

**Depot secret to create:** `ADVERSARY_OFFICIAL_SIGNING_SEED` — paste the value from Doppler project `adversarylabs` config `prd`.

## Notation / TUF

- **Notation/Cosign**: optional later for CI interop; users still only need this CLI.
- **TUF**: later for key rotation without shipping a new binary for every key id.

## Migration

Until catalog packages are signed and re-pulled, remote host exec needs
`--allow-unsafe-host-execution` or a sandbox. Local source projects remain
trusted by path selection.
