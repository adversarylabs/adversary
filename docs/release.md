# Release policy and operations

Adversary uses immutable CalVer tags (`YYYY.M.D`, optionally `-beta.N`). GitHub
Releases are the authoritative changelog and artifact location. Never move a
published tag; publish a correcting release. Stable CLI/schema deprecations
remain supported for at least two minor releases or 60 days, whichever is
longer, unless a documented security issue requires earlier removal.

## Supply-chain contract

The Depot workflow has one trigger: a CalVer tag push. It pins every
third-party action to a full commit SHA. Its
read-only build job runs tests/vet, produces byte-reproducible archives, an SPDX
2.3 dependency graph validated by the pinned official SPDX Go toolkit, and
checksums. A second secret-free job receives only short-lived GitHub
OIDC/attestation permissions. A fresh third job in the protected `release`
environment rechecks the tag, clean tracked state, exact untracked bundle, and
all bundle digests before its final step alone receives `contents: write` and
the tap token. Tag-scoped concurrency prevents two publishers for one release.

Archives have stable ordering, uid/gid 0, normalized modes and mtimes, and gzip
headers without timestamps. Each contains the binary, README, LICENSE status,
release guide, and trust model. Every cross-built binary is inspected for its
stamped version metadata; the native Linux binary executes `adversary version`.
`release-manifest.json` binds the version and peeled tag commit to each artifact
digest; the checksum set covers that manifest. GitHub's keyless
build-provenance attestation covers archives, formula, SBOM, checksums, and
manifest. Verify:

```sh
sha256sum --check checksums.txt
gh attestation verify adversary_2026.7.11_linux_amd64.tar.gz \
  --repo adversarylabs/adversary
```

Standalone keyless signatures are not emitted. GitHub attestations already bind
the artifact digest to this repository/workflow through OIDC without a project
key-distribution problem. Adding a second signing system before publishing a
pinned verifier and trust-root policy would create ambiguous trust semantics.
This is the CLI-022 signing decision; revisit if distribution outside GitHub
requires portable signatures. Digests and attestations do not make adversary
code safe to execute; see the trust model.

## Create a release

1. Ensure `main` CI passes and release notes cover additions, fixes, security,
   deprecations, migrations, rollback, and known limitations. Run
   `go run golang.org/x/vuln/cmd/govulncheck@v1.6.0 ./...`; record the tool
   version and disposition of each reachable finding in the release.
2. Create and push an annotated CalVer tag from reviewed `main`:

   ```sh
   git tag -a 2026.7.11 -m 'Release 2026.7.11'
   git push origin 2026.7.11
   ```

3. Approve the protected `release` environment after checking the tag commit.
   Repository administrators must create that environment, restrict deployment
   to release tags, and configure required reviewers; workflow YAML cannot
   enforce those external repository settings.
4. Verify checksums, attestation, archive contents, binary `version`, and the
   rendered Homebrew formula. Confirm the tap commit references the same URLs
   and hashes.

Prereleases use `2026.7.11-beta.1`, update `adversary-beta.rb`, and install
`adversary-beta` so stable and beta can coexist.

## Credentials and least privilege

`HOMEBREW_TAP_TOKEN` is a Depot secret available only to the publish job. Use a
fine-grained token scoped solely to `adversarylabs/homebrew-tap` contents
read/write. The script copies the exact checksummed formula from the release
bundle into the tap and verifies its digest; it never rerenders after
attestation. It uses `GIT_ASKPASS`, so secrets never appear in clone URLs, and
an EXIT trap removes temporary credentials and checkouts. Rotate the token
by replacing the secret, testing the next release, then revoking the old token.
The runtime GitHub token is repository-scoped and not used for the tap.

## Local verification

GNU tar is required for deterministic archives (`nix develop` supplies it).
On macOS install it as `gtar`; the script feature-detects GNU tar and fails
before building rather than silently using incompatible BSD tar:

```sh
BUILD_ONLY=1 scripts/publish-homebrew.sh 2026.7.11
scripts/test-release-contract.sh
```

`DIST_DIR` is restricted to top-level `dist` or `.release-dist/<safe-name>`;
real-path and symlink checks run before deletion. Set `SKIP_PUBLISH=1` for the
same local build plus rendered formula. `PUBLISH_ONLY=1` is reserved for the
workflow and publishes an already transferred, checksummed bundle.

## Recovery and rollback

The workflow never force-pushes. Failed artifact upload can be retried; assets
are replaced only for the same immutable tag. A concurrent tap change must be
reviewed and reconciled, not overwritten. If artifacts are incorrect, mark the
release affected, publish a new tag, and update the formula to the new hashes.
Do not move the tag or silently replace trusted bytes. If only the formula is
bad, revert its tap commit and publish a corrected repository release.
