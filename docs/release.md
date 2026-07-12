# Release policy and operations

Adversary uses immutable CalVer tags (`YYYY.M.D`, optionally `-beta.N`). GitHub
Releases are the authoritative changelog and artifact location. Never move a
published tag; publish a correcting release. Stable CLI/schema deprecations
remain supported for at least two minor releases or 60 days, whichever is
longer, unless a documented security issue requires earlier removal.

## Supply-chain contract

The Depot workflow has one trigger: a CalVer tag push. It pins every
third-party action to a full commit SHA. Its read-only build job runs tests,
vet, and the release contract, then produces byte-reproducible archives, an SPDX
2.3 dependency graph validated by the pinned official SPDX Go toolkit, and
checksums. A second secret-free job receives only short-lived GitHub
OIDC/attestation permissions. Two fresh, channel-specific jobs in the protected
`release` environment then recheck the tag, clean tracked state, exact
untracked bundle, and all bundle digests. The GitHub job publishes the attested
assets and cannot receive the tap token. Only after that succeeds can the
Homebrew job run; it has read-only repository permissions and receives the
fine-grained tap token only in its final step. Tag-scoped concurrency prevents
two publishers for one release.

Archives have stable ordering, uid/gid 0, normalized modes and mtimes, and gzip
headers without timestamps. Each contains the binary, README, LICENSE status,
release guide, and trust model. Every cross-built binary is inspected for its
stamped version metadata; the native Linux binary executes `adversary version`.
`release-manifest.json` binds the version and peeled tag commit to each artifact
digest; the checksum set covers that manifest. GitHub's keyless
build-provenance attestation covers archives, formula, SBOM, checksums, and
manifest.

Release builds use `-buildvcs=false` because the workflow has already verified
the immutable tag and explicitly stamps that exact commit, version, and build
date. The contract rejects missing explicit stamps and automatic `vcs.*` build
settings. This keeps binary bytes independent of incidental checkout/cache
state without weakening the source identity recorded in the artifact.

Verify:

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

GitHub Actions permissions are job-scoped; the platform has no step-scoped
`GITHUB_TOKEN` permission setting. Consequently, the protected
`publish-github` job has `contents: write` for its full lifetime. This is an
explicit CLI-022 platform decision, not a claim that only its last step is
privileged. The job is the minimum isolated unit that can independently check
out and verify the immutable tag, download and verify the exact attested bundle,
and publish those bytes. Checkout sets `persist-credentials: false`, and this
job has no tap credential. Moving verification to a previous workspace would
weaken the publication boundary; finer scope would require an external
credential broker rather than a GitHub workflow permission.

The following `publish-homebrew` job has only `contents: read` for this
repository. `HOMEBREW_TAP_TOKEN` is exposed only to its final step and must be a
fine-grained token scoped solely to `adversarylabs/homebrew-tap` contents
read/write. The script copies the exact checksummed formula from the release
bundle into the tap and verifies its digest; it never rerenders after
attestation. It uses `GIT_ASKPASS`, so secrets never appear in clone URLs, and
an EXIT trap removes temporary credentials and checkouts. Rotate the token by
replacing the secret, testing the next release, then revoking the old token.
The repository-scoped GitHub publication token is rejected by the Homebrew
mode, and the tap token is rejected by the GitHub mode.

## Local verification

GNU tar is required for deterministic archives (`nix develop` supplies it).
On macOS install it as `gtar`; the script feature-detects GNU tar and fails
before building rather than silently using incompatible BSD tar:

```sh
RELEASE_MODE=build scripts/publish-homebrew.sh 2026.7.11
RELEASE_MODE=verify scripts/publish-homebrew.sh 2026.7.11
scripts/test-release-contract.sh
```

`DIST_DIR` is restricted to top-level `dist` or `.release-dist/<safe-name>`;
real-path and symlink checks run before deletion. Publication requires one
explicit, mutually exclusive mode: `publish-github` accepts only
`GITHUB_TOKEN`, while `publish-homebrew` accepts only `HOMEBREW_TAP_TOKEN`.
The old boolean mode variables are rejected so conflicting channel authority
cannot be selected accidentally.

## Recovery and rollback

The workflow never force-pushes. A failed GitHub publication can be retried
without granting tap authority; Homebrew publication cannot start until the
GitHub channel succeeds. A new release is first created as an unpublished draft
without assets. Missing assets may be added only to that draft; the complete
remote bundle is then re-listed, downloaded, and compared byte-for-byte before
promotion as the final operation. The pre-promotion snapshot includes each
asset's stable ID, name, size, and server digest when available, so a concurrent
same-name replacement also aborts. Draft and prerelease state are revalidated
at that boundary. Existing drafts can resume this transaction.
Published releases are immutable: they must already contain the exact bundle,
and missing, unexpected, or mismatched assets fail closed without mutation.
A concurrent tap change must be reviewed and reconciled, not overwritten. If
artifacts are incorrect, mark the release affected, publish a new tag, and
update the formula to the new hashes. Do not move the tag or silently replace
trusted bytes. If only the formula is bad, revert its tap commit and rerun only
the Homebrew channel for the same verified bundle, or publish a correcting
release when artifact metadata also changes.
