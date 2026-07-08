# Release Publishing

Adversary releases are published by a Depot workflow in `.depot/workflows/release.yml`.
The workflow uses the Depot secret `HOMEBREW_TAP_TOKEN`; it does not use GitHub
Actions secrets.

## Required Depot Secret

Create a Depot secret named `HOMEBREW_TAP_TOKEN`.

The token must be able to:

- read and write releases in `github.com/adversarylabs/adversary`
- clone, commit to, and push `github.com/adversarylabs/homebrew`

For a fine-grained GitHub PAT, grant repository access to both repositories. The
source repository needs contents read/write for release assets. The tap
repository needs contents read/write for `Formula/adversary.rb`.

## Creating a Release

Use a CalVer tag:

```bash
git tag 2026.7.8
git push origin 2026.7.8
```

The release workflow accepts CalVer tags like `2026.7.8`. The tag push starts
the Depot workflow. If the GitHub Release does not already exist, the workflow
creates it. If a GitHub Release for the tag is published first, the
release-published event starts the same workflow and uploads the artifacts to
that existing release.

Prerelease tags use a suffix:

```bash
git tag 2026.7.8-beta.1
git push origin 2026.7.8-beta.1
```

Stable releases update `Formula/adversary.rb` and install the `adversary`
command. Prereleases update `Formula/adversary-beta.rb` and install the command
as `adversary-beta`, so users can keep stable and beta installations side by
side.

Do not manually edit the Homebrew tap for normal releases.

## What the Workflow Does

The workflow:

1. checks out the source repository
2. installs the GitHub CLI
3. runs `go test ./...`
4. runs `scripts/publish-homebrew.sh`

The publishing script builds these archives:

```text
adversary_${VERSION}_darwin_amd64.tar.gz
adversary_${VERSION}_darwin_arm64.tar.gz
adversary_${VERSION}_linux_amd64.tar.gz
adversary_${VERSION}_linux_arm64.tar.gz
```

It writes `dist/checksums.txt`, verifies that every expected archive has a
SHA256 line, uploads the archives and checksum file to the GitHub Release, then
renders `Formula/adversary.rb` from `Formula/adversary.rb.tmpl`.

To verify the build, checksum, and template-rendering path locally without
publishing:

```bash
SKIP_PUBLISH=1 scripts/publish-homebrew.sh 2026.7.8
```

The rendered formula uses Homebrew platform blocks for macOS Intel, macOS Apple
Silicon, Linux x86_64, and Linux ARM64. It installs the archive's `adversary`
binary with:

```ruby
bin.install "adversary"
```

Finally, the script clones `github.com/adversarylabs/homebrew`, commits the
updated formula, and pushes it back to the tap. Any upload, missing checksum,
commit, or push failure fails the workflow.

## Rotating the PAT

1. Create a new fine-grained GitHub PAT with access to:
   - `adversarylabs/adversary`
   - `adversarylabs/homebrew`
2. Grant contents read/write permissions for both repositories.
3. Replace the Depot secret `HOMEBREW_TAP_TOKEN` with the new token.
4. Re-run the latest failed release workflow, or push the next release tag.
5. Revoke the old PAT after the new token has successfully published a release.

## Recovering From a Failed Publish

The script is safe to re-run for the same tag.

- If archive upload failed, re-run the Depot workflow. Existing release assets
  are overwritten with `gh release upload --clobber`.
- If the tap push failed, re-run the workflow. The script regenerates the same
  formula and pushes it again.
- If the tap repository changed concurrently, pull or inspect the tap, resolve
  the conflict there if needed, then re-run the release workflow.
- If a bad formula was pushed, fix the release inputs or template in this
  repository, then re-run the workflow for the same tag.

After a successful release, users can install with:

```bash
brew tap adversarylabs/homebrew
brew install adversary
```

or:

```bash
brew install adversarylabs/homebrew/adversary
```
