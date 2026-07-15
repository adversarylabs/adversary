# Build and Git change contract

This document records the repository decisions for audit findings CLI-007 and
CLI-015.

## Explicit, isolated builds (CLI-007)

Packing is the explicit release-build operation. `pack.Create` only builds when
its caller requests `Build`; the injected production operation backed by
`BuildProjectWithEnvironment` never guesses from the presence of the word
`build`. It parses `package.json` and runs only a non-empty string at
`scripts.build`. Malformed and unreadable package files are errors.

Builder selection and cancellation are validated before project filesystem
access. Local builds require Node 22-compatible npm and an existing
`node_modules`; they run from a descriptor-relative, no-follow snapshot in a
sibling staging tree, including an isolated copy of dependencies. The snapshot
preserves only relative symlinks below `node_modules` whose complete target chain
resolves inside the staged project; it rejects absolute, escaping, dangling,
cyclic, raced, source-tree, and special-file links. Published output and artifact
inputs continue to reject every symlink. Local builds reject Node versions other
than the supported v22.x execution major. Docker
builds use a similarly isolated source snapshot and do not require host
`node_modules`.
Snapshots are limited to 250,000 entries and 4 GiB, with retained dependency
symlink path/target metadata separately capped at 64 MiB, and are copied with
context checks. They prevent ordinary relative build output and dependency
mutation from reaching the source tree; the invoked npm script remains a
cooperative host process, not a security sandbox against a script that
deliberately searches for and opens the original project by another path.
Docker release builds require `package-lock.json`, run `npm ci`, and use the multi-platform image
`node:22.14.0-alpine3.21` pinned by OCI index digest. This aligns the builder
major with the supported Node 22 runtime while retaining platform selection.
On 2026-07-11 an official Docker registry manifest query independently resolved
the tag to index digest
`sha256:9bef0ef1e268f60627da9ba7d7605e8831d5b56ad07487d24d1aa386336d1944`,
with Linux amd64 manifest
`sha256:01393fe5a51489b63da0ab51aa8e0a7ff9990132917cf20cfc3d46f5e36c0e48`
and Linux arm64/v8 manifest
`sha256:4a78eedb5c49d58c0c0b610ebc48f4ac397358604daac64e8dec1baecde2a31b`.

Each project has one lock in the private per-user
`UserCacheDir/adversary/build-state` root (or an explicit hermetic override).
Production composition resolves and canonicalizes that root once while
constructing `application.App`, then forces the captured value through both
`pack --build` and `run --build`. Later HOME or XDG cache mutations cannot move
the lock/journal boundary. Direct library callers retain the explicit
`BuildOptions.BuildStateDir` override and otherwise resolve their default when
they invoke the builder.
The root is a non-symlink directory restricted to mode 0700 and checked for
current-user ownership where the platform exposes Unix ownership. A SHA-256 of
the canonical existing project path keys both its lock and private state
directory. No lock or journal metadata is created inside the repository, and a
missing, symlink, non-directory, or no-build project is rejected or returned
before coordination metadata is created. Lock order is: project build lock,
recovery, source snapshot, builder process, output snapshot, publication
journal/renames, recovery or cleanup, unlock. No other lock may be acquired
while holding it. This serializes local processes across staging, building,
publication, and rollback.

Both builders produce a staged `dist`. The old `dist` is renamed aside only
after the build succeeds and output is validated. The external fsynced journal
records exact cryptographically random, exclusively created stage and backup
names plus the project correlation hash; recovery never interprets repository
files or wildcard prefixes. Injected failures roll back immediately and a later
build checks for trusted preexisting state, locks, and recovers before reading
`package.json`, even when that file is then missing, malformed, or has no build
script. Clean no-build projects do not create state. Project-directory syncs
durably order each rename phase. External journal-directory syncs retry three
times; success requires both a durable project rename and at least one successful
final external-state sync. Exhausted retries rewrite rollback intent, restore
and sync the prior `dist`, and return `PublicationDurabilityError`; visibility
is never mistaken for durability by rereading the journal. Failed and canceled builds cannot modify
the source project or its existing output. Reusing stale output is never
implicit: library callers must set `BuildOptions.AllowStaleDist`, which emits a
diagnostic. Release packing does not enable it.

Rollback recovery is idempotent. In `backup-moved`, an exact validated backup
is authoritative (and replaces uncommitted visible output if both exist). If
that backup is absent but a valid prior `dist` exists, recovery treats rollback
as already completed and preserves it. If both are absent for a project that
previously had output, recovery fails without deleting any other path.

Portable filesystems do not provide a universal atomic exchange for non-empty
directories. Publication therefore has a brief cooperative-reader window
between the two renames in which `dist` can be absent, and an abrupt process
exit can leave the hidden backup until recovery under the next build lock.
Writers are serialized and journaled. There is not yet a public reader-lock API,
so readers cannot presently guarantee uninterrupted visibility; the repository
chooses this portable transaction and explicit limitation rather than
platform-specific exchange APIs.

Compatibility decision: local `adversary run` no longer builds implicitly. It
uses existing `dist` output by default; `--build` explicitly invokes the
transactional builder and `--build-timeout` bounds it. The deprecated
`--no-build` spelling remains a no-op for script compatibility. The complete
command and rollback policy is recorded in
`process-lifecycle-and-exit-contract.md`.

Rollback: callers can stop requesting `Build` and supply already-built immutable
output. Reverting the isolated builder does not change artifact or manifest
formats. The pinned image may be advanced by reviewing both its Node version and
index digest together.

## CI toolchain and build matrix (CLI-021)

The `go` directive in `go.mod` is the single source of truth for the supported
release Go toolchain. Every Go CI job and the release build use the
checksum-pinned `actions/setup-go` action with `go-version-file: go.mod`; no
workflow carries a competing Go version literal. `scripts/verify-ci-contract.go`
enforces that relationship. A toolchain upgrade is one reviewed `go.mod`
change accompanied by module verification and the complete CI matrix, rather
than independent workflow edits that can drift.

Node 22 is the supported generated-project and local-build major. Native tests
install it on Ubuntu 24.04, macOS 14, and Windows 2022; the Ubuntu race,
coverage, and freshly generated TypeScript template jobs also install Node 22.
Go native tests run on those same three operating systems. Cross-builds cover
Linux amd64/arm64, Darwin amd64/arm64, and Windows amd64. Formatting, module
verification, vet, race, coverage, template, CLI smoke, security tooling, and
release-contract jobs all feed the single required `ci / test` aggregate.

Required CI intentionally does not depend on a privileged Docker daemon or a
Docker Hub pull. Docker-build behavior is covered hermetically: tests execute a
fake Docker command through the real argument/output boundary, verify the exact
generated Dockerfile uses the reviewed digest and `npm ci`, and exercise staged
output publication, cancellation, locking, recovery, and rollback. This keeps
fork CI credential-free and avoids making releases depend on daemon privilege,
Hub rate limits, or an external outage.

An opt-in live Docker fixture becomes appropriate when the repository has an
isolated, maintained BuildKit/Docker runner, bounded cleanup and resource
quotas, a reviewed base-image mirror or pull policy, and a non-secret fork
policy. The fixture must build a representative locked TypeScript project with
the reviewed image on each supported Linux architecture, validate the produced
`dist`, prove the source tree is unchanged, and report separately until its
availability is reliable enough for required CI. This is an explicit coverage
boundary, not an assertion that fake execution proves daemon behavior.

Rollback: removing the verifier or matrix decision does not migrate code or
artifacts, but permits workflow/toolchain drift and reopens CLI-021. Replacing
the hermetic decision with required live Docker coverage requires the runner,
availability, credential, and cleanup controls above before it can be a safe
required gate.

## Lossless Git changes (CLI-015)

`CommandGitDiffer.Changes` defines comparison as Git `base...head`: changes
between the merge base of the two commits and `head`. It invokes
`git diff --name-status -z --find-renames --find-copies --find-copies-harder merge-base head --`, so paths
containing spaces, leading/trailing whitespace, tabs, or newlines remain exact
and revisions cannot be interpreted as pathspecs.

Changes explicitly model added, modified, deleted, renamed, copied, and
type-changed entries. Rename/copy records retain both old and new paths. The
legacy `ChangedFiles` interface projects this model to head-side paths so the
existing protocol remains compatible. For deletions its projected `Path` is
necessarily the base-side path, which no longer exists at `head`; consumers
that open paths or need rename/copy origin and similarity scores must call
`Changes` and branch on status.

Refs beginning with `-` and NUL-containing refs are rejected. The differ checks
for a work tree, verifies both commits, and verifies their merge base. Errors
distinguish non-repositories, unavailable objects, and missing shallow history
and tell CI users to fetch the revisions and history. Trigger globs are compiled
once per match operation without `MustCompile`, and filenames are never trimmed.
Manifest validation already rejects empty and non-normalized trigger strings;
the glob translator quotes regexp metacharacters, so every accepted glob has a
safe compiled representation.

Rollback: the compatibility `ChangedFiles` method can remain while typed-change
consumers are rolled back independently. Reverting this implementation restores
the old diff behavior but loses unusual filenames and change status information;
there is no stored-data migration.
