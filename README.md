# Adversary

Adversary is a CLI for packaging, distributing, and running source-code review
adversaries. Host execution runs code with your user account's authority; read
the [trust model](docs/trust-model.md) before running code you did not write.

## Install

Supported release binaries target macOS and Linux on amd64 and arm64. Windows
is source-build and CI supported but does not yet have a packaged release.

```sh
brew install adversarylabs/tap/adversary
# Or build the current checkout with stamped metadata:
make build VERSION=dev
```

Release archives, checksums, SPDX SBOMs, and GitHub build attestations are on
the corresponding GitHub Release. Verify checksums before installation and
verify the attestation with GitHub CLI as described in [the release guide](docs/release.md).
Because the project has not selected a license, source publication grants no
reuse rights; see [the license decision](docs/license-decision.md).

`go install github.com/adversarylabs/adversary@<commit-or-tag>` is supported for
source installation, but the Go tool does not apply release `-ldflags`, so the
binary reports version `dev`; its Go VCS build information remains inspectable
with `go version -m`. Prefer release archives when a stamped version is needed.

## Quick start

Node.js 22 is required for the generated TypeScript adversary. Node is managed
by the user, not downloaded by this CLI.

```sh
adversary init my-adversary --sdk typescript
cd my-adversary && npm install && npm test && npm run build
adversary run . --repo /path/to/repository
```

Only TypeScript project generation is currently supported. Useful commands:

```sh
adversary run . --repo . --format json
adversary inspect . --repo .
adversary pack . --name ghcr.io/acme/reviewer
adversary push ghcr.io/acme/reviewer:0.1.0
adversary pull ghcr.io/acme/reviewer:0.1.0
adversary list --format json
adversary completion bash
```

Run `adversary help <command>` for the canonical command and flag reference.

## Safety and trust

Local Node and process adversaries are not sandboxed. Installed or pulled code
requires `--allow-unsafe-host-execution`; that acknowledgment is not isolation.
The child can access the repository, credentials, network, processes, and any
other resources available to your account. Restrictions the host runner cannot
enforce fail closed. OCI digests provide integrity and identity, not publisher
authenticity. Registry credentials and trusted CA/proxy configuration are part
of the user's environment trust boundary. See [artifact limits](docs/artifact-trust-and-limits.md)
and [network policy](docs/network-oci-policy.md).

## Configuration and precedence

Command flags take precedence over environment variables, which take
precedence over the selected profile in the OS config file, followed by built-in
defaults. Manifest runtime and permission declarations apply to the adversary
and are not general CLI configuration.

| Concern | Flag | Environment | Default/config |
| --- | --- | --- | --- |
| SaaS endpoint | `--api-url` | `ADVERSARY_API_URL` | `https://adversarylabs.ai/api` |
| profile | `--profile` | — | `default` profile in OS config dir |
| registry | explicit OCI reference | `ADVERSARY_REGISTRY_HOST`, `ADVERSARY_REGISTRY_NAMESPACE` | Adversary Labs registry |
| artifact data | — | `ADVERSARY_DATA_DIR` | OS data directory |
| Node runtime | manifest requirement | `ADVERSARY_NODE_PATH`, then `PATH` | user runtime locations |
| OCI diagnostics | `--verbose` | `ADVERSARY_OCI_DEBUG` (internal transport toggle) | disabled; secrets redacted |
| review suppression | command behavior | `ADVERSARY_INCLUDE_SUPPRESSED` (injected into adversary) | suppressed details omitted |
| adversary protocol paths | — | `ADVERSARY_INPUT`, `ADVERSARY_OUTPUT`, `ADVERSARY_REPO` (injected) | per-run temporary paths |
| adversary diagnostics | `--verbose` | `ADVERSARY_VERBOSE` (injected) | disabled |
| password login | `--password-stdin` | `ADVERSARY_PASSWORD` only in shell examples | secure prompt; variable is not read directly by the CLI |

`ADVERSARY_BUILD_HELPER` is a test seam, not a supported user setting. Standard
`HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`, and platform CA trust are
honored by Go networking. Registry credentials come from Docker credential
configuration or the selected Adversary profile as documented in
[network policy](docs/network-oci-policy.md). Never put passwords in URLs or
command history.

## Output and exits

Text is the default. `--format json` emits exactly one versioned JSON document
to stdout; progress, diagnostics, and deprecation notices go to stderr. Exit 0
means success, 1 means the review reported any finding, 2 means invalid
usage or configuration, 3 means adversary/protocol/execution failure, 4 means
network or authentication failure, and 130 means interruption. Child exit and
signal behavior are defined in the
[process contract](docs/process-lifecycle-and-exit-contract.md). Stable DTO and
deprecation rules are in the [output contract](docs/cli-output-contract.md).

## Artifact storage and resolution

Local paths resolve directly. Named and digest references resolve through the
unified content-addressed repository; pulls verify descriptor sizes and
digests before atomic publication. Default data locations are
`~/Library/Application Support/Adversary` on macOS,
`$XDG_DATA_HOME/adversary` (or `~/.local/share/adversary`) on Linux, and
`%LOCALAPPDATA%\Adversary` on Windows. Directories and mutable indexes are
owner-only; published content is read-only. `ADVERSARY_DATA_DIR` overrides the
data root. See [resolver migration](docs/resolver-migration.md).

## Support and compatibility

The tested OS/runtime matrix is in [platform support](docs/platform-runtime-support.md).
Public JSON schemas and manifest fields follow additive compatibility within a
major schema version. A deprecated CLI flag remains for at least two minor or
60 days (whichever is longer) and warns on stderr before removal. Security
exceptions can shorten that window and are called out in the changelog.
Release, rollback, and provenance policy is in [docs/release.md](docs/release.md).

Security reports: [SECURITY.md](SECURITY.md). Contributions: [CONTRIBUTING.md](CONTRIBUTING.md).
