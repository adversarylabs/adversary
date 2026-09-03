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

Release archives, checksums, and SPDX SBOMs are on the corresponding GitHub
Release. Verify checksums before installation and review the current provenance
limitation in [the release guide](docs/release.md).
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
cd my-adversary && npm ci && npm test && npm run build
adversary run . --path /path/to/repository
```

Only TypeScript project generation is currently supported. Useful commands:

```sh
adversary run . --path . --format json
adversary run --dry-run --explain
adversary run --all-files
adversary inspect . --path .
adversary pack . --name ghcr.io/acme/reviewer
adversary push ghcr.io/acme/reviewer:0.1.0
adversary pull ghcr.io/acme/reviewer:0.1.0
adversary list --format json
adversary completion bash
```

Run `adversary help <command>` for the canonical command and flag reference.
See [automatic selection](docs/automatic-detection.md) for change resolution,
manifest detection declarations, selection policy, and CI behavior.
See [composition](docs/composition.md) for `adversary.yaml` `uses` (language packs
and persona entrypoints that expand to specialist adversaries).
See [comment voice](docs/voice.md) for `agent/voice.md`, example banks, and GitHub
rewrite with `--github-review`.

## Automatic review scope

`adversary run` chooses an obvious review scope when no scope flags are given.
The precedence is:

1. explicit `--base`, `--head`, or `--all-files`;
2. pull-request base/head references captured from CI;
3. staged, unstaged, and untracked worktree changes;
4. a clean feature branch compared with the detected default branch using its
   merge base; then
5. the entire target for a clean default branch, a non-Git target, or when the
   default branch cannot be determined.

`--base main` implies `--head HEAD`. `--head feature` detects the default base.
Use `--path` to choose the repository and `--all-files` to bypass inference.
The selected scope is printed to stderr before execution.
Default-branch detection checks `git config adversary.defaultBase`, the tracked
remote's `HEAD`, `origin/HEAD`, and then conventional `main`, `master`, or
`trunk` refs. Set `git config adversary.defaultBase <ref>` for repositories
whose default branch cannot be inferred.

The CLI resolves Git once and passes the same versioned context to the
adversary. In the TypeScript SDK, every rule receives the portable
`context.input` and the structured `context.review`. The latter contains the
mode, refs, merge base, and added, modified, deleted, renamed, copied, or
untracked files. It is `null` for an intentional whole-target scan. These
changed files describe the review focus; they do not restrict an adversary from
reading other repository files through its normal SDK APIs.

## Safety and trust

Local source adversaries run directly with `HostExecutor` for a fast development
loop. Installed adversaries may use the host backend when an **official
signature** verifies, or when a hosted private package has a valid
platform-delegated team signature for its registry, exact repository, and
content digest. See [artifact signatures](docs/official-signatures.md). Private
publishes to the Adversary Labs registry are signed automatically; external
copies such as GHCR remain untrusted. Path names and registry hostnames alone do
not grant trust.
Unknown publishers require a sandbox backend or `--allow-unsafe-host-execution`; that explicit
override is not isolation. Manifest permissions are advisory by default;
`permissions.enforcement: required` and `--no-network` fail before launch when
the selected executor cannot enforce them.
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
| model provider | `--model-provider`, `--model` | `ADVERSARY_MODEL_PROVIDER`, `ADVERSARY_MODEL`, provider API key | inferred only when exactly one supported key is present |
| OCI diagnostics | `--verbose` | `ADVERSARY_OCI_DEBUG` (internal transport toggle) | disabled; secrets redacted |
| review suppression | command behavior | `ADVERSARY_INCLUDE_SUPPRESSED` (injected into adversary) | suppressed details omitted |
| adversary protocol paths | — | `ADVERSARY_INPUT`, `ADVERSARY_OUTPUT`, `ADVERSARY_REPO` (injected) | per-run temporary paths |
| automatic change context | — | `ADVERSARY_CHANGE_CONTEXT` (injected) | one versioned context shared by selected runs |
| adversary diagnostics | `--verbose` | `ADVERSARY_VERBOSE` (injected) | disabled |
| service-account login | `--token-stdin --registry-namespace <slug>` | service token only in the caller's shell/secret store | selected profile in OS config dir |
| password login | `--password-stdin` | `ADVERSARY_PASSWORD` only in shell examples | secure prompt; variable is not read directly by the CLI |

## Model-backed adversaries

An adversary that declares `permissions.model: true` can use the SDK's
`ctx.model.review(...)` capability. The CLI owns provider credentials and
network transport. It starts a short-lived authenticated loopback broker for
the adversary execution and passes only the broker endpoint and execution token
to the child process; provider API keys are never inherited by the adversary.

Select the provider and model per run while keeping the API token in the
environment:

```sh
export OPENAI_API_KEY="..."
adversary run adversarylabs/example \
  --model-provider openai \
  --model "your-model-id"
```

Fireworks uses its full model identifier:

```sh
export FIREWORKS_API_KEY="..."
adversary run adversarylabs/example \
  --model-provider fireworks \
  --model "accounts/fireworks/models/your-model-id"
```

camelStream is a first-class OpenAI-compatible provider and uses Camel's own
credential namespace:

```sh
export CAMEL_API_KEY="qaml_live_..."
adversary run review/code \
  --model-provider camel \
  --model auto
```

Flags override `ADVERSARY_MODEL_PROVIDER` and `ADVERSARY_MODEL`. Without a
provider flag or environment value, the CLI infers `openai`, `anthropic`,
`fireworks`, or `camel` only when exactly one of `OPENAI_API_KEY`,
`ANTHROPIC_API_KEY`, `FIREWORKS_API_KEY`, or `CAMEL_API_KEY` is configured. API
tokens are intentionally not accepted as flags because command arguments can
leak through process listings and shell history.

`ADVERSARY_OPENAI_BASE_URL`, `ADVERSARY_ANTHROPIC_BASE_URL`, and
`ADVERSARY_FIREWORKS_BASE_URL`, and `ADVERSARY_CAMEL_BASE_URL` override provider
endpoints for compatible gateways and testing. Model-backed execution currently
uses the host executor because sandbox and container loopback routing is not yet
available.
`--no-network` applies to the adversary child; provider network access remains
isolated in the CLI-owned broker.

`ADVERSARY_BUILD_HELPER` is a test seam, not a supported user setting. Standard
`HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`, and platform CA trust are
honored by Go networking. Registry credentials come from Docker credential
configuration or the selected Adversary profile as documented in
[network policy](docs/network-oci-policy.md). Never put passwords in URLs or
command history. Pass service-account tokens through `--token-stdin`; the CLI
does not accept them as command-line values.

## Run telemetry

Authenticated runs report privacy-safe OpenTelemetry timing spans to
Adversary Labs. The trace contains adversary identifiers, group identifiers,
durations, statuses, and aggregate finding counts. It never contains source
code, repository identity, file paths, prompts, or finding text.

Attach short labels with repeatable `--tag key=value`. Benchmark harnesses
should pass `--tag benchmark=true`; these traces are stored for comparison but
hidden from normal project analytics by default. `--telemetry-file trace.jsonl`
appends each completed run as OTLP/HTTP JSON, and `adversary telemetry pull
<trace-id>` retrieves an authorized stored trace in the same format. Standard
`OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`, headers,
and timeout variables send a copy to another OTLP/HTTP collector.

Telemetry is disabled for one run with `--no-telemetry`, or globally by any of `DO_NOT_TRACK=1`,
`ADVERSARY_DO_NOT_TRACK=1`, `ADVERSARY_NO_TELEMETRY=1`,
`ADVERSARY_TELEMETRY=0`, `OTEL_SDK_DISABLED=true`, or
`OTEL_TRACES_EXPORTER=none`.

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

## Train (review history → package improvement issues)

Grade **home-built** (local) packages against your team’s PR review history and
file deduplicated improvement issues. Official catalog packages can act as a
read-only jury only.

```sh
cd my-adversary
adversary train init --single-package
# edit adversary.train.yaml (sources, authors, official jury)
adversary train run
adversary train results ls
```

In a workspace of sibling packages, repeat the following for durable
round-robin coverage. Each target gets independent discovery memory; the
separately trained `torvalds` package is excluded automatically.

```sh
adversary train run --cycle-adversaries --max-prs 1
```

For large public-repository catalogs, `sources.discovery: github_events`
batches candidate selection through ClickHouse's read-only GH Archive mirror.
Selected PRs are still hydrated from GitHub before any review evidence is used.

`train run` opens issues for consolidated drafts and false-positive fixes by
default. Individual misses remain in the local results database as evidence.
Use `--no-issues` when you want a local-only run.

Guide: **[docs/train.md](docs/train.md)** (home-built workflow).  
Also: [composition](docs/composition.md), [comment voice](docs/voice.md).
