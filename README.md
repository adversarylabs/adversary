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
See [finding verification](docs/finding-verification.md) for source-based checks
before deduplication and replaying the filter on saved candidates.
See [comment voice](docs/voice.md) for `agent/voice.md`, example banks, and GitHub
rewrite with `--github-review`.

## Private catalog training

Create a private catalog, configure the GitHub repositories and human reviewers
whose comments should count, then run a foreground scan. The scan never pauses
for input: it stores resumable results in a local, gitignored SQLite inbox and
exits. Review is a separate command.

```sh
adversary catalog init my-private-adversaries
cd my-private-adversaries
# Edit adversary.train.yaml, or select sources and a model on the command line:
adversary catalog train --source-repo acme/api --source-repo acme/web \
  --model-provider cloudflare --model @cf/meta/llama-3.3-70b-instruct-fp8-fast
adversary catalog train review
adversary catalog train inspect
adversary catalog train inspect <id>
adversary catalog train accept <id>
```

For an exhaustive, resumable repository scan, set a date boundary and remove
the normal candidate limits:

```yaml
sources:
  discovery: repos
  since: "2025-09-12"
run:
  all_history: true
```

The equivalent one-off flags are `--since 2025-09-12 --all-history`. Historical
scans detect GitHub primary and secondary rate limits, wait for the advertised
reset (or a conservative fallback), and continue unless interrupted.

Bare `inspect` opens a localhost review queue with every candidate in a left
nav grouped by source repository. Inline comments appear with their file, diff
hunk, PR author, and reviewer identity. Context controls load adjacent lines
from the exact reviewed GitHub revision. Reviewers can edit the proposed rule, route it to an existing or new
private adversary, accept or dismiss it, and reopen earlier decisions. Use
`inspect --all` for the terminal wizard instead.

Use repeatable `--author` and `--exclude-author` flags for one-off reviewer
selection; the equivalent committed policy is `sources.authors_only` and
`sources.authors_ignore`. Model configuration can also come from
`ADVERSARY_MODEL_PROVIDER` and `ADVERSARY_MODEL`. Accepted results record a
decision only. They do not modify tracked catalog files, upload private evidence
to Adversary Labs, or open a pull request. The scan does send bounded comment,
thread, review-summary, and diff evidence to the model provider you select.
Interactive CLI commands display a one-line stderr reminder while registered
catalogs still have unreviewed results; machine-readable and noninteractive
commands remain quiet.

The collector intentionally runs in the foreground and checkpoints its state.
Shells and schedulers can run it unattended without a CLI-managed background
process. A future catalog GitHub Action can use the same interface, but needs an
explicit cross-repository credential and an agreed `--auto` contract before it
can safely create catalog pull requests.

See the [private catalog training guide](docs/train.md) for discovery and inbox
behavior.

See [review feedback](docs/github-feedback.md) for the SaaS-owned learning loop
that watches replies and steers later reviews.

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
The child can access the repository, filesystem, network, processes, and other
resources available to your account. Its process environment contains only
basic runtime variables, CLI-owned values, and keys explicitly named by
`permissions.environment.allow`; other ambient credentials are omitted.
Restrictions the host runner cannot enforce fail closed. OCI digests provide
integrity and identity, not publisher authenticity. Registry credentials and
trusted CA/proxy configuration are part of the user's environment trust
boundary. See [artifact limits](docs/artifact-trust-and-limits.md)
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
| model provider | `--model-provider`, `--model` | `ADVERSARY_MODEL_PROVIDER`, `ADVERSARY_MODEL`, provider API key | inferred only when exactly one supported provider credential set is present |
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

Selecting OpenAI `gpt-5.6-luna` defaults to high reasoning. Because reasoning
and the final answer share the output allowance, the CLI multiplies each
adversary's requested token budget by four, with a 16,384-token minimum and
65,536-token maximum. For example, a 1,500-token planning budget becomes 16,384,
and an 8,000-token review budget becomes 32,000. These are ceilings, not target
lengths; larger generations can increase cost and latency. Request deadlines
remain unchanged.

`ADVERSARY_OPENAI_REASONING_EFFORT` explicitly selects `none`, `low`, `medium`,
`high`, `xhigh`, or `max` (subject to the selected model's support).
`ADVERSARY_OPENAI_MAX_OUTPUT_TOKENS` sets an exact per-request output cap from
1 through 65,536 and overrides automatic sizing. Setting reasoning to `none`
also disables Luna's automatic headroom unless an explicit output cap is set.
Other models retain their existing defaults. Incomplete Responses are reported
as errors, including the effective budget when the output limit is exhausted;
they are not automatically retried at a higher cost.

Codex can use an installed `codex` executable and your existing ChatGPT
subscription login, without an API key:

```sh
codex login
adversary run review/code --model codex/gpt-5.6-luna
# Equivalent explicit provider:
adversary run review/code --model-provider codex --model gpt-5.6-luna
```

The `codex/` prefix selects Codex before API-key inference. An explicitly
configured different provider conflicts with this prefix. The model ID must be
available to your Codex account. `ADVERSARY_CODEX_REASONING_EFFORT` defaults to
`high`; supported selections are `low`, `medium`, `high`, `xhigh`, and `max`,
subject to model support.

Use a recent Codex CLI supporting `exec --ignore-user-config`, `--ephemeral`,
and `--output-schema`. Each model request starts an isolated, ephemeral,
read-only Codex session with shell, web search, multi-agent, and app tools
disabled. User config is ignored to avoid custom providers and MCP servers;
authentication remains in the existing `CODEX_HOME` (default `~/.codex`).
The CLI requires `codex login status` to report ChatGPT authentication, strips
API credentials from the subprocess environment, and never falls back to paid
API access. Authentication and execution failures are not automatically retried
by this provider. Final JSON is checked against the adversary's requested schema.

Requests sharing a `CODEX_HOME` are serialized across adversary processes using
an OS lock. Queue waiting counts against the request deadline. Other programs
using Codex do not participate in that lock: use a dedicated authenticated home
for a trusted private CI runner, and do not copy a login across concurrent
machines. Subscription usage limits still apply. See OpenAI's
[CI authentication guidance](https://learn.chatgpt.com/docs/auth/ci-cd-auth).

Codex does not expose a hard output-token cap through `exec`; the requested
output budget is advisory in the prompt. Timeouts and final response byte limits
are enforced. On Windows, cancellation terminates the direct Codex child;
on Unix it terminates its process group. Codex's agent harness differs from the
API provider, so record `codex` as a separate provider in benchmark comparisons.

Fireworks uses its full model identifier:

```sh
export FIREWORKS_API_KEY="..."
adversary run adversarylabs/example \
  --model-provider fireworks \
  --model "accounts/fireworks/models/your-model-id"
```

Cloudflare AI Gateway uses Cloudflare's OpenAI-compatible Responses endpoint.
Set the account ID and a token with Workers AI Read permission; model identifiers
use Cloudflare's `author/model` format. A gateway ID is optional and enables the
configured gateway's logging, caching, rate limits, and policies:

```sh
export CLOUDFLARE_API_TOKEN="..."
export CLOUDFLARE_ACCOUNT_ID="..."
export ADVERSARY_CLOUDFLARE_GATEWAY_ID="your-gateway"
adversary run adversarylabs/example \
  --model-provider cloudflare \
  --model "openai/gpt-5.5"
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
provider flag or environment value, the CLI infers `openai`, `cloudflare`,
`anthropic`, `fireworks`, or `camel` only when exactly one provider credential
set is configured. Cloudflare requires both `CLOUDFLARE_API_TOKEN` and
`CLOUDFLARE_ACCOUNT_ID`; the other providers use `OPENAI_API_KEY`,
`ANTHROPIC_API_KEY`, `FIREWORKS_API_KEY`, or `CAMEL_API_KEY`. API
tokens are intentionally not accepted as flags because command arguments can
leak through process listings and shell history.

`ADVERSARY_OPENAI_BASE_URL`, `ADVERSARY_CLOUDFLARE_BASE_URL`,
`ADVERSARY_ANTHROPIC_BASE_URL`, `ADVERSARY_FIREWORKS_BASE_URL`, and
`ADVERSARY_CAMEL_BASE_URL` override provider
endpoints for compatible gateways and testing. Model-backed execution currently
uses the host executor because sandbox and container loopback routing is not yet
available.
Camel retries transient connection, rate-limit, and server failures up to eight
times within the affected model call. Backoff grows from 2s to 60s plus jitter;
`Retry-After` seconds and HTTP dates are honored without shortening the requested
wait. The original request deadline and cancellation still bound all waits.
Set `ADVERSARY_CAMEL_REQUEST_RETRIES` from `0` through `20` to override the default.
Capacity retry exhaustion does not restart the entire specialist.

`ADVERSARY_CAMEL_MAX_CONCURRENCY` limits actual simultaneous Camel HTTP requests
(default `5`, range `1`–`256`), independently of `--compose-concurrency`. All
specialist brokers and the verifier in the **same CLI process**, using the same
endpoint and credential, share this budget and a cooldown. Congestion halves the
effective limit (minimum one); ten successful responses after the cooldown restore
one slot, never beyond the configured cap. Conflicting limits for the same
credential within a process use the smaller limit.

This is not an account-wide distributed lock. Multiple CLI processes, CI jobs,
or machines sharing a key must divide the account budget externally. The benchmark
fleet reserves slots in Postgres and sets each CLI cap to its reservation; new
review jobs must wait for outstanding judge leases. For a 20-stream fleet with
five slots per review, at most four reviews can run when no judges hold slots.
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

Also: [composition](docs/composition.md), [comment voice](docs/voice.md).
