# Adversary

Adversary runs source-code adversaries against a local repository.

## Create an Adversary

```sh
./bin/adversary init my-adversary --sdk typescript
cd my-adversary
npm install
npm run build
adversary run . --repo /path/to/repository
```

Only the TypeScript SDK is supported by `init` today. The generated project includes a working manifest, starter rule, fixtures, and tests.

## Usage

```sh
./bin/adversary run ./smoke-tests/comment-sentence-adversary --repo .
./bin/adversary run ./smoke-tests/comment-sentence-adversary --repo . --verbose
./bin/adversary run ./smoke-tests/comment-sentence-adversary --repo . --format json
./bin/adversary run ./smoke-tests/comment-sentence-adversary --repo . --base main --head HEAD
./bin/adversary run ./smoke-tests/comment-sentence-adversary --repo . --base main --head HEAD --all-files
./bin/adversary inspect ./smoke-tests/comment-sentence-adversary --repo .
./bin/adversary pack .
./bin/adversary ls
./bin/adversary inspect security-reviewer
./bin/adversary login
./bin/adversary whoami
./bin/adversary search dockerfile
./bin/adversary push ghcr.io/acme/security-reviewer
./bin/adversary pull ghcr.io/acme/security-reviewer
```

An adversary reference can be either a local directory containing `adversary.yaml` or a locally installed adversary artifact.

When `--base` and `--head` are provided, the CLI includes changed files from `git diff --name-only <base>...<head>` in `input.json`. Use `--all-files` to keep that diff context but request a full repository scan and bypass `triggers.files_changed` skipping.

## Smoke Test Adversary

```sh
./bin/adversary run ./smoke-tests/comment-sentence-adversary --repo .
```

The repository includes a deliberately small smoke-test adversary used to verify the local CLI loop. Full authoring examples live with the SDK. `adversary run` executes local directories and installed adversary artifacts through the CLI-managed runtime; it does not build or run Docker images.

## Debugging

Use `--verbose` to print the manifest, runtime, command, environment, repository contents, process exit code, and execution timing:

```sh
./bin/adversary run ./smoke-tests/comment-sentence-adversary --repo . --verbose
```

Use `inspect` to validate the runtime configuration without executing the adversary:

```sh
./bin/adversary inspect ./smoke-tests/comment-sentence-adversary --repo .
```

Use `--shell` to launch an interactive shell in the adversary working directory instead of running the adversary command:

```sh
./bin/adversary run ./smoke-tests/comment-sentence-adversary --repo . --shell
```

Adversary stdout and stderr stream directly to the terminal.

## Local Packaging

Package the current adversary into the local content-addressable store:

```sh
adversary pack .
adversary pack . --builder docker
```

`pack` reads `adversary.yaml`, validates the manifest, detects the runtime, runs the TypeScript build when needed, creates deterministic OCI-style artifact content, writes content by digest, and updates local refs. It does not create or tag a Docker image. Packed adversaries are run through the Adversary CLI, which materializes the artifact and executes it with the appropriate CLI-managed runtime. Use `--builder docker` to run the TypeScript build inside Docker/BuildKit; this supports remote builders that honor `docker build --output`, such as CI builders configured through `DOCKER_HOST`.

```text
refs/security-reviewer/0.1.0
refs/security-reviewer/latest
```

Local store locations:

```text
macOS: ~/Library/Application Support/Adversary/
Linux: ~/.local/share/adversary/
Fallback: ~/.adversary/
```

The store layout is content-addressable:

```text
store/blobs/sha256/...
store/manifests/sha256/...
refs/<name>/<tag>
```

List local adversaries:

```sh
adversary ls
adversary list
adversary ls --json
```

Inspect local artifacts by name, tag, or digest:

```sh
adversary inspect security-reviewer
adversary inspect security-reviewer:0.1.0
adversary inspect sha256:abc123
adversary inspect security-reviewer --json
```

Packaging applies safe default ignores for `node_modules/`, `.git/`, `.env`, `.env.*`, `.DS_Store`, `coverage/`, `tmp/`, `.cache/`, and `Dockerfile`. Add `.adversaryignore` for project-specific exclusions.

## Registry Distribution

Adversaries can be packaged as OCI artifacts and pushed to any OCI-compatible registry:

```sh
adversary push security-reviewer
adversary push adversarylabs/security-reviewer
adversary push ghcr.io/acme/security-reviewer
adversary push registry.company.com/team/security-reviewer
```

Pull works the same way:

```sh
adversary pull security-reviewer
adversary pull adversarylabs/security-reviewer
adversary pull ghcr.io/acme/security-reviewer
adversary pull registry.company.com/team/security-reviewer
```

References without a registry default to Adversary Labs:

```text
security-reviewer       -> registry.adversarylabs.ai/library/security-reviewer
acme/security-reviewer  -> registry.adversarylabs.ai/acme/security-reviewer
ghcr.io/acme/reviewer   -> ghcr.io/acme/reviewer
```

Pulled artifacts are cached under `~/.adversary/cache/` by digest and registered locally so `adversary run security-reviewer --repo .` can resolve a pulled adversary.

## Login, Logout, And Search

`adversary login` authenticates with Adversary Labs and stores the returned token in `~/.adversary/config.json`:

```sh
adversary login
adversary login --name "Marc's MacBook Pro"
adversary login --ci
adversary login --email-address marc@example.com
adversary login --email-address marc@example.com --password "$ADVERSARY_PASSWORD"
adversary login --api-url http://localhost:3000/api
```

Without `--email-address`, login opens a browser and waits for the Adversary Labs app to redirect back to a temporary localhost callback. With `--email-address` but no `--password`, the CLI prompts for the password.
The stored token is used for Adversary Labs registry access, private artifacts, search, and future SaaS API calls. Tokens are never printed by the CLI.
The default SaaS endpoint is `https://adversarylabs.ai/api`. For local development, set `ADVERSARY_API_URL` or pass `--api-url`.

```sh
adversary search security
adversary whoami
adversary logout
adversary logout --local-only
```

`push` and `pull` remain generic OCI operations. Adversary Labs-specific behavior is limited to default reference resolution, login/logout, and search.

## TypeScript Logging

TypeScript adversaries can use the SDK logging helper:

```ts
import { log } from "@adversary/sdk";

log.debug("Scanning repository")
log.info("Scanning src/index.ts")
log.warn("Skipping binary file")
log.error("Unable to parse source file")
```

Warnings and errors are always printed. Debug and info logs print when the CLI is run with `--verbose`.
