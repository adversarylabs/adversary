# Adversary

Adversary runs containerized source-code adversaries against a local repository.

## Create an Adversary

```sh
./bin/adversary init my-adversary --sdk typescript
cd my-adversary
npm install
npm run build
adversary run . --repo /path/to/repository
```

Only the TypeScript SDK is supported by `init` today. The generated project includes a working manifest, Dockerfile, starter rule, fixtures, and tests.

## Usage

```sh
./bin/adversary run ./smoke-tests/comment-sentence-adversary --repo .
./bin/adversary run ./smoke-tests/comment-sentence-adversary --repo . --verbose
./bin/adversary run ./smoke-tests/comment-sentence-adversary --repo . --format json
./bin/adversary run ./smoke-tests/comment-sentence-adversary --repo . --base main --head HEAD
./bin/adversary run ./smoke-tests/comment-sentence-adversary --repo . --base main --head HEAD --all-files
./bin/adversary inspect ./smoke-tests/comment-sentence-adversary --repo .
```

An adversary reference can be either a local directory containing `adversary.yaml` or a direct container image reference.

When `--base` and `--head` are provided, the CLI includes changed files from `git diff --name-only <base>...<head>` in `input.json`. Use `--all-files` to keep that diff context but request a full repository scan and bypass `triggers.files_changed` skipping.

## Smoke Test Adversary

```sh
./bin/adversary run ./smoke-tests/comment-sentence-adversary --repo .
```

The repository includes a deliberately small smoke-test adversary used to verify the local CLI loop. Full authoring examples live with the SDK. For local adversary directories with a Dockerfile, `adversary run` builds the image from `runtime.image` before running it. Use `--no-build` to skip that local build.

## Debugging

Use `--verbose` to print the manifest, build context, image, Docker command, mounts, environment, repository contents, container exit code, and execution timing:

```sh
./bin/adversary run ./smoke-tests/comment-sentence-adversary --repo . --verbose
```

Use `inspect` to validate the runtime configuration without executing the adversary:

```sh
./bin/adversary inspect ./smoke-tests/comment-sentence-adversary --repo .
```

Use `--shell` to launch an interactive shell in the configured container instead of running the adversary command:

```sh
./bin/adversary run ./smoke-tests/comment-sentence-adversary --repo . --shell
```

Container stdout and stderr stream directly to the terminal.

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
