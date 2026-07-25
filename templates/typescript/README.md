# {{name}}

{{description}}

## Build

```sh
npm ci
npm run build
```

## Run

```sh
adversary run . --path /path/to/repository
```

## Test

```sh
npm test
```

## Layout

- `adversary.yaml` declares the adversary manifest.
- `AGENTS.md` gives AI coding agents repository-specific engineering guidance.
- `src/index.ts` contains the TypeScript SDK adversary.
- `dist/index.js` is prebuilt so `adversary run . --path ...` works immediately.
- Each rule receives `context.input` and `context.review` automatically.
  `context.review` contains the CLI-resolved Git mode, refs, merge base, and
  structured changed files, or `null` for an intentional all-files scan.
- `test/index.test.ts` demonstrates testing rules with fixtures.
- `fixtures/clean` should produce no findings.
- `fixtures/vulnerable` should produce one finding.
