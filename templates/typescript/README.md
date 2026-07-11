# {{name}}

{{description}}

## Build

```sh
npm ci
npm run build
```

## Run

```sh
adversary run . --repo /path/to/repository
```

## Test

```sh
npm test
```

## Layout

- `adversary.yaml` declares the adversary manifest.
- `AGENTS.md` gives AI coding agents repository-specific engineering guidance.
- `src/index.ts` contains the TypeScript SDK adversary.
- `dist/index.js` is prebuilt so `adversary run . --repo ...` works immediately.
- `test/index.test.ts` demonstrates testing rules with fixtures.
- `fixtures/clean` should produce no findings.
- `fixtures/vulnerable` should produce one finding.
