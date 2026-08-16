# Contributing

## Prerequisites

- Node.js 22
- The Adversary CLI

## Build and test

```sh
npm ci
npm test
adversary validate .
adversary pack . --check
```

## Changing review behavior

When adding or changing a rule:

1. Update `docs/scope.md` when the review boundary changes.
2. Add or update representative fixtures and tests.
3. Keep `CHECKS.md` aligned with every emitted rule ID and severity.
4. Rebuild `dist/index.js` with `npm run build` and include it in the change.
