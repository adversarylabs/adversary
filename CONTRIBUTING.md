# Contributing

Before contributing, note that no project license has been selected. Opening a
pull request does not by itself establish contribution licensing; maintainers
must resolve [the license decision](docs/license-decision.md) before accepting
external contributions that require a license grant.

Use a focused branch and include regression tests, documentation for user-facing
changes, rollback notes for migrations, and audit IDs when applicable. Run:

```sh
make verify
make ci
```

`make verify` is the quick formatting/module/vet/native-test loop. `make ci`
runs the same complete stages required by `ci / test`: race and coverage gates,
five cross-builds, a freshly generated TypeScript project's `npm ci`, build,
tests and full audit, an actual CLI smoke, checksum-pinned workflow/shell and
vulnerability tooling, and the deterministic release contract. The complete
gate downloads npm packages and pinned security tools and is intentionally
slower.

Commits should be reviewable and must not contain generated build output,
credentials, or personal repository data. Report vulnerabilities privately as
described in [SECURITY.md](SECURITY.md).
