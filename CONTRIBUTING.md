# Contributing

Before contributing, note that no project license has been selected. Opening a
pull request does not by itself establish contribution licensing; maintainers
must resolve [the license decision](docs/license-decision.md) before accepting
external contributions that require a license grant.

Use a focused branch and include regression tests, documentation for user-facing
changes, rollback notes for migrations, and audit IDs when applicable. Run:

```sh
make verify
go test -race ./...
node --test templates/typescript/vendor/adversary-sdk/test/protocol.test.js
```

Commits should be reviewable and must not contain generated build output,
credentials, or personal repository data. Report vulnerabilities privately as
described in [SECURITY.md](SECURITY.md).
