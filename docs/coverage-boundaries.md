# Performance and parser coverage boundaries

This record closes the remaining executable-proof gaps for CLI-019, CLI-021,
and CLI-024. The targets below exercise production parser, matcher, packaging,
protocol, and rendering entry points; they are not placeholder loops.

## CLI-019 benchmarks

Run the bounded one-iteration benchmark suite with:

```sh
go test ./pkg/pack -run '^$' -bench '^BenchmarkCreateManyFilesRepository$' -benchtime=1x
go test ./internal/adversary -run '^$' -bench '^BenchmarkShouldRunForManyChangedFiles$' -benchtime=1x
go test ./pkg/review -run '^$' -bench '^BenchmarkDecodeValidateRenderLargeReview$' -benchtime=1x
```

- `BenchmarkCreateManyFilesRepository` creates 2,000 deterministic source files
  before timing, then packages them through `pack.Create`. Each timed artifact
  is closed, so repeated iterations do not retain temporary layers.
- `BenchmarkShouldRunForManyChangedFiles` sends 20,000 paths and six trigger
  patterns through the actual compiled `ShouldRunForChangedFiles` boundary,
  with the match deliberately last.
- `BenchmarkDecodeValidateRenderLargeReview` prepares a 2,000-finding envelope
  before timing, then performs strict protocol decoding, semantic validation,
  and terminal rendering to `io.Discard`.

All three call `ReportAllocs`; fixture construction is outside the timed loop.
The existing large incompressible-layer and verified-source benchmarks continue
to cover byte-volume scaling independently.

## CLI-021 fuzz targets

Seed corpora run during ordinary package tests. Maintainers can fuzz one boundary
explicitly with, for example,
`go test ./pkg/review -fuzz '^FuzzDecodeRunEnvelope$' -fuzztime=30s`.
The targets are:

- `FuzzGlobMatcher`: caps patterns at 256 bytes and names at 512 bytes, compiles
  the translated regular expression, and compares the direct matcher with the
  production changed-file trigger boundary.
- `FuzzDecodeRunEnvelope`: caps documents at 64 KiB, performs strict decode and
  semantic validation, and requires every accepted envelope to render and
  survive a canonical typed round trip.
- `FuzzExtractGzipTar`: caps compressed input at 64 KiB and extraction at 256
  KiB, 64 files, 64 KiB per file, and 512-byte paths. Every iteration owns and
  removes its temporary parent, verifies an outside sentinel is unchanged, and
  rejects successful extraction that produces a symlink or escaped path.

The corpora include valid inputs, malformed syntax, unsupported protocol and
semantic combinations, truncated gzip, traversal, and arbitrary non-format
bytes. These caps keep continuous fuzzing from creating unbounded memory, work,
or retained disk state.

## CLI-024 composition wording

The `internal/application` package comment now describes the completed
composition boundary: the application is constructed at the process edge and
injected into effectful commands. This aligns source documentation with the
maintained application decision and changes no runtime behavior.

## Rollback

The benchmarks, fuzz targets, documentation correction, and audit links are
test-only or documentation-only and introduce no wire, storage, command-output,
or runtime migration. They can be reverted together. Doing so removes the
executable performance/parser evidence and restores the stale composition
comment, reopening the proof gaps for CLI-019, CLI-021, and CLI-024 without
changing production behavior.
