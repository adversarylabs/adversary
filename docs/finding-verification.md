# Verify findings before composition

Composed reviews now verify every generalist and specialist finding against host-read source before deduplication. Candidates are evaluated independently. A reviewer name, high confidence, an overlapping finding, or a complexity count is not evidence of correctness.

A high-confidence, source-cited **keep** enters the normal composition merger. A supported **reject** stays in the decision ledger and original replay pool. **Unresolved** candidates receive one bounded retrieval-and-recheck pass when the verifier requests more source. A high-confidence unresolved finding may still enter composition when either the verifier citation or the finding's original evidence resolves to readable head-side source on a changed line. Free-form evidence, off-diff locations and base-side source remain withheld. Provider, context, cancellation, budget, and schema-correction failures carry explicit failure codes and cannot use this fallback. Other unresolved candidates remain visible in review observations without being posted as confirmed findings. Unresolved decisions do **not** fail the review or discard verified peers. The normal finding exit code applies when verified findings remain; otherwise the review succeeds with an empty finding list. A clean/ship opinion is withheld whenever any candidate remains unresolved. Cancellation, invalid report/snapshot structure and failed artifact writes remain errors.

## Partial reviewer failures

A failed specialist does not discard completed peers. Its error and reviewer status remain visible, but any envelope emitted by the failed process contributes neither findings nor a clean opinion. Remaining candidates still pass through verification and deduplication. The CLI returns the normal finding exit code (1 with findings, 0 without) if at least one applicable reviewer completed. If every applicable reviewer failed, the review remains an execution error; skipped reviewers do not count as completed coverage.

`composition.incomplete` marks partial coverage and withholds the clean/ship opinion even when no findings survive. Specialists can also emit `review.evidence-incomplete` when they withhold unsupported candidates; composition propagates that warning and withholds a clean opinion. Successful peers are not rerun. Benchmarks credit only their returned confirmed findings and leave uncovered expected issues as recall misses. A partial result is not proof that the entire PR was reviewed successfully.

Benchmarks judge only the confirmed findings returned by the product. An unresolved candidate earns no match; an expected issue not covered by another confirmed finding counts as a recall miss. Withheld candidates do not enter the precision denominator and remain available for diagnosis. Neither an unresolved-only review nor a mixed review is a whole-PR execution failure merely because verification was uncertain. Replay commands use the same nonfatal uncertainty policy. This changes result handling, not the verification prompt or evidence standards.

This stage does not rewrite claims or transfer validity between findings. The existing conservative deduplication still applies after validity: claim, impact, recommendation, and structured remediation must agree before a location/title or group-key heuristic can merge findings. No benchmark labels are used to select a representative.

## Capture a run and replay only the verifier

```sh
adversary run review/code --base main --head feature \
  --model-provider camel --model auto \
  --verification-output verification.json

adversary verify-findings verification.json \
  --model-provider camel --model auto \
  --output verification-replay.json
```

The replay command makes verification model calls, but does not regenerate findings, execute the reviewed repository, post GitHub comments, or run the recall harness. It reads only the saved packet. A request for uncaptured source remains unresolved. Compare revisions of the verifier using the same candidate pool and sources; retain an unchanged input artifact. Prompt changes must update `PromptRevision` so results identify the filtering policy they used.

Artifacts contain the original candidates, reviewer provenance, pinned base/head revisions, host-read source windows, fetched retry evidence, all decisions, model identity, usage, and request digests. Initial and retry evidence are stored separately so offline replay does not reveal later evidence prematurely. Files are written atomically with private permissions because they contain repository source. Artifact parents must already exist.

`--verify-findings=false` preserves the previous composition behavior for a controlled baseline comparison. `--verification-output` requires verified composition and a path distinct from the normal review output. Standalone non-composed reviewers keep their existing behavior.

## Source and budget boundaries

Committed source is read from pinned revisions. For dirty-worktree review, changed files and their diffs are frozen before reviewers run; unchanged files come from pinned HEAD. Source reads stay inside the repository, reject symlinks and traversal, and disable external diff/text-conversion drivers and filesystem-monitor hooks. Missing or over-budget source is marked unavailable rather than trusted from a finding's claimed snippet.

Each candidate has a 2-minute, 2,048-output-token request budget and at most one retry, with at most four candidates active at once. Each retry can request up to three base/head file windows, at most 200 lines and 32 KiB per window. Files over 512 KiB are unavailable. Initial context includes up to four cited paths (base and head), their available change hunks, root policy excerpts, and up to 100 changed-path retrieval leads. Each model input is capped at 768 KiB; snapshots/reports at 64 MiB and 1,000 candidates. Exceeding a limit never silently marks a candidate false or a review clean.

## Validation and rollout

Unit and integration tests use mocked provider responses and small local repositories. They cover independent retention/rejection, duplicate ordering, partial failures, malformed decisions, citation validation, bounded evidence retries, offline replay, pinned source, dirty-worktree freezing, and private artifact replacement. These tests do not establish model recall or precision.

Measure retained unique issues, invalid comments, residual duplicates, unresolved rate, and model cost on frozen outputs before claiming a gain. Independently adjudicate rewritten or newly generated findings in experiments; do not reuse labels by analogy. Use held-out PRs and repositories for the final assessment. Verification cannot discover issues missing from the candidate pool.
