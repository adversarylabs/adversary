# Adversary protocol schemas

These Draft 2020-12 JSON Schemas are the normative contracts for the versioned
runtime input and review output envelopes. Changes to an existing schema must
remain backward compatible; incompatible changes require a new versioned file.

The fixtures in `fixtures/` are shared compatibility examples. The Go review
decoder and vendored TypeScript SDK both exercise the review fixture. Schema
copies shipped in the vendored SDK are tested byte-for-byte against these files.

Suppression is explicit in review v1: `suppressed.findings` is always the total
number withheld from `findings`. When suppressed details are requested, the
optional `suppressedFindings` array is present and its length equals that total.
