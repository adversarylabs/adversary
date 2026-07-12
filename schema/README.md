# Adversary protocol schemas

These Draft 2020-12 JSON Schemas are the normative contracts for the versioned
runtime input and review output envelopes. Changes to an existing schema must
remain backward compatible; incompatible changes require a new versioned file.
`adversary.manifest.v1.schema.json` is the canonical v1 project manifest schema.
Unknown fields are rejected at every schema-defined object boundary. Extensions
must therefore use a new versioned contract instead of adding unversioned fields
to a v1 payload.

`adversary.error.v1.schema.json` is the normative failure envelope shared by
Go and TypeScript. Consumers must reject newer protocol versions rather than
silently interpreting them as v1. Arrays in all v1 contracts preserve producer
order and are never silently reordered by validation or encoding (the shared
order fixture enforces this in Go and TypeScript). Canonical error encoders recursively
sort object keys, including `details`, so Go and TypeScript emit the same bytes
independent of map insertion order.

The manifest JSON Schema is the portable structural and syntactic layer. The
canonical Go `manifest.Parse` operation is the normative semantic validator and
always runs at CLI trust boundaries, including `adversary validate`. Semantic
rules that JSON Schema cannot robustly express—full Masterminds version
constraints, cross-array read/write conflicts, and project/runtime consistency—
are listed in `x-adversary-semanticRules` and covered by parser-only corpora.
Schema/parser parity tests are limited to rules expressible in both layers.
Every runtime declares exactly one execution identity: either a supported named
runtime with a version constraint, or an OCI image without `name` or `version`.
Image references use deterministic distribution-reference syntax. The canonical
parser converts familiar references such as `node:22` to
`docker.io/library/node:22`, and adds `:latest` to untagged references without a
digest. This fixed Docker Hub normalization never reads ambient registry
configuration, so the stored manifest value is stable before later resolution.
Commands for image runtimes are paths/arguments inside the image and therefore
do not require corresponding files in the host project.
The schema checks the portable image-reference structure. Numeric port range,
IPv6 address semantics, and the normalized distribution repository-path
255-byte limit require extracted-field checks and are normative parser-only
semantic rules recorded in the schema annotation. That length excludes registry,
tag, and digest, but includes Docker Hub's injected `library/` namespace.

The fixtures in `fixtures/` are shared compatibility examples. The Go review
decoder and vendored TypeScript SDK both exercise the review fixture. Schema
copies shipped in the vendored SDK are tested byte-for-byte against these files.

Suppression is explicit in review v1: `suppressed.findings` is always the total
number withheld from `findings`. When suppressed details are requested, the
optional `suppressedFindings` array is present and its length equals that total.

Terminal rendering is intentionally outside these data contracts.
