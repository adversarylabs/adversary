# TypeScript SDK output migration (CLI-013)

The TypeScript SDK historically returns a rule-summary object from
`Adversary.run()` while writing an `adversary.review.v1` envelope to the runtime
output file. The returned object contains a `schema_version` value naming the
wire schema even though it is not that schema. Existing callers may depend on
that return shape, so changing it requires a staged migration.

The additive phase names the historical object `LegacyRunResult`, retains the
deprecated `Output` interface, and exposes `runLegacy()` as its durable
compatibility path. `run()` delegates to `runLegacy()` in this phase and
therefore has no runtime or declaration-shape break. The legacy
`schema_version` member is documented as a discriminator, not a claim that the
object is a wire document.

`createReviewEnvelope()` is the public canonical target. It converts visible
and suppressed legacy findings through the same evidence, recommendation, and
review normalization used by runtime output, constructs suppression counts,
controls suppressed-detail disclosure explicitly, and validates the resulting
`AdversaryRunEnvelope` before returning it. Canonical callers should use this
builder and the exported `AdversaryRunEnvelope`/`ReviewResult` types.

The migration sequence is:

1. Add the truthful legacy name, explicit legacy method, and canonical builder
   without changing `run()`.
2. Migrate `run()` and maintained consumers to the canonical envelope while
   callers that need the old object select `runLegacy()`.
3. After the documented compatibility window, remove the deprecated `Output`
   name and any conversion-only compatibility surface in a cleanup release.

Rollback of this additive phase removes only new names and the builder; it does
not change runtime files, schemas, manifests, or existing `run()` behavior.
Once a later phase changes the default return type, rollback must restore
`run()` and its declarations together while retaining `runLegacy()` for callers
that already migrated to the explicit path.
