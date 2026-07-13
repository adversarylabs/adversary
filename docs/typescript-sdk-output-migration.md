# TypeScript SDK output migration (CLI-013)

The TypeScript SDK historically returns a rule-summary object from
`Adversary.run()` while writing an `adversary.review.v1` envelope to the runtime
output file. The returned object contains a `schema_version` value naming the
wire schema even though it is not that schema. Existing callers may depend on
that return shape, so changing it requires a staged migration.

The completed additive phase named the historical object `LegacyRunResult` and
introduced `runLegacy()` as an explicit compatibility path. The completed
migration phase makes `run()` return the canonical
`AdversaryRunEnvelope`; maintained callers use `result.findings`, `ruleId`, and
the other canonical fields. The legacy
`schema_version` member is documented as a discriminator, not a claim that the
object is a wire document.

`createReviewEnvelope()` is the public canonical target. It converts visible
and suppressed legacy findings through the same evidence, recommendation, and
review normalization used by runtime output, constructs suppression counts,
controls suppressed-detail disclosure explicitly, and validates the resulting
`AdversaryRunEnvelope` before returning it. Canonical callers should use this
builder and the exported `AdversaryRunEnvelope`/`ReviewResult` types.
This builder requires legacy objects to carry exactly
`schema_version: "adversary.review.v1"` before conversion. Missing, non-string,
and unsupported discriminators are rejected rather than silently rewritten.
`writeOutput()` is canonical-only and rejects legacy objects; conversion must
always be explicit.

The migration sequence is:

1. **Complete:** add the truthful legacy name, explicit legacy method, and
   canonical builder without changing `run()`.
2. **Complete:** migrate `run()` and maintained consumers to the canonical
   envelope while callers that need the old object select `runLegacy()`.
3. **Complete:** remove the ambiguous `Output` alias, configurable legacy
   discriminator, and implicit conversion in `writeOutput()`. The legacy sorter
   is explicitly named `sortLegacyFindings()`.

`LegacyRunResult`, `runLegacy()`, `createReviewEnvelope()`, and
`sortLegacyFindings()` remain for one released compatibility cycle and through
the current major version. They become eligible for removal in the next major
version after callers have had at least one release with canonical `run()` as
the default. No default or write API accepts the legacy shape.

Rollback of cleanup restores the `Output` alias and legacy `writeOutput()`
conversion together, plus the old sorter name and `schemaVersion` option if a
released caller requires them. It does not revert canonical `run()` or the
maintained consumer migration; those remain independently reversible through
the preceding migration phase.
