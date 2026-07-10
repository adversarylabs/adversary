import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  Adversary,
  Finding,
  Severity,
  parseInput,
  validateReviewEnvelope,
} from "../dist/index.js";

test("shared review fixture satisfies SDK semantics", async () => {
  const fixture = new URL(
    "../../../../../schema/fixtures/adversary.review.v1.valid.json",
    import.meta.url,
  );
  const envelope = JSON.parse(await readFile(fixture, "utf8"));
  assert.doesNotThrow(() => validateReviewEnvelope(envelope));
  assert.equal(envelope.result.suppressedFindings.length, 1);
});

test("parseInput accepts the shared input fixture and rejects extensions", async () => {
  const fixture = new URL(
    "../../../../../schema/fixtures/adversary.input.v1.valid.json",
    import.meta.url,
  );
  const input = await parseInput(fixture.pathname);
  assert.equal(input.schema_version, "adversary.input.v1");

  const directory = await mkdtemp(join(tmpdir(), "adversary-sdk-input-"));
  try {
    const path = join(directory, "input.json");
    await writeFile(path, JSON.stringify({ ...input, extension: true }));
    await assert.rejects(parseInput(path), /unknown field/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("suppressed findings are counted and included only when requested", async () => {
  const directory = await mkdtemp(join(tmpdir(), "adversary-sdk-output-"));
  const previous = process.env.ADVERSARY_INCLUDE_SUPPRESSED;
  try {
    const app = new Adversary({ name: "local/suppression-test" });
    app.rule("suppressed.rule", () =>
      new Finding({
        ruleId: "suppressed.rule",
        severity: Severity.Low,
        title: "Suppressed example",
        message: "This finding is suppressed by policy.",
        suppressed: true,
      }),
    );

    const input = { source: { path: directory } };
    delete process.env.ADVERSARY_INCLUDE_SUPPRESSED;
    const hiddenPath = join(directory, "hidden.json");
    await app.run({ input, outputPath: hiddenPath });
    const hidden = JSON.parse(await readFile(hiddenPath, "utf8"));
    assert.equal(hidden.result.suppressed.findings, 1);
    assert.equal(hidden.result.suppressedFindings, undefined);

    process.env.ADVERSARY_INCLUDE_SUPPRESSED = "true";
    const includedPath = join(directory, "included.json");
    await app.run({ input, outputPath: includedPath });
    const included = JSON.parse(await readFile(includedPath, "utf8"));
    assert.equal(included.result.suppressed.findings, 1);
    assert.equal(included.result.suppressedFindings[0].ruleId, "suppressed.rule");
    assert.doesNotThrow(() => validateReviewEnvelope(included));
  } finally {
    if (previous === undefined) delete process.env.ADVERSARY_INCLUDE_SUPPRESSED;
    else process.env.ADVERSARY_INCLUDE_SUPPRESSED = previous;
    await rm(directory, { recursive: true, force: true });
  }
});

test("review validation rejects duplicate IDs and mismatched suppression counts", () => {
  const base = {
    protocolVersion: 1,
    result: {
      adversary: { name: "local/test" },
      target: {},
      positives: [],
      observations: [],
      findings: [],
      suppressed: { observations: 0, findings: 1 },
      suppressedFindings: [],
    },
  };
  assert.throws(() => validateReviewEnvelope(base), /length must equal/);
});
