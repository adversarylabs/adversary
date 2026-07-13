import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  Adversary,
  Finding,
  Severity,
  createReviewEnvelope,
  encodeErrorEnvelope,
  parseInput,
  validateErrorEnvelope,
  validateReviewEnvelope,
} from "../dist/index.js";

test("run remains legacy while runLegacy provides the explicit migration path", async () => {
  const app = new Adversary({ name: "local/additive-test" });
  app.rule("additive.rule", () =>
    new Finding({
      ruleId: "additive.rule",
      severity: Severity.Low,
      title: "Additive finding",
    }),
  );
  const options = { input: { source: { path: "/workspace" } }, write: false };
  const current = await app.run(options);
  const explicitLegacy = await app.runLegacy(options);
  assert.deepEqual(current, explicitLegacy);
  assert.equal(current.schema_version, "adversary.review.v1");
  assert.equal(current.protocolVersion, undefined);
  assert.equal(current.result, undefined);
});

test("canonical builder converts legacy findings, evidence, and suppression", () => {
  const envelope = createReviewEnvelope(
    {
      schema_version: "adversary.review.v1",
      adversary: "local/additive-test",
      summary: { files_scanned: 2 },
      findings: [
        {
          rule_id: "visible.rule",
          id: "visible",
          severity: Severity.High,
          title: "Visible finding",
          message: "Visible summary",
          file: "src/index.ts",
          line: 7,
          evidence: "matched source",
        },
        {
          rule_id: "suppressed.rule",
          id: "suppressed",
          severity: Severity.Low,
          title: "Suppressed finding",
          message: "Suppressed summary",
          suppressed: true,
        },
      ],
    },
    { repoPath: "/workspace", includeSuppressed: true },
  );
  assert.doesNotThrow(() => validateReviewEnvelope(envelope));
  assert.equal(envelope.protocolVersion, 1);
  assert.equal(envelope.result.target.repository, "/workspace");
  assert.equal(envelope.result.target.filesScanned, 2);
  assert.equal(envelope.result.findings[0].summary, "Visible summary");
  assert.deepEqual(envelope.result.findings[0].evidence, [
    { file: "src/index.ts", line: 7, message: "matched source", metadata: undefined },
  ]);
  assert.equal(envelope.result.suppressed.findings, 1);
  assert.equal(envelope.result.suppressedFindings[0].id, "suppressed");
});

test("declarations expose canonical target and deprecated legacy compatibility", async () => {
  const declarations = await readFile(new URL("../dist/index.d.ts", import.meta.url), "utf8");
  assert.match(declarations, /interface LegacyRunResult/);
  assert.match(declarations, /@deprecated Use LegacyRunResult/);
  assert.match(declarations, /runLegacy\(options\?: RunOptions\): Promise<LegacyRunResult>/);
  assert.match(declarations, /createReviewEnvelope\(output: LegacyRunResult/);
});

test("shared error fixture has deterministic encoding and rejects newer versions", async () => {
  const fixture = new URL(
    "../../../../../schema/fixtures/adversary.error.v1.valid.json",
    import.meta.url,
  );
  const envelope = JSON.parse(await readFile(fixture, "utf8"));
  assert.doesNotThrow(() => validateErrorEnvelope(envelope));
  assert.equal(
    encodeErrorEnvelope(envelope),
    '{"error":{"code":"invalid_manifest","details":{"field":"runtime.version"},"message":"runtime.version is not a valid constraint","retryable":false},"protocolVersion":1}\n',
  );
  assert.throws(() => validateErrorEnvelope({ ...envelope, protocolVersion: 2 }), /Unsupported/);
});

test("shared invalid error fixtures are rejected", async () => {
  const fixture = new URL(
    "../../../../../schema/fixtures/adversary.error.v1.invalid.json",
    import.meta.url,
  );
  for (const entry of JSON.parse(await readFile(fixture, "utf8"))) {
    assert.throws(() => validateErrorEnvelope(entry.envelope), undefined, entry.name);
  }
});

test("shared review fixture satisfies SDK semantics", async () => {
  const fixture = new URL(
    "../../../../../schema/fixtures/adversary.review.v1.valid.json",
    import.meta.url,
  );
  const envelope = JSON.parse(await readFile(fixture, "utf8"));
  assert.doesNotThrow(() => validateReviewEnvelope(envelope));
  assert.equal(envelope.result.suppressedFindings.length, 1);
});

test("review validation and encoding preserve shared producer order", async () => {
  const fixture = new URL(
    "../../../../../schema/fixtures/adversary.review.v1.order.json",
    import.meta.url,
  );
  const expected = (await readFile(fixture, "utf8")).trim();
  const envelope = JSON.parse(expected);
  validateReviewEnvelope(envelope);
  assert.equal(JSON.stringify(envelope), expected);
  assert.deepEqual(envelope.result.findings.map(({ id }) => id), ["z", "a"]);
  assert.deepEqual(envelope.result.suppressedFindings.map(({ id }) => id), ["y", "b"]);
});

test("shared adversarial review fixtures are rejected", async () => {
  const fixture = new URL(
    "../../../../../schema/fixtures/adversary.review.v1.invalid.json",
    import.meta.url,
  );
  const cases = JSON.parse(await readFile(fixture, "utf8"));
  for (const entry of cases) {
    assert.throws(
      () => validateReviewEnvelope(entry.envelope),
      undefined,
      entry.name,
    );
  }
});

test("review validation covers optional object constraint families", () => {
  const envelope = () => ({
    protocolVersion: 1,
    result: {
      adversary: { name: "local/test" },
      target: {},
      positives: [],
      observations: [],
      findings: [],
      suppressed: { observations: 0, findings: 0 },
    },
  });
  const invalid = [
    (value) => { value.result.target.filesScanned = -1; },
    (value) => { value.result.assessment = { risk: "urgent" }; },
    (value) => { value.result.opinion = { summary: "ok", ship: "yes" }; },
    (value) => { value.result.timing = { totalMs: 1.5 }; },
    (value) => { value.result.positives = [{ key: "x", summary: "x", metadata: [] }]; },
    (value) => { value.result.findings = [{ id: "x", title: "x", category: "x", severity: "low", confidence: "high", summary: "x", evidence: [], remediation: { estimate: 1 } }]; },
  ];
  for (const mutate of invalid) {
    const value = envelope();
    mutate(value);
    assert.throws(() => validateReviewEnvelope(value));
  }
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
