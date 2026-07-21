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
  parseDetectionContext,
  parseInput,
  sortLegacyFindings,
  validateErrorEnvelope,
  validateReviewEnvelope,
  validateDetectionResult,
  writeDetectionResult,
  writeOutput,
} from "../dist/index.js";

test("run returns and writes the same canonical envelope after one rule execution", async () => {
  const directory = await mkdtemp(join(tmpdir(), "adversary-sdk-run-"));
  const outputPath = join(directory, "output.json");
  const noWritePath = join(directory, "not-written.json");
  let executions = 0;
  const app = new Adversary({ name: "local/additive-test" });
  app.rule("additive.rule", () => {
    executions += 1;
    return new Finding({
      ruleId: "additive.rule",
      severity: Severity.Low,
      title: "Additive finding",
      evidence: "matched source",
    });
  });
  try {
    const current = await app.run({
      input: { source: { path: "/workspace" } },
      outputPath,
    });
    assert.equal(executions, 1);
    assert.doesNotThrow(() => validateReviewEnvelope(current));
    assert.deepEqual(current, JSON.parse(await readFile(outputPath, "utf8")));

    const notWritten = await app.run({
      input: { source: { path: "/workspace" } },
      outputPath: noWritePath,
      write: false,
    });
    assert.equal(executions, 2);
    assert.doesNotThrow(() => validateReviewEnvelope(notWritten));
    await assert.rejects(readFile(noWritePath), /ENOENT/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("runLegacy preserves its return shape while writing a canonical envelope", async () => {
  const directory = await mkdtemp(join(tmpdir(), "adversary-sdk-legacy-"));
  const outputPath = join(directory, "output.json");
  let executions = 0;
  const app = new Adversary({ name: "local/legacy-test" });
  app.rule("legacy.rule", () => {
    executions += 1;
    return new Finding({
      ruleId: "legacy.rule",
      severity: Severity.Low,
      title: "Legacy finding",
    });
  });
  try {
    const legacy = await app.runLegacy({ input: { source: { path: directory } }, outputPath });
    assert.equal(executions, 1);
    assert.equal(legacy.schema_version, "adversary.review.v1");
    assert.equal(legacy.findings[0].rule_id, "legacy.rule");
    assert.equal(legacy.protocolVersion, undefined);
    const written = JSON.parse(await readFile(outputPath, "utf8"));
    assert.doesNotThrow(() => validateReviewEnvelope(written));
    assert.equal(written.result.findings[0].ruleId, "legacy.rule");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
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
    { file: "src/index.ts", line: 7, message: "matched source" },
  ]);
  assert.equal(envelope.result.suppressed.findings, 1);
  assert.equal(envelope.result.suppressedFindings[0].id, "suppressed");
  const defaultTarget = createReviewEnvelope({
    schema_version: "adversary.review.v1",
    adversary: "local/default-target",
    summary: {},
    findings: [],
  });
  assert.equal(defaultTarget.result.target.repository, "/workspace");
});

test("run preserves environment-over-input repository precedence in return and output", async () => {
  const directory = await mkdtemp(join(tmpdir(), "adversary-sdk-repo-"));
  const previous = process.env.ADVERSARY_REPO;
  const app = new Adversary({ name: "local/repo-test" });
  try {
    delete process.env.ADVERSARY_REPO;
    const inputPath = join(directory, "input-target");
    const inputOutput = join(directory, "input.json");
    const fromInput = await app.run({ input: { source: { path: inputPath } }, outputPath: inputOutput });
    assert.equal(fromInput.result.target.repository, inputPath);
    assert.equal(JSON.parse(await readFile(inputOutput, "utf8")).result.target.repository, inputPath);

    const environmentPath = join(directory, "environment-target");
    process.env.ADVERSARY_REPO = environmentPath;
    const environmentOutput = join(directory, "environment.json");
    const fromEnvironment = await app.run({
      input: { source: { path: inputPath } },
      outputPath: environmentOutput,
    });
    assert.equal(fromEnvironment.result.target.repository, environmentPath);
    assert.equal(
      JSON.parse(await readFile(environmentOutput, "utf8")).result.target.repository,
      environmentPath,
    );
  } finally {
    if (previous === undefined) delete process.env.ADVERSARY_REPO;
    else process.env.ADVERSARY_REPO = previous;
    await rm(directory, { recursive: true, force: true });
  }
});

test("canonical builder strictly validates the legacy schema discriminator", () => {
  const base = {
    adversary: "local/additive-test",
    summary: {},
    findings: [],
  };
  assert.doesNotThrow(() =>
    createReviewEnvelope({ ...base, schema_version: "adversary.review.v1" }),
  );
  assert.throws(
    () => createReviewEnvelope({ ...base, schema_version: "adversary.review.v2" }),
    /Unsupported legacy run result schema_version "adversary\.review\.v2"; expected "adversary\.review\.v1"/,
  );
  assert.throws(
    () => createReviewEnvelope(base),
    /schema_version must be the string "adversary\.review\.v1"/,
  );
  assert.throws(
    () => createReviewEnvelope({ ...base, schema_version: 1 }),
    /schema_version must be the string "adversary\.review\.v1"/,
  );
});

test("writeOutput accepts canonical envelopes and rejects legacy objects", async () => {
  const directory = await mkdtemp(join(tmpdir(), "adversary-sdk-output-"));
  const outputPath = join(directory, "output.json");
  const legacy = {
    schema_version: "adversary.review.v1",
    adversary: "local/cleanup-test",
    summary: {},
    findings: [],
  };
  try {
    const envelope = createReviewEnvelope(legacy);
    await writeOutput(envelope, outputPath);
    assert.deepEqual(JSON.parse(await readFile(outputPath, "utf8")), envelope);
    await assert.rejects(
      writeOutput(legacy, outputPath),
      /envelope/,
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("declarations expose only explicit canonical and legacy paths", async () => {
  const declarations = await readFile(new URL("../dist/index.d.ts", import.meta.url), "utf8");
  assert.match(declarations, /interface LegacyRunResult/);
  assert.doesNotMatch(declarations, /interface Output\b/);
  assert.doesNotMatch(declarations, /readonly schemaVersion|schemaVersion\?:/);
  assert.match(declarations, /run\(options\?: RunOptions\): Promise<AdversaryRunEnvelope>/);
  assert.match(declarations, /runLegacy\(options\?: RunOptions\): Promise<LegacyRunResult>/);
  assert.match(declarations, /writeOutput\(output: AdversaryRunEnvelope/);
  assert.match(declarations, /createReviewEnvelope\(output: LegacyRunResult/);
  assert.match(declarations, /sortLegacyFindings\(findings: SerializedFinding/);
  assert.doesNotMatch(declarations, /sortFindings\(/);
  assert.equal("schemaVersion" in new Adversary({ name: "local/cleanup-test" }), false);
});

test("sortLegacyFindings explicitly sorts serialized legacy findings", () => {
  const finding = (rule_id, path, line) => ({
    rule_id,
    id: `${rule_id}:${path}:${line}`,
    severity: Severity.Low,
    title: rule_id,
    path,
    line,
  });
  const findings = [
    finding("z.rule", "b.ts", 1),
    finding("z.rule", "a.ts", 2),
    finding("a.rule", "a.ts", 2),
  ];
  assert.deepEqual(
    sortLegacyFindings(findings).map(({ id }) => id),
    ["a.rule:a.ts:2", "z.rule:a.ts:2", "z.rule:b.ts:1"],
  );
  assert.equal(findings[0].id, "z.rule:b.ts:1");
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

test("detection context and result use the strict shared contract", async () => {
  const directory = await mkdtemp(join(tmpdir(), "adversary-sdk-detection-"));
  try {
    const inputPath = join(directory, "input.json");
    const outputPath = join(directory, "output.json");
    const context = {
      schemaVersion: "adversary.detection.v1",
      repositoryRoot: "/workspace",
      mode: "dirty-worktree",
      changedFiles: [{ path: "Dockerfile", status: "modified" }],
    };
    await writeFile(inputPath, JSON.stringify(context));
    assert.deepEqual(await parseDetectionContext(inputPath), context);
    const result = {
      schemaVersion: "adversary.detection.v1",
      applicable: true,
      confidence: "high",
      reasons: ["Dockerfile changed"],
      relevantFiles: ["Dockerfile"],
    };
    validateDetectionResult(result);
    await writeDetectionResult(result, outputPath);
    assert.deepEqual(JSON.parse(await readFile(outputPath, "utf8")), result);
    await writeFile(inputPath, JSON.stringify({ ...context, findings: [] }));
    await assert.rejects(parseDetectionContext(inputPath), /unknown field/);
    assert.throws(() => validateDetectionResult({ ...result, findings: [] }), /unknown field/);
    assert.throws(() => validateDetectionResult({ ...result, reasons: ["match\nforged"] }), /control/);
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
    const hiddenReturn = await app.run({ input, outputPath: hiddenPath });
    const hidden = JSON.parse(await readFile(hiddenPath, "utf8"));
    assert.deepEqual(hiddenReturn, hidden);
    assert.equal(hidden.result.suppressed.findings, 1);
    assert.equal(hidden.result.suppressedFindings, undefined);

    process.env.ADVERSARY_INCLUDE_SUPPRESSED = "true";
    const includedPath = join(directory, "included.json");
    const includedReturn = await app.run({ input, outputPath: includedPath });
    const included = JSON.parse(await readFile(includedPath, "utf8"));
    assert.deepEqual(includedReturn, included);
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
