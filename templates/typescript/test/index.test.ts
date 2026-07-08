import assert from "node:assert/strict";
import test from "node:test";
import { createApp } from "../src/index.ts";

test("clean fixture produces no findings", async () => {
  const output = await createApp().run({
    input: { source: { path: new URL("../fixtures/clean", import.meta.url).pathname } },
    write: false,
  });

  assert.equal(output.summary.rules_executed, 1);
  assert.equal(output.findings.length, 0);
});

test("vulnerable fixture produces one finding", async () => {
  const output = await createApp().run({
    input: { source: { path: new URL("../fixtures/vulnerable", import.meta.url).pathname } },
    write: false,
  });

  assert.equal(output.summary.rules_executed, 1);
  assert.equal(output.findings.length, 1);
  assert.equal(output.findings[0].rule_id, "readme.exists");
});
