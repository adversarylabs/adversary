import assert from "node:assert/strict";
import test from "node:test";
import { createApp } from "../src/index.ts";

test("clean fixture produces no findings", async () => {
  const result = await createApp().run({
    input: { source: { path: new URL("../fixtures/clean", import.meta.url).pathname } },
  });

  assert.equal(result.findings.length, 0);
});

test("vulnerable fixture produces one finding", async () => {
  const result = await createApp().run({
    input: { source: { path: new URL("../fixtures/vulnerable", import.meta.url).pathname } },
  });

  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].ruleId, "readme.exists");
});
