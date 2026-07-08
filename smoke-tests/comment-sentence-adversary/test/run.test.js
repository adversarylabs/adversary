import assert from "node:assert/strict";
import { cp, mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { createApp, findComments, looksLikeSentence } from "../dist/run.js";

test("finds line comments and ignores markers inside strings", () => {
  const comments = findComments([
    "const url = 'https://example.test';",
    "// fix later",
    'const text = "# not a comment";',
    "# cleanup",
  ].join("\n"));

  assert.deepEqual(comments, [
    { text: "fix later", evidence: "// fix later", line: 2 },
    { text: "cleanup", evidence: "# cleanup", line: 4 },
  ]);
});

test("classifies comments with simple sentence heuristics", () => {
  assert.equal(looksLikeSentence("fix later"), false);
  assert.equal(looksLikeSentence("temporary"), false);
  assert.equal(looksLikeSentence("This comment is a complete sentence."), true);
  assert.equal(looksLikeSentence("This comment is missing punctuation"), false);
  assert.equal(looksLikeSentence("this comment starts lowercase."), false);
});

test("reports expected findings from fixtures", async () => {
  const repo = await mkdtemp(join(tmpdir(), "comment-sentence-fixtures-"));
  await cp(new URL("fixtures", import.meta.url), repo, { recursive: true });

  const output = await createApp().run({
    input: { source: { path: repo } },
    write: false,
  });

  assert.equal(output.summary.files_scanned, 2);
  assert.equal(output.summary.rules_executed, 1);
  assert.deepEqual(
    output.findings.map((finding) => `${finding.path}:${finding.line}:${finding.evidence}`),
    [
      "bad.ts:1:// fix later",
      "bad.ts:4:// temporary",
      "bad.ts:7:// maybe",
    ],
  );
});

test("ignores generated and dependency directories", async () => {
  const repo = await mkdtemp(join(tmpdir(), "comment-sentence-ignore-"));
  await writeFile(join(repo, "index.ts"), "// fix later\n");
  await writeFile(join(repo, "README.md"), "// fix later\n");
  await mkdir(join(repo, "dist"), { recursive: true });
  await mkdir(join(repo, "node_modules"), { recursive: true });
  await writeFile(join(repo, "dist", "generated.ts"), "// fix later\n");
  await writeFile(join(repo, "node_modules", "dep.ts"), "// fix later\n");

  const output = await createApp().run({
    input: { source: { path: repo } },
    write: false,
  });

  assert.equal(output.summary.files_scanned, 1);
  assert.deepEqual(output.findings.map((finding) => finding.path), ["index.ts"]);
});
