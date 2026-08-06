#!/usr/bin/env node

import { access } from "node:fs/promises";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { Adversary, Severity, log } from "@adversarylabs/sdk";

export function createApp(): Adversary {
  const app = new Adversary({
    name: "local/{{name}}",
  });

  app.rule("readme.exists", async (ctx) => {
    log.info("Checking for README.md...");

    const readmePath = join(ctx.repoPath, "README.md");
    if (await exists(readmePath)) {
      return;
    }

    log.info("README.md was not found.");
    ctx.finding({
      ruleId: "readme.exists",
      category: "docs",
      severity: Severity.Low,
      confidence: "high",
      title: "Repository is missing a README",
      summary: "Add a README.md so developers understand the project.",
      evidence: [{ file: "README.md", message: "README.md is missing at the repository root." }],
      recommendation: "Create a README.md with setup, usage, and testing instructions.",
    });
  });

  return app;
}

async function exists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

const app = createApp();
export default app;

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await app.runFromEnvironment();
}
