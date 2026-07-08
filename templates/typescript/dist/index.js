#!/usr/bin/env node
import { access } from "node:fs/promises";
import { join } from "node:path";
import { Adversary, Finding, Severity, log } from "@adversary/sdk";
export function createApp() {
    const app = new Adversary({
        name: "local/{{name}}",
    });
    app.rule("readme.exists", async (ctx) => {
        log.info("Checking for README.md...");
        const readmePath = join(ctx.repoPath, "README.md");
        if (await exists(readmePath)) {
            return [];
        }
        log.info("README.md was not found.");
        return new Finding({
            ruleId: "readme.exists",
            severity: Severity.Low,
            title: "Repository is missing a README",
            message: "Add a README.md so developers understand the project.",
            path: "README.md",
            recommendation: "Create a README.md with setup, usage, and testing instructions.",
        });
    });
    return app;
}
async function exists(path) {
    try {
        await access(path);
        return true;
    }
    catch {
        return false;
    }
}
if (process.argv[1] !== undefined && import.meta.url === new URL(process.argv[1], "file:").href) {
    await createApp().run();
}
