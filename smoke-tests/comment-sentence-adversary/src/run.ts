#!/usr/bin/env node

import { readdir, readFile } from "node:fs/promises";
import { extname, join, relative } from "node:path";
import { Adversary, Finding, Severity, log, type RuleContext } from "@adversary/sdk";

type SourceFile = {
  path: string;
  relPath: string;
  comments: Comment[];
};

type Comment = {
  text: string;
  evidence: string;
  line: number;
};

const sourceExtensions = new Set([".ts", ".tsx", ".js", ".jsx", ".go", ".py"]);
const ignoredDirectories = new Set(["node_modules", "vendor", "dist", "build", ".git"]);
const sourceFilesCacheKey = "comment-sentence.source-files";
const commentPrefixPattern = new RegExp("^(//|#)\\s*");

export function createApp(): Adversary {
  const app = new Adversary({
    name: "smoke-tests/comment-sentence",
  });

  app.rule("comments.full-sentence", async (ctx) => {
    log.info("Scanning repository...");
    const files = await getSourceFiles(ctx);
    ctx.summary.files_scanned = files.length;

    const findings: Finding[] = [];
    for (const file of files) {
      log.info(`Scanning ${file.relPath}...`);
      for (const comment of file.comments) {
        if (looksLikeSentence(comment.text)) {
          continue;
        }
        log.info(`Found incomplete comment on line ${comment.line}`);
        findings.push(
          new Finding({
            ruleId: "comments.full-sentence",
            id: `comments.full-sentence:${file.relPath}:${comment.line}`,
            severity: Severity.Low,
            title: "Comment is not a complete sentence",
            message: "Consider rewriting comments as complete sentences.",
            path: file.relPath,
            line: comment.line,
            evidence: comment.evidence,
            recommendation: "Rewrite the comment as a complete sentence ending with punctuation.",
          }),
        );
      }
    }

    log.info("Finished.");
    return findings;
  });

  return app;
}

export async function getSourceFiles(ctx: RuleContext): Promise<SourceFile[]> {
  const cached = ctx.cache.get(sourceFilesCacheKey);
  if (cached !== undefined) {
    return cached as SourceFile[];
  }

  const files: SourceFile[] = [];
  for (const path of await walkSourceFiles(ctx.repoPath)) {
    const comments = findComments(await readFile(path, "utf8"));
    if (comments.length === 0) {
      continue;
    }
    files.push({
      path,
      relPath: toPosix(relative(ctx.repoPath, path)),
      comments,
    });
  }
  files.sort((left, right) => left.relPath.localeCompare(right.relPath));
  ctx.cache.set(sourceFilesCacheKey, files);
  return files;
}

async function walkSourceFiles(directory: string): Promise<string[]> {
  const entries = await readdir(directory, { withFileTypes: true });
  const files: string[] = [];

  for (const entry of entries) {
    if (entry.isDirectory()) {
      if (!ignoredDirectories.has(entry.name)) {
        files.push(...(await walkSourceFiles(join(directory, entry.name))));
      }
      continue;
    }
    if (entry.isFile() && sourceExtensions.has(extname(entry.name))) {
      files.push(join(directory, entry.name));
    }
  }

  return files;
}

export function findComments(contents: string): Comment[] {
  const comments: Comment[] = [];
  const lines = contents.split(/\r?\n/);

  for (const [index, line] of lines.entries()) {
    const marker = findCommentMarker(line);
    if (marker === undefined) {
      continue;
    }
    const evidence = line.slice(marker).trim();
    const text = evidence.replace(commentPrefixPattern, "").trim();
    if (text.length === 0 || text.startsWith("!")) {
      continue;
    }
    comments.push({
      text,
      evidence,
      line: index + 1,
    });
  }

  return comments;
}

function findCommentMarker(line: string): number | undefined {
  let inSingle = false;
  let inDouble = false;
  let escaped = false;

  for (let index = 0; index < line.length; index += 1) {
    const char = line[index];
    const next = line[index + 1];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (char === "\\") {
      escaped = true;
      continue;
    }
    if (char === "'" && !inDouble) {
      inSingle = !inSingle;
      continue;
    }
    if (char === '"' && !inSingle) {
      inDouble = !inDouble;
      continue;
    }
    if (!inSingle && !inDouble && char === "/" && next === "/") {
      return index;
    }
    if (!inSingle && !inDouble && char === "#") {
      return index;
    }
  }

  return undefined;
}

export function looksLikeSentence(comment: string): boolean {
  if (comment.length < 24) {
    return false;
  }
  if (/^[a-z]/.test(comment)) {
    return false;
  }
  return /[.!?]$/.test(comment);
}

function toPosix(path: string): string {
  return path.replaceAll("\\", "/");
}

if (process.argv[1] !== undefined && import.meta.url === new URL(process.argv[1], "file:").href) {
  await createApp().run();
}
