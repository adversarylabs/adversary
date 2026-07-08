import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { dirname, isAbsolute, relative, resolve } from "node:path";
export const DEFAULT_INPUT_PATH = "/adversary/input.json";
export const DEFAULT_OUTPUT_PATH = "/adversary/output.json";
export const FINDINGS_SCHEMA_VERSION = "adversary.findings.v1";
const verboseValues = new Set(["1", "true", "TRUE", "yes", "YES"]);
export const Severity = {
    Info: "info",
    Low: "low",
    Medium: "medium",
    High: "high",
    Critical: "critical",
};
export const log = {
    debug(message) {
        if (isVerbose()) {
            writeLog("debug", message);
        }
    },
    info(message) {
        if (isVerbose()) {
            writeLog("info", message);
        }
    },
    warn(message) {
        writeLog("warn", message);
    },
    error(message) {
        writeLog("error", message);
    },
};
export class Finding {
    ruleId;
    id;
    severity;
    title;
    message;
    path;
    file;
    line;
    column;
    evidence;
    recommendation;
    metadata;
    constructor(init) {
        assertFindingInit(init);
        this.ruleId = init.ruleId;
        this.id = init.id ?? init.ruleId;
        this.severity = init.severity;
        this.title = init.title;
        this.message = init.message;
        this.path = init.path;
        this.file = init.file ?? init.path;
        this.line = init.line;
        this.column = init.column;
        this.evidence = init.evidence;
        this.recommendation = init.recommendation;
        this.metadata = init.metadata;
    }
    toJSON() {
        return omitUndefined({
            rule_id: this.ruleId,
            id: this.id,
            severity: this.severity,
            title: this.title,
            message: this.message,
            path: this.path,
            file: this.file,
            line: this.line,
            column: this.column,
            evidence: this.evidence,
            recommendation: this.recommendation,
            metadata: this.metadata,
        });
    }
}
export class Adversary {
    name;
    schemaVersion;
    rules = [];
    constructor(options) {
        if (options.name.length === 0) {
            throw new Error("Adversary name must be a non-empty string.");
        }
        if (options.schemaVersion !== undefined && options.schemaVersion !== FINDINGS_SCHEMA_VERSION) {
            throw new Error(`Unsupported schemaVersion "${options.schemaVersion}".`);
        }
        this.name = options.name;
        this.schemaVersion = options.schemaVersion ?? FINDINGS_SCHEMA_VERSION;
    }
    rule(id, handler) {
        if (id.length === 0) {
            throw new Error("Rule id must be a non-empty string.");
        }
        this.rules.push({ id, handler });
    }
    async run(options = {}) {
        const input = options.input ?? (await parseInput(options.inputPath));
        const repoPath = input.source.path;
        const summary = {};
        const cache = new Map();
        const context = createRuleContext(repoPath, summary, cache);
        const findings = [];
        for (const rule of this.rules) {
            log.debug(`running rule ${rule.id}`);
            const result = await rule.handler(context);
            findings.push(...normalizeRuleResult(result));
        }
        if (summary.rules_executed === undefined) {
            summary.rules_executed = this.rules.length;
        }
        const output = {
            schema_version: this.schemaVersion,
            adversary: this.name,
            summary,
            findings: sortFindings(findings),
        };
        if (options.write !== false) {
            await writeOutput(output, options.outputPath);
        }
        return output;
    }
}
export async function parseInput(path = DEFAULT_INPUT_PATH) {
    const raw = await readFile(path, "utf8");
    const parsed = JSON.parse(raw);
    if (!isRecord(parsed)) {
        throw new Error(`Invalid input at ${path}: expected an object.`);
    }
    if (!isRecord(parsed.source)) {
        throw new Error(`Invalid input at ${path}: source must be an object.`);
    }
    if (typeof parsed.source.path !== "string" || parsed.source.path.length === 0) {
        throw new Error(`Invalid input at ${path}: source.path must be a non-empty string.`);
    }
    return parsed;
}
export async function writeOutput(output, path = DEFAULT_OUTPUT_PATH) {
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, `${JSON.stringify(output, null, 2)}\n`, "utf8");
}
export function sortFindings(findings) {
    return [...findings].sort((left, right) => {
        const pathComparison = compareStrings(left.path ?? "", right.path ?? "");
        if (pathComparison !== 0) {
            return pathComparison;
        }
        const lineComparison = compareNumbers(left.line, right.line);
        if (lineComparison !== 0) {
            return lineComparison;
        }
        return compareStrings(left.rule_id, right.rule_id);
    });
}
function createRuleContext(repoPath, summary, cache) {
    const absoluteRepoPath = resolve(repoPath);
    return {
        repoPath: absoluteRepoPath,
        summary,
        cache,
        relpath(path) {
            return relative(absoluteRepoPath, isAbsolute(path) ? path : resolve(absoluteRepoPath, path));
        },
        glob(pattern) {
            return findMatchingPaths(absoluteRepoPath, pattern, false);
        },
        rglob(pattern) {
            return findMatchingPaths(absoluteRepoPath, pattern, true);
        },
    };
}
function normalizeRuleResult(result) {
    if (result === undefined || result === null) {
        return [];
    }
    const findings = Array.isArray(result) ? result : [result];
    return findings.map((item) => item.toJSON());
}
async function findMatchingPaths(repoPath, pattern, recursive) {
    const matcher = globPatternToRegExp(pattern);
    const paths = recursive ? await walk(repoPath) : await listFiles(repoPath);
    return paths
        .map((path) => relative(repoPath, path))
        .filter((path) => {
        const posixPath = toPosixPath(path);
        const candidate = recursive && !pattern.includes("/") ? basename(posixPath) : posixPath;
        return matcher.test(candidate);
    })
        .sort(compareStrings);
}
async function listFiles(directory) {
    const entries = await readdir(directory, { withFileTypes: true });
    return entries.filter((entry) => entry.isFile()).map((entry) => resolve(directory, entry.name));
}
async function walk(directory) {
    const entries = await readdir(directory, { withFileTypes: true });
    const paths = [];
    for (const entry of entries) {
        const path = resolve(directory, entry.name);
        if (entry.isDirectory()) {
            paths.push(...(await walk(path)));
        }
        else if (entry.isFile()) {
            paths.push(path);
        }
    }
    return paths;
}
function globPatternToRegExp(pattern) {
    const source = toPosixPath(pattern)
        .replace(/[.+^${}()|[\]\\]/g, "\\$&")
        .replace(/\*\*/g, "\0")
        .replace(/\*/g, "[^/]*")
        .replace(/\?/g, "[^/]")
        .replace(/\0/g, ".*");
    return new RegExp(`^${source}$`);
}
function assertFindingInit(value) {
    requireString(value.ruleId, "ruleId");
    requireString(value.title, "title");
    if (!isSeverity(value.severity)) {
        throw new Error("Finding severity must be one of Severity.Info, Low, Medium, High, Critical.");
    }
    optionalString(value.id, "id");
    optionalString(value.message, "message");
    optionalString(value.path, "path");
    optionalString(value.file, "file");
    optionalPositiveInteger(value.line, "line");
    optionalPositiveInteger(value.column, "column");
    optionalString(value.evidence, "evidence");
    optionalString(value.recommendation, "recommendation");
    if (value.metadata !== undefined && !isRecord(value.metadata)) {
        throw new Error("Finding metadata must be an object.");
    }
}
function writeLog(level, message) {
    process.stderr.write(`[adversary] ${level}: ${String(message)}\n`);
}
function isVerbose() {
    return verboseValues.has(process.env.ADVERSARY_VERBOSE ?? "");
}
function compareStrings(left, right) {
    return left.localeCompare(right);
}
function compareNumbers(left, right) {
    return (left ?? Number.MAX_SAFE_INTEGER) - (right ?? Number.MAX_SAFE_INTEGER);
}
function toPosixPath(path) {
    return path.replaceAll("\\", "/");
}
function basename(path) {
    return path.split("/").at(-1) ?? path;
}
function requireString(value, field) {
    if (typeof value !== "string" || value.length === 0) {
        throw new Error(`${field} must be a non-empty string.`);
    }
}
function optionalString(value, field) {
    if (value !== undefined && typeof value !== "string") {
        throw new Error(`${field} must be a string.`);
    }
}
function optionalPositiveInteger(value, field) {
    if (value !== undefined && (!Number.isInteger(value) || Number(value) < 1)) {
        throw new Error(`${field} must be a positive integer.`);
    }
}
function isSeverity(value) {
    return (value === Severity.Info ||
        value === Severity.Low ||
        value === Severity.Medium ||
        value === Severity.High ||
        value === Severity.Critical);
}
function isRecord(value) {
    return typeof value === "object" && value !== null && !Array.isArray(value);
}
function omitUndefined(value) {
    return Object.fromEntries(Object.entries(value).filter(([, entryValue]) => entryValue !== undefined));
}
//# sourceMappingURL=index.js.map