import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { dirname, isAbsolute, relative, resolve } from "node:path";
export const DEFAULT_INPUT_PATH = "/adversary/input.json";
export const DEFAULT_OUTPUT_PATH = "/adversary/output.json";
export const DEFAULT_REPO_PATH = "/workspace";
export const INPUT_SCHEMA_VERSION = "adversary.input.v1";
export const REVIEW_SCHEMA_VERSION = "adversary.review.v1";
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
    suppressed;
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
        this.suppressed = init.suppressed;
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
            suppressed: this.suppressed,
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
        if (options.schemaVersion !== undefined && options.schemaVersion !== REVIEW_SCHEMA_VERSION) {
            throw new Error(`Unsupported schemaVersion "${options.schemaVersion}".`);
        }
        this.name = options.name;
        this.schemaVersion = options.schemaVersion ?? REVIEW_SCHEMA_VERSION;
    }
    rule(id, handler) {
        if (id.length === 0) {
            throw new Error("Rule id must be a non-empty string.");
        }
        this.rules.push({ id, handler });
    }
    async run(options = {}) {
        const input = options.input === undefined ? await parseInput(options.inputPath) : normalizeRuntimeInput(options.input);
        const repoPath = process.env.ADVERSARY_REPO ?? input.source.path ?? DEFAULT_REPO_PATH;
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
        const suppressedFindings = findings.filter((finding) => finding.suppressed === true);
        const output = {
            schema_version: this.schemaVersion,
            adversary: this.name,
            summary,
            findings: sortFindings(findings.filter((finding) => finding.suppressed !== true)).map(stripSuppressed),
        };
        if (options.write !== false) {
            await writeOutput(createAdversaryRunEnvelope(output, repoPath, suppressedFindings), options.outputPath);
        }
        return output;
    }
}
export async function parseInput(path = process.env.ADVERSARY_INPUT ?? DEFAULT_INPUT_PATH) {
    const raw = await readFile(path, "utf8");
    const parsed = JSON.parse(raw);
    try {
        return validateRuntimeInput(parsed);
    }
    catch (error) {
        throw new Error(`Invalid input at ${path}: ${error.message}`);
    }
}
export async function writeOutput(output, path = process.env.ADVERSARY_OUTPUT ?? DEFAULT_OUTPUT_PATH) {
    const envelope = isRunEnvelope(output)
        ? output
        : createAdversaryRunEnvelope(output, process.env.ADVERSARY_REPO ?? DEFAULT_REPO_PATH, []);
    validateReviewEnvelope(envelope);
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, `${JSON.stringify(envelope, null, 2)}\n`, "utf8");
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
    if (value.suppressed !== undefined && typeof value.suppressed !== "boolean") {
        throw new Error("Finding suppressed must be a boolean.");
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
function stripSuppressed(finding) {
    const { suppressed: _suppressed, ...serialized } = finding;
    return serialized;
}
function createAdversaryRunEnvelope(output, repoPath, suppressedFindings) {
    return {
        protocolVersion: 1,
        result: normalizeReviewResult(output, repoPath, suppressedFindings),
    };
}
function normalizeReviewResult(output, repoPath, suppressedFindings = []) {
    const summary = output.summary ?? {};
    const normalizedSuppressed = sortFindings(suppressedFindings).map((finding) => normalizeReviewFinding(stripSuppressed(finding)));
    const includeSuppressed = verboseValues.has(process.env.ADVERSARY_INCLUDE_SUPPRESSED ?? "");
    return omitUndefined({
        adversary: normalizeAdversary(output.adversary),
        target: omitUndefined({
            repository: repoPath,
            filesScanned: summary.files_scanned ?? summary.filesScanned,
        }),
        positives: [],
        observations: [],
        findings: Array.isArray(output.findings) ? output.findings.map(normalizeReviewFinding) : [],
        suppressed: { observations: 0, findings: normalizedSuppressed.length },
        suppressedFindings: includeSuppressed && normalizedSuppressed.length > 0 ? normalizedSuppressed : undefined,
    });
}
function normalizeAdversary(value) {
    if (typeof value === "object" && value !== null) {
        return value;
    }
    return { name: String(value ?? "adversary") };
}
function normalizeReviewFinding(finding) {
    return omitUndefined({
        id: finding.id ?? finding.rule_id ?? finding.ruleId ?? finding.title,
        ruleId: finding.ruleId ?? finding.rule_id,
        title: finding.title,
        category: finding.category ?? "general",
        severity: finding.severity,
        confidence: finding.confidence ?? "medium",
        summary: finding.summary ?? finding.message ?? finding.title,
        whyItMatters: finding.whyItMatters ?? finding.why_it_matters,
        impact: finding.impact,
        evidence: normalizeReviewEvidence(finding.evidence, finding.file ?? finding.path, finding.line),
        recommendation: normalizeRecommendation(finding.recommendation),
        remediation: finding.remediation,
        tags: finding.tags,
        metadata: finding.metadata,
    });
}
function normalizeReviewEvidence(evidence, file, line) {
    if (Array.isArray(evidence)) {
        return evidence.map((item) => normalizeEvidenceItem(item));
    }
    if (file !== undefined || line !== undefined || evidence !== undefined) {
        return [normalizeEvidenceItem({ file, line, message: typeof evidence === "string" ? evidence : undefined, metadata: typeof evidence === "object" ? evidence : undefined })];
    }
    return [];
}
function normalizeEvidenceItem(item) {
    if (item?.file !== undefined || item?.message !== undefined || item?.snippet !== undefined) {
        return item;
    }
    const location = item?.location ?? {};
    const data = item?.data ?? item?.evidence ?? {};
    return omitUndefined({
        file: location.file,
        line: location.line,
        endLine: location.endLine ?? location.end_line,
        message: typeof data.stage === "string" ? `${data.stage} stage` : item?.message,
        snippet: typeof data.instruction === "string" ? data.instruction : item?.snippet,
        metadata: Object.keys(data).length > 0 ? data : undefined,
    });
}
function normalizeRecommendation(value) {
    if (typeof value === "string") {
        return value;
    }
    if (value !== undefined && value !== null) {
        return [value.summary, value.details].filter((item) => typeof item === "string" && item.length > 0).join("\n\n");
    }
    return undefined;
}
function normalizeRuntimeInput(value) {
    return validateRuntimeInput({ schema_version: INPUT_SCHEMA_VERSION, change: null, ...value });
}
function validateRuntimeInput(value) {
    requireExactKeys(value, ["schema_version", "source", "change"], "input");
    if (value.schema_version !== INPUT_SCHEMA_VERSION) {
        throw new Error(`schema_version must be "${INPUT_SCHEMA_VERSION}".`);
    }
    requireExactKeys(value.source, ["path"], "source");
    requireString(value.source.path, "source.path");
    if (value.change !== null) {
        requireExactKeys(value.change, ["type", "base_ref", "head_ref", "scan_mode", "changed_files"], "change");
        if (value.change.type !== "diff") {
            throw new Error('change.type must be "diff".');
        }
        requireString(value.change.base_ref, "change.base_ref");
        requireString(value.change.head_ref, "change.head_ref");
        if (value.change.scan_mode !== "changed" && value.change.scan_mode !== "all") {
            throw new Error('change.scan_mode must be "changed" or "all".');
        }
        if (!Array.isArray(value.change.changed_files) || value.change.changed_files.some((path) => typeof path !== "string" || path.length === 0)) {
            throw new Error("change.changed_files must contain only non-empty strings.");
        }
        if (new Set(value.change.changed_files).size !== value.change.changed_files.length) {
            throw new Error("change.changed_files must not contain duplicates.");
        }
    }
    return value;
}
function requireExactKeys(value, keys, field) {
    if (!isRecord(value)) {
        throw new Error(`${field} must be an object.`);
    }
    const expected = new Set(keys);
    const unknown = Object.keys(value).filter((key) => !expected.has(key));
    if (unknown.length > 0) {
        throw new Error(`${field} contains unknown field "${unknown[0]}".`);
    }
    for (const key of keys) {
        if (!(key in value)) {
            throw new Error(`${field}.${key} is required.`);
        }
    }
}
function isRunEnvelope(value) {
    return isRecord(value) && "protocolVersion" in value;
}
export function validateReviewEnvelope(value) {
    requireExactKeys(value, ["protocolVersion", "result"], "envelope");
    if (value.protocolVersion !== 1) {
        throw new Error("envelope.protocolVersion must be 1.");
    }
    const result = value.result;
    if (!isRecord(result)) {
        throw new Error("envelope.result must be an object.");
    }
    requireExactKeys(result, ["adversary", "target", "assessment", "positives", "observations", "findings", "opinion", "suppressed", "timing", "suppressedFindings", "rawObservations"].filter((key) => key in result || ["adversary", "target", "positives", "observations", "findings", "suppressed"].includes(key)), "result");
    requireExactKeys(result.adversary, ["name", "version"].filter((key) => key in result.adversary || key === "name"), "result.adversary");
    requireString(result.adversary.name, "result.adversary.name");
    if (!isRecord(result.target)) {
        throw new Error("result.target must be an object.");
    }
    for (const field of ["positives", "observations", "findings"]) {
        if (!Array.isArray(result[field])) {
            throw new Error(`result.${field} must be an array.`);
        }
    }
    requireExactKeys(result.suppressed, ["observations", "findings"], "result.suppressed");
    for (const field of ["observations", "findings"]) {
        if (!Number.isInteger(result.suppressed[field]) || result.suppressed[field] < 0) {
            throw new Error(`result.suppressed.${field} must be a non-negative integer.`);
        }
    }
    if (result.suppressedFindings !== undefined) {
        if (!Array.isArray(result.suppressedFindings) || result.suppressedFindings.length !== result.suppressed.findings) {
            throw new Error("result.suppressedFindings length must equal result.suppressed.findings.");
        }
    }
    const seen = new Set();
    for (const [field, findings] of [["findings", result.findings], ["suppressedFindings", result.suppressedFindings ?? []]]) {
        for (const finding of findings) {
            validateReviewFinding(finding, `result.${field}`);
            if (seen.has(finding.id)) {
                throw new Error(`result contains duplicate finding id "${finding.id}".`);
            }
            seen.add(finding.id);
        }
    }
}
function validateReviewFinding(finding, field) {
    if (!isRecord(finding)) {
        throw new Error(`${field} entries must be objects.`);
    }
    for (const key of ["id", "title", "category", "severity", "confidence", "summary"]) {
        requireString(finding[key], `${field}.${key}`);
    }
    if (!isSeverity(finding.severity)) {
        throw new Error(`${field}.severity is unsupported.`);
    }
    if (!["low", "medium", "high"].includes(finding.confidence)) {
        throw new Error(`${field}.confidence is unsupported.`);
    }
    if (!Array.isArray(finding.evidence)) {
        throw new Error(`${field}.evidence must be an array.`);
    }
}
//# sourceMappingURL=index.js.map
