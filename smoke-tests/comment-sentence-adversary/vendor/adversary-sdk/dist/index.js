import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { dirname, isAbsolute, relative, resolve } from "node:path";
export const DEFAULT_INPUT_PATH = "/adversary/input.json";
export const DEFAULT_OUTPUT_PATH = "/adversary/output.json";
export const DEFAULT_REPO_PATH = "/workspace";
export const DEFAULT_DETECTION_INPUT_PATH = "/adversary/detection-input.json";
export const DEFAULT_DETECTION_OUTPUT_PATH = "/adversary/detection-output.json";
export const INPUT_SCHEMA_VERSION = "adversary.input.v1";
export const DETECTION_SCHEMA_VERSION = "adversary.detection.v1";
export const REVIEW_SCHEMA_VERSION = "adversary.review.v1";
export const ERROR_PROTOCOL_VERSION = 1;
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
    rules = [];
    constructor(options) {
        requireString(options.name, "Adversary name");
        this.name = options.name;
    }
    rule(id, handler) {
        requireString(id, "Rule id");
        this.rules.push({ id, handler });
    }
    async run(options = {}) {
        const execution = await executeRules(this, options);
        if (options.write !== false) {
            await writeOutput(execution.envelope, options.outputPath);
        }
        return execution.envelope;
    }
    async runLegacy(options = {}) {
        const execution = await executeRules(this, options);
        if (options.write !== false) {
            await writeOutput(execution.envelope, options.outputPath);
        }
        return execution.legacy;
    }
}
async function executeRules(adversary, options) {
    const input = options.input === undefined ? await parseInput(options.inputPath) : normalizeRuntimeInput(options.input);
    const repoPath = process.env.ADVERSARY_REPO ?? input.source.path ?? DEFAULT_REPO_PATH;
    const summary = {};
    const cache = new Map();
    const context = createRuleContext(repoPath, summary, cache);
    const findings = [];
    for (const rule of adversary.rules) {
        log.debug(`running rule ${rule.id}`);
        const result = await rule.handler(context);
        findings.push(...normalizeRuleResult(result));
    }
    if (summary.rules_executed === undefined) {
        summary.rules_executed = adversary.rules.length;
    }
    const suppressedFindings = findings.filter((finding) => finding.suppressed === true);
    const legacy = {
        schema_version: REVIEW_SCHEMA_VERSION,
        adversary: adversary.name,
        summary,
        findings: findings.filter((finding) => finding.suppressed !== true).map(stripSuppressed),
    };
    const envelope = createAdversaryRunEnvelope(legacy, repoPath, suppressedFindings);
    validateReviewEnvelope(envelope);
    return { legacy, envelope };
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
export async function parseDetectionContext(path = process.env.ADVERSARY_DETECTION_INPUT ?? DEFAULT_DETECTION_INPUT_PATH) {
    const raw = await readFile(path, "utf8");
    const parsed = JSON.parse(raw);
    try {
        return validateDetectionContext(parsed);
    }
    catch (error) {
        throw new Error(`Invalid detection context at ${path}: ${error.message}`);
    }
}
export async function writeDetectionResult(result, path = process.env.ADVERSARY_DETECTION_OUTPUT ?? DEFAULT_DETECTION_OUTPUT_PATH) {
    validateDetectionResult(result);
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, `${JSON.stringify(result, null, 2)}\n`, "utf8");
}
export async function writeOutput(output, path = process.env.ADVERSARY_OUTPUT ?? DEFAULT_OUTPUT_PATH) {
    validateReviewEnvelope(output);
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, `${JSON.stringify(output, null, 2)}\n`, "utf8");
}
export function createReviewEnvelope(output, options = {}) {
    validateLegacyRunResult(output);
    const findings = Array.isArray(output.findings) ? output.findings : [];
    const embeddedSuppressed = findings.filter((finding) => finding.suppressed === true);
    const visibleOutput = {
        ...output,
        findings: findings.filter((finding) => finding.suppressed !== true).map(stripSuppressed),
    };
    const suppressedFindings = [...embeddedSuppressed, ...(options.suppressedFindings ?? [])];
    const envelope = createAdversaryRunEnvelope(visibleOutput, options.repoPath ?? DEFAULT_REPO_PATH, suppressedFindings, options.includeSuppressed ?? false);
    validateReviewEnvelope(envelope);
    return envelope;
}
function validateLegacyRunResult(output) {
    if (output === null || typeof output !== "object" || Array.isArray(output)) {
        throw new Error("Legacy run result must be an object.");
    }
    if (typeof output.schema_version !== "string") {
        throw new Error(`Legacy run result schema_version must be the string "${REVIEW_SCHEMA_VERSION}".`);
    }
    if (output.schema_version !== REVIEW_SCHEMA_VERSION) {
        throw new Error(`Unsupported legacy run result schema_version "${output.schema_version}"; expected "${REVIEW_SCHEMA_VERSION}".`);
    }
    return output;
}
export function sortLegacyFindings(findings) {
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
    if (typeof value !== "string" || value.trim().length === 0) {
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
function createAdversaryRunEnvelope(output, repoPath, suppressedFindings, includeSuppressed = verboseValues.has(process.env.ADVERSARY_INCLUDE_SUPPRESSED ?? "")) {
    return {
        protocolVersion: 1,
        result: normalizeReviewResult(output, repoPath, suppressedFindings, includeSuppressed),
    };
}
function normalizeReviewResult(output, repoPath, suppressedFindings = [], includeSuppressed = false) {
    const summary = output.summary ?? {};
    const normalizedSuppressed = suppressedFindings.map((finding) => normalizeReviewFinding(stripSuppressed(finding)));
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
        return omitUndefined(item);
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
        if (!Array.isArray(value.change.changed_files) || value.change.changed_files.some((path) => typeof path !== "string" || path.trim().length === 0)) {
            throw new Error("change.changed_files must contain only non-empty strings.");
        }
        if (new Set(value.change.changed_files).size !== value.change.changed_files.length) {
            throw new Error("change.changed_files must not contain duplicates.");
        }
    }
    return value;
}
function validateDetectionContext(value) {
    validateObject(value, ["schemaVersion", "repositoryRoot", "mode", "baseRef", "headRef", "mergeBase", "changedFiles", "repositoryFiles"], ["schemaVersion", "repositoryRoot", "mode", "changedFiles"], "detection context");
    if (value.schemaVersion !== DETECTION_SCHEMA_VERSION) throw new Error(`detection context schemaVersion must be "${DETECTION_SCHEMA_VERSION}".`);
    requireString(value.repositoryRoot, "detection context.repositoryRoot");
    if (!["dirty-worktree", "branch-comparison", "explicit-range", "pull-request"].includes(value.mode)) throw new Error("detection context.mode is unsupported.");
    for (const field of ["baseRef", "headRef", "mergeBase"]) optionalString(value[field], `detection context.${field}`);
    if (!Array.isArray(value.changedFiles)) throw new Error("detection context.changedFiles must be an array.");
    value.changedFiles.forEach((changed, index) => {
        const field = `detection context.changedFiles[${index}]`;
        validateObject(changed, ["path", "previousPath", "status", "additions", "deletions"], ["path", "status"], field);
        requireString(changed.path, `${field}.path`);
        optionalString(changed.previousPath, `${field}.previousPath`);
        if (!["added", "modified", "deleted", "renamed", "copied", "untracked"].includes(changed.status)) throw new Error(`${field}.status is unsupported.`);
        optionalNonNegativeInteger(changed.additions, `${field}.additions`);
        optionalNonNegativeInteger(changed.deletions, `${field}.deletions`);
    });
    if (value.repositoryFiles !== undefined && (!Array.isArray(value.repositoryFiles) || value.repositoryFiles.some((path) => typeof path !== "string" || path.trim().length === 0))) throw new Error("detection context.repositoryFiles must contain only non-empty strings.");
    return value;
}
export function validateDetectionResult(value) {
    validateObject(value, ["schemaVersion", "applicable", "confidence", "reasons", "relevantFiles", "repositoryMatch", "changeMatch"], ["schemaVersion", "applicable", "confidence", "reasons"], "detection result");
    if (value.schemaVersion !== DETECTION_SCHEMA_VERSION) throw new Error(`detection result schemaVersion must be "${DETECTION_SCHEMA_VERSION}".`);
    if (typeof value.applicable !== "boolean") throw new Error("detection result.applicable must be a boolean.");
    if (!["low", "medium", "high"].includes(value.confidence)) throw new Error("detection result.confidence is unsupported.");
    const hasControl = (text) => /[\u0000-\u001f\u007f-\u009f]/u.test(text);
    if (!Array.isArray(value.reasons) || value.reasons.length === 0 || value.reasons.some((reason) => typeof reason !== "string" || reason.trim().length === 0 || hasControl(reason))) throw new Error("detection result.reasons must contain non-empty strings without control characters.");
    if (value.relevantFiles !== undefined && (!Array.isArray(value.relevantFiles) || value.relevantFiles.some((path) => typeof path !== "string" || path.trim().length === 0 || hasControl(path)))) throw new Error("detection result.relevantFiles must contain only non-empty strings without control characters.");
    for (const field of ["repositoryMatch", "changeMatch"]) if (value[field] !== undefined && typeof value[field] !== "boolean") throw new Error(`detection result.${field} must be a boolean.`);
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
export function validateReviewEnvelope(value) {
    validateObject(value, ["protocolVersion", "result"], ["protocolVersion", "result"], "envelope");
    if (value.protocolVersion !== 1) {
        throw new Error("envelope.protocolVersion must be 1.");
    }
    const result = value.result;
    validateObject(result, ["adversary", "target", "assessment", "positives", "observations", "findings", "opinion", "suppressed", "timing", "suppressedFindings", "rawObservations"], ["adversary", "target", "positives", "observations", "findings", "suppressed"], "result");
    validateObject(result.adversary, ["name", "version"], ["name"], "result.adversary");
    requireString(result.adversary.name, "result.adversary.name");
    optionalString(result.adversary.version, "result.adversary.version");
    validateObject(result.target, ["repository", "filesScanned"], [], "result.target");
    optionalString(result.target.repository, "result.target.repository");
    optionalNonNegativeInteger(result.target.filesScanned, "result.target.filesScanned");
    if (result.assessment !== undefined) {
        validateObject(result.assessment, ["risk", "summary"], ["risk"], "result.assessment");
        if (!["none", "low", "medium", "high", "critical"].includes(result.assessment.risk)) {
            throw new Error("result.assessment.risk is unsupported.");
        }
        optionalString(result.assessment.summary, "result.assessment.summary");
    }
    for (const field of ["positives", "observations"]) {
        if (!Array.isArray(result[field])) {
            throw new Error(`result.${field} must be an array.`);
        }
        result[field].forEach((note, index) => validateReviewNote(note, `result.${field}[${index}]`));
    }
    if (!Array.isArray(result.findings)) {
        throw new Error("result.findings must be an array.");
    }
    if (result.opinion !== undefined) {
        validateObject(result.opinion, ["ship", "summary"], ["summary"], "result.opinion");
        if (result.opinion.ship !== undefined && typeof result.opinion.ship !== "boolean") {
            throw new Error("result.opinion.ship must be a boolean.");
        }
        requireString(result.opinion.summary, "result.opinion.summary");
    }
    validateObject(result.suppressed, ["observations", "findings"], ["observations", "findings"], "result.suppressed");
    for (const field of ["observations", "findings"]) {
        if (!Number.isInteger(result.suppressed[field]) || result.suppressed[field] < 0) {
            throw new Error(`result.suppressed.${field} must be a non-negative integer.`);
        }
    }
    if (result.timing !== undefined) {
        validateObject(result.timing, ["buildMs", "startupMs", "scanMs", "totalMs"], [], "result.timing");
        for (const field of ["buildMs", "startupMs", "scanMs", "totalMs"]) {
            optionalNonNegativeInteger(result.timing[field], `result.timing.${field}`);
        }
    }
    if (result.suppressedFindings !== undefined) {
        if (!Array.isArray(result.suppressedFindings) || result.suppressedFindings.length !== result.suppressed.findings) {
            throw new Error("result.suppressedFindings length must equal result.suppressed.findings.");
        }
    }
    const seen = new Set();
    for (const [field, findings] of [["findings", result.findings], ["suppressedFindings", result.suppressedFindings ?? []]]) {
        for (const [index, finding] of findings.entries()) {
            validateReviewFinding(finding, `result.${field}[${index}]`);
            if (seen.has(finding.id)) {
                throw new Error(`result contains duplicate finding id "${finding.id}".`);
            }
            seen.add(finding.id);
        }
    }
}

export function validateErrorEnvelope(value) {
    validateObject(value, ["protocolVersion", "error"], ["protocolVersion", "error"], "envelope");
    if (value.protocolVersion !== ERROR_PROTOCOL_VERSION) {
        throw new Error(`Unsupported adversary error protocolVersion ${value.protocolVersion}.`);
    }
    validateObject(value.error, ["code", "message", "retryable", "details"], ["code", "message", "retryable", "details"], "error");
    if (typeof value.error.code !== "string" || !/^[a-z][a-z0-9_]*$/.test(value.error.code)) throw new Error("error.code is invalid.");
    requireString(value.error.message, "error.message");
    if (typeof value.error.retryable !== "boolean") throw new Error("error.retryable must be a boolean.");
    if (!isRecord(value.error.details)) throw new Error("error.details must be an object.");
}

export function encodeErrorEnvelope(value) {
    validateErrorEnvelope(value);
    return `${JSON.stringify(canonicalValue(value))}\n`;
}
function canonicalValue(value) {
    if (Array.isArray(value)) return value.map(canonicalValue);
    if (!isRecord(value)) return value;
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalValue(value[key])]));
}
function validateReviewFinding(finding, field) {
    validateObject(finding, ["id", "ruleId", "groupKey", "title", "category", "severity", "confidence", "summary", "whyItMatters", "impact", "evidence", "recommendation", "remediation", "tags", "metadata"], ["id", "title", "category", "severity", "confidence", "summary", "evidence"], field);
    for (const key of ["id", "title", "category", "severity", "confidence", "summary"]) {
        requireString(finding[key], `${field}.${key}`);
    }
    for (const key of ["ruleId", "groupKey", "whyItMatters", "impact", "recommendation"]) {
        optionalString(finding[key], `${field}.${key}`);
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
    finding.evidence.forEach((evidence, index) => validateReviewEvidence(evidence, `${field}.evidence[${index}]`));
    if (finding.remediation !== undefined) {
        validateObject(finding.remediation, ["estimate", "complexity"], [], `${field}.remediation`);
        optionalString(finding.remediation.estimate, `${field}.remediation.estimate`);
        optionalString(finding.remediation.complexity, `${field}.remediation.complexity`);
    }
    if (finding.tags !== undefined) {
        if (!Array.isArray(finding.tags) || finding.tags.some((tag) => typeof tag !== "string")) {
            throw new Error(`${field}.tags must contain only strings.`);
        }
        if (new Set(finding.tags).size !== finding.tags.length) {
            throw new Error(`${field}.tags must not contain duplicates.`);
        }
    }
    optionalMetadata(finding.metadata, `${field}.metadata`);
}
function validateReviewNote(note, field) {
    validateObject(note, ["key", "summary", "evidence", "metadata"], ["key", "summary"], field);
    requireString(note.key, `${field}.key`);
    requireString(note.summary, `${field}.summary`);
    if (note.evidence !== undefined) {
        if (!Array.isArray(note.evidence)) {
            throw new Error(`${field}.evidence must be an array.`);
        }
        note.evidence.forEach((evidence, index) => validateReviewEvidence(evidence, `${field}.evidence[${index}]`));
    }
    optionalMetadata(note.metadata, `${field}.metadata`);
}
function validateReviewEvidence(evidence, field) {
    validateObject(evidence, ["file", "line", "endLine", "message", "snippet", "metadata"], [], field);
    for (const key of ["file", "message", "snippet"]) {
        optionalString(evidence[key], `${field}.${key}`);
    }
    optionalPositiveInteger(evidence.line, `${field}.line`);
    optionalPositiveInteger(evidence.endLine, `${field}.endLine`);
    if (evidence.endLine !== undefined && evidence.line === undefined) {
        throw new Error(`${field}.endLine requires line.`);
    }
    if (evidence.endLine !== undefined && evidence.endLine < evidence.line) {
        throw new Error(`${field}.endLine must not precede line.`);
    }
    optionalMetadata(evidence.metadata, `${field}.metadata`);
}
function optionalMetadata(value, field) {
    if (value !== undefined && !isRecord(value)) {
        throw new Error(`${field} must be an object.`);
    }
}
function optionalNonNegativeInteger(value, field) {
    if (value !== undefined && (!Number.isInteger(value) || value < 0)) {
        throw new Error(`${field} must be a non-negative integer.`);
    }
}
function validateObject(value, allowed, required, field) {
    if (!isRecord(value)) {
        throw new Error(`${field} must be an object.`);
    }
    const allowedKeys = new Set(allowed);
    const unknown = Object.keys(value).filter((key) => !allowedKeys.has(key));
    if (unknown.length > 0) {
        throw new Error(`${field} contains unknown field "${unknown[0]}".`);
    }
    for (const key of required) {
        if (!(key in value)) {
            throw new Error(`${field}.${key} is required.`);
        }
    }
}
//# sourceMappingURL=index.js.map
