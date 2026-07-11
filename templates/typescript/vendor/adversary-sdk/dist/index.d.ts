export declare const DEFAULT_INPUT_PATH = "/adversary/input.json";
export declare const DEFAULT_OUTPUT_PATH = "/adversary/output.json";
export declare const DEFAULT_REPO_PATH = "/workspace";
export declare const INPUT_SCHEMA_VERSION = "adversary.input.v1";
export declare const REVIEW_SCHEMA_VERSION = "adversary.review.v1";
export declare const ERROR_PROTOCOL_VERSION = 1;
export interface ErrorEnvelope {
    protocolVersion: typeof ERROR_PROTOCOL_VERSION;
    error: { code: string; message: string; retryable: boolean; details: Record<string, unknown> };
}
export declare const Severity: {
    readonly Info: "info";
    readonly Low: "low";
    readonly Medium: "medium";
    readonly High: "high";
    readonly Critical: "critical";
};
export type Severity = (typeof Severity)[keyof typeof Severity];
export interface RuntimeInput {
    schema_version: typeof INPUT_SCHEMA_VERSION;
    source: {
        path: string;
    };
    change: {
        type: "diff";
        base_ref: string;
        head_ref: string;
        scan_mode: "changed" | "all";
        changed_files: string[];
    } | null;
}
export interface Summary {
    files_scanned?: number;
    rules_executed?: number;
    [key: string]: number | string | boolean | null | undefined;
}
export interface FindingInit {
    ruleId: string;
    id?: string;
    severity: Severity;
    title: string;
    message?: string;
    path?: string;
    file?: string;
    line?: number;
    column?: number;
    evidence?: string;
    recommendation?: string;
    metadata?: Record<string, unknown>;
    suppressed?: boolean;
}
export interface SerializedFinding {
    rule_id: string;
    id: string;
    severity: Severity;
    title: string;
    message?: string;
    path?: string;
    file?: string;
    line?: number;
    column?: number;
    evidence?: string;
    recommendation?: string;
    metadata?: Record<string, unknown>;
    suppressed?: boolean;
}
export interface Output {
    schema_version: typeof REVIEW_SCHEMA_VERSION;
    adversary: string;
    summary: Summary;
    findings: SerializedFinding[];
}
export interface AdversaryRunEnvelope {
    protocolVersion: 1;
    result: ReviewResult;
}
export interface ReviewEvidence {
    file?: string;
    line?: number;
    endLine?: number;
    message?: string;
    snippet?: string;
    metadata?: Record<string, unknown>;
}
export interface ReviewFinding {
    id: string;
    ruleId?: string;
    groupKey?: string;
    title: string;
    category: string;
    severity: Severity;
    confidence: "low" | "medium" | "high";
    summary: string;
    whyItMatters?: string;
    impact?: string;
    evidence: ReviewEvidence[];
    recommendation?: string;
    remediation?: { estimate?: string; complexity?: string };
    tags?: string[];
    metadata?: Record<string, unknown>;
}
export interface ReviewResult {
    adversary: { name: string; version?: string };
    target: { repository?: string; filesScanned?: number };
    assessment?: { risk: "none" | "low" | "medium" | "high" | "critical"; summary?: string };
    positives: Array<{ key: string; summary: string; evidence?: ReviewEvidence[]; metadata?: Record<string, unknown> }>;
    observations: Array<{ key: string; summary: string; evidence?: ReviewEvidence[]; metadata?: Record<string, unknown> }>;
    findings: ReviewFinding[];
    opinion?: { ship?: boolean; summary: string };
    suppressed: { observations: number; findings: number };
    timing?: { buildMs?: number; startupMs?: number; scanMs?: number; totalMs?: number };
    suppressedFindings?: ReviewFinding[];
    rawObservations?: unknown;
}
export interface RuleContext {
    repoPath: string;
    summary: Summary;
    cache: Map<string, unknown>;
    relpath: (path: string) => string;
    glob: (pattern: string) => Promise<string[]>;
    rglob: (pattern: string) => Promise<string[]>;
}
export type RuleResult = undefined | null | Finding | Finding[];
export type RuleHandler = (context: RuleContext) => RuleResult | Promise<RuleResult>;
export interface AdversaryOptions {
    name: string;
    schemaVersion?: typeof REVIEW_SCHEMA_VERSION;
}
export interface RunOptions {
    input?: RuntimeInput | { source: { path: string }; schema_version?: typeof INPUT_SCHEMA_VERSION; change?: RuntimeInput["change"] };
    inputPath?: string;
    outputPath?: string;
    write?: boolean;
}
export declare const log: {
    debug(message: unknown): void;
    info(message: unknown): void;
    warn(message: unknown): void;
    error(message: unknown): void;
};
export declare class Finding {
    readonly ruleId: string;
    readonly id: string;
    readonly severity: Severity;
    readonly title: string;
    readonly message?: string;
    readonly path?: string;
    readonly file?: string;
    readonly line?: number;
    readonly column?: number;
    readonly evidence?: string;
    readonly recommendation?: string;
    readonly metadata?: Record<string, unknown>;
    readonly suppressed?: boolean;
    constructor(init: FindingInit);
    toJSON(): SerializedFinding;
}
export declare class Adversary {
    readonly name: string;
    readonly schemaVersion: typeof REVIEW_SCHEMA_VERSION;
    readonly rules: Array<{
        id: string;
        handler: RuleHandler;
    }>;
    constructor(options: AdversaryOptions);
    rule(id: string, handler: RuleHandler): void;
    run(options?: RunOptions): Promise<Output>;
}
export declare function parseInput(path?: string): Promise<RuntimeInput>;
export declare function writeOutput(output: Output | AdversaryRunEnvelope, path?: string): Promise<void>;
export declare function sortFindings(findings: SerializedFinding[]): SerializedFinding[];
export declare function validateReviewEnvelope(value: unknown): asserts value is AdversaryRunEnvelope;
export declare function validateErrorEnvelope(value: unknown): asserts value is ErrorEnvelope;
export declare function encodeErrorEnvelope(value: ErrorEnvelope): string;
//# sourceMappingURL=index.d.ts.map
