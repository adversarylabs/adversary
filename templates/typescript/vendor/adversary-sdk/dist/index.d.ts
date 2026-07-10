export declare const DEFAULT_INPUT_PATH = "/adversary/input.json";
export declare const DEFAULT_OUTPUT_PATH = "/adversary/output.json";
export declare const DEFAULT_REPO_PATH = "/workspace";
export declare const REVIEW_SCHEMA_VERSION = "adversary.review.v1";
export declare const Severity: {
    readonly Info: "info";
    readonly Low: "low";
    readonly Medium: "medium";
    readonly High: "high";
    readonly Critical: "critical";
};
export type Severity = (typeof Severity)[keyof typeof Severity];
export interface RuntimeInput {
    source: {
        path: string;
    };
    [key: string]: unknown;
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
}
export interface Output {
    schema_version: typeof REVIEW_SCHEMA_VERSION;
    adversary: string;
    summary: Summary;
    findings: SerializedFinding[];
}
export interface AdversaryRunEnvelope {
    protocolVersion: 1;
    result: Output;
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
    input?: RuntimeInput;
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
//# sourceMappingURL=index.d.ts.map
