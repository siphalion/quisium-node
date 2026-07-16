/**
 * Core data structures shared across the whole package: ScanResult, GuardDecision,
 * ToolCall, and the small enums that classify them.
 */

export const RiskLevel = {
  NONE: "none",
  LOW: "low",
  MEDIUM: "medium",
  HIGH: "high",
  CRITICAL: "critical",
} as const;
export type RiskLevel = (typeof RiskLevel)[keyof typeof RiskLevel];

export function riskLevelFromScore(score: number): RiskLevel {
  if (!(score >= 0.0 && score <= 1.0)) {
    throw new RangeError(`score must be in [0.0, 1.0], got ${score}`);
  }
  if (score < 0.1) return RiskLevel.NONE;
  if (score < 0.4) return RiskLevel.LOW;
  if (score < 0.75) return RiskLevel.MEDIUM;
  if (score < 0.9) return RiskLevel.HIGH;
  return RiskLevel.CRITICAL;
}

export const GuardType = {
  PROMPT: "prompt",
  OUTPUT: "output",
  TOOL: "tool",
} as const;
export type GuardType = (typeof GuardType)[keyof typeof GuardType];

export const PolicyAction = {
  BLOCK: "block",
  WARN: "warn",
  LOG: "log",
} as const;
export type PolicyAction = (typeof PolicyAction)[keyof typeof PolicyAction];

export function round4(value: number): number {
  return Math.round(value * 10000) / 10000;
}

export interface ScanResultInit {
  allowed: boolean;
  score: number;
  reasons?: string[];
  safeOutput?: string | null;
  guardType?: GuardType;
  metadata?: Record<string, unknown>;
}

export interface ScanResultDict {
  allowed: boolean;
  score: number;
  risk_level: RiskLevel;
  reasons: string[];
  safe_output: string | null;
  guard_type: GuardType;
  metadata: Record<string, unknown>;
}

/** The output of a single guard check. */
export class ScanResult {
  readonly allowed: boolean;
  readonly score: number;
  readonly reasons: string[];
  readonly safeOutput: string | null;
  readonly guardType: GuardType;
  readonly metadata: Record<string, unknown>;

  constructor(init: ScanResultInit) {
    if (!(init.score >= 0.0 && init.score <= 1.0)) {
      throw new RangeError(`ScanResult.score must be in [0.0, 1.0], got ${init.score}`);
    }
    this.allowed = init.allowed;
    this.score = init.score;
    this.reasons = init.reasons ?? [];
    this.safeOutput = init.safeOutput ?? null;
    this.guardType = init.guardType ?? GuardType.PROMPT;
    this.metadata = init.metadata ?? {};
  }

  get riskLevel(): RiskLevel {
    return riskLevelFromScore(this.score);
  }

  get isClean(): boolean {
    return this.allowed && this.score < 0.1;
  }

  toDict(): ScanResultDict {
    return {
      allowed: this.allowed,
      score: round4(this.score),
      risk_level: this.riskLevel,
      reasons: this.reasons,
      safe_output: this.safeOutput,
      guard_type: this.guardType,
      metadata: this.metadata,
    };
  }

  toJSON(): ScanResultDict {
    return this.toDict();
  }
}

export interface GuardDecisionInit {
  allowed: boolean;
  score: number;
  reasons?: string[];
  safeOutput?: string | null;
  warned?: boolean;
  scanResults?: ScanResult[];
  action?: PolicyAction;
}

export interface GuardDecisionDict {
  allowed: boolean;
  score: number;
  risk_level: RiskLevel;
  reasons: string[];
  safe_output: string | null;
  warned: boolean;
  action: PolicyAction;
  scan_results: ScanResultDict[];
}

/** The top-level result returned to the application — an aggregation of all ScanResults. */
export class GuardDecision {
  readonly allowed: boolean;
  readonly score: number;
  readonly reasons: string[];
  readonly safeOutput: string | null;
  readonly warned: boolean;
  readonly scanResults: ScanResult[];
  readonly action: PolicyAction;

  constructor(init: GuardDecisionInit) {
    if (!(init.score >= 0.0 && init.score <= 1.0)) {
      throw new RangeError(`GuardDecision.score must be in [0.0, 1.0], got ${init.score}`);
    }
    this.allowed = init.allowed;
    this.score = init.score;
    this.reasons = init.reasons ?? [];
    this.safeOutput = init.safeOutput ?? null;
    this.warned = init.warned ?? false;
    this.scanResults = init.scanResults ?? [];
    this.action = init.action ?? PolicyAction.LOG;
  }

  get riskLevel(): RiskLevel {
    return riskLevelFromScore(this.score);
  }

  get wasBlocked(): boolean {
    return !this.allowed;
  }

  get promptResults(): ScanResult[] {
    return this.scanResults.filter((r) => r.guardType === GuardType.PROMPT);
  }

  get outputResults(): ScanResult[] {
    return this.scanResults.filter((r) => r.guardType === GuardType.OUTPUT);
  }

  get toolResults(): ScanResult[] {
    return this.scanResults.filter((r) => r.guardType === GuardType.TOOL);
  }

  static blocked(reasons: string[], score = 1.0, scanResults: ScanResult[] = []): GuardDecision {
    return new GuardDecision({
      allowed: false,
      score,
      reasons,
      safeOutput: null,
      warned: false,
      scanResults,
      action: PolicyAction.BLOCK,
    });
  }

  static allowedWithWarning(
    safeOutput: string,
    reasons: string[],
    score: number,
    scanResults: ScanResult[] = [],
  ): GuardDecision {
    return new GuardDecision({
      allowed: true,
      score,
      reasons,
      safeOutput,
      warned: true,
      scanResults,
      action: PolicyAction.WARN,
    });
  }

  static clean(safeOutput: string | null, scanResults: ScanResult[] = []): GuardDecision {
    return new GuardDecision({
      allowed: true,
      score: 0.0,
      reasons: [],
      safeOutput,
      warned: false,
      scanResults,
      action: PolicyAction.LOG,
    });
  }

  toDict(): GuardDecisionDict {
    return {
      allowed: this.allowed,
      score: round4(this.score),
      risk_level: this.riskLevel,
      reasons: this.reasons,
      safe_output: this.safeOutput,
      warned: this.warned,
      action: this.action,
      scan_results: this.scanResults.map((r) => r.toDict()),
    };
  }

  toJSON(): GuardDecisionDict {
    return this.toDict();
  }
}

export interface ToolCallInit {
  name: string;
  args: Record<string, unknown>;
  schema?: Record<string, unknown>;
  callId?: string | null;
}

export interface ToolCallDict {
  name: string;
  args: Record<string, unknown>;
  schema: Record<string, unknown>;
  call_id: string | null;
}

/** A structured tool/function invocation that the model requested. */
export class ToolCall {
  readonly name: string;
  readonly args: Record<string, unknown>;
  readonly schema: Record<string, unknown>;
  readonly callId: string | null;

  constructor(init: ToolCallInit) {
    if (!init.name || !init.name.trim()) {
      throw new Error("ToolCall.name must be a non-empty string.");
    }
    this.name = init.name;
    this.args = init.args;
    this.schema = init.schema ?? {};
    this.callId = init.callId ?? null;
  }

  get hasSchema(): boolean {
    return Object.keys(this.schema).length > 0;
  }

  toDict(): ToolCallDict {
    return {
      name: this.name,
      args: this.args,
      schema: this.schema,
      call_id: this.callId,
    };
  }

  toJSON(): ToolCallDict {
    return this.toDict();
  }
}
