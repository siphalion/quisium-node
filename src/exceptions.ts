/**
 * The exception hierarchy raised throughout the guard pipeline.
 */
import type { GuardDecision, ScanResult } from "./types.js";

export class LLMSecurityError extends Error {
  readonly context: Record<string, unknown>;

  constructor(message: string, context: Record<string, unknown> = {}) {
    super(message);
    this.name = new.target.name;
    this.context = context;
    Object.setPrototypeOf(this, new.target.prototype);
  }

  override toString(): string {
    return `${this.name}(${JSON.stringify(this.message)})`;
  }
}

export interface BlockedByPolicyErrorInit {
  reasons: string[];
  score?: number;
  decision?: GuardDecision | null;
  policyName?: string;
  context?: Record<string, unknown>;
}

export class BlockedByPolicyError extends LLMSecurityError {
  readonly reasons: string[];
  readonly score: number;
  readonly decision: GuardDecision | null;
  readonly policyName: string;

  constructor(init: BlockedByPolicyErrorInit) {
    const reasons = init.reasons;
    const score = init.score ?? 1.0;
    const policyName = init.policyName ?? "unknown";
    const reasonSummary = reasons.length > 0 ? reasons.join("; ") : "no details provided";
    const message = `Request blocked by policy ${JSON.stringify(policyName)} (score=${score.toFixed(3)}): ${reasonSummary}`;
    super(message, init.context);
    this.reasons = reasons;
    this.score = score;
    this.decision = init.decision ?? null;
    this.policyName = policyName;
  }

  toDict(): Record<string, unknown> {
    return {
      error: this.name,
      reasons: this.reasons,
      score: Math.round(this.score * 10000) / 10000,
      policy_name: this.policyName,
    };
  }
}

export interface PromptBlockedErrorInit extends BlockedByPolicyErrorInit {
  promptSnippet?: string;
}

export class PromptBlockedError extends BlockedByPolicyError {
  readonly promptSnippet: string;

  constructor(init: PromptBlockedErrorInit) {
    super(init);
    this.promptSnippet = (init.promptSnippet ?? "").slice(0, 120);
  }

  override toDict(): Record<string, unknown> {
    return { ...super.toDict(), prompt_snippet: this.promptSnippet };
  }
}

export interface OutputBlockedErrorInit extends BlockedByPolicyErrorInit {
  outputSnippet?: string;
}

export class OutputBlockedError extends BlockedByPolicyError {
  readonly outputSnippet: string;

  constructor(init: OutputBlockedErrorInit) {
    super(init);
    this.outputSnippet = (init.outputSnippet ?? "").slice(0, 120);
  }

  override toDict(): Record<string, unknown> {
    return { ...super.toDict(), output_snippet: this.outputSnippet };
  }
}

export interface InvalidToolCallErrorInit {
  toolName: string;
  reason: string;
  scanResult?: ScanResult | null;
  callId?: string | null;
  context?: Record<string, unknown>;
}

export class InvalidToolCallError extends LLMSecurityError {
  readonly toolName: string;
  readonly reason: string;
  readonly scanResult: ScanResult | null;
  readonly callId: string | null;

  constructor(init: InvalidToolCallErrorInit) {
    const callIdPart = init.callId ? ` [call_id=${JSON.stringify(init.callId)}]` : "";
    const message = `Invalid tool call for ${JSON.stringify(init.toolName)}${callIdPart}: ${init.reason}`;
    super(message, init.context);
    this.toolName = init.toolName;
    this.reason = init.reason;
    this.scanResult = init.scanResult ?? null;
    this.callId = init.callId ?? null;
  }

  toDict(): Record<string, unknown> {
    return {
      error: this.name,
      tool_name: this.toolName,
      reason: this.reason,
      call_id: this.callId,
    };
  }
}

export interface PolicyNotFoundErrorInit {
  policyName: string;
  available?: string[];
  context?: Record<string, unknown>;
}

export class PolicyNotFoundError extends LLMSecurityError {
  readonly policyName: string;
  readonly available: string[];

  constructor(init: PolicyNotFoundErrorInit) {
    const available = init.available ?? [];
    const message =
      available.length > 0
        ? `Policy ${JSON.stringify(init.policyName)} not found. Available policies: ${[...available].sort().join(", ")}`
        : `Policy ${JSON.stringify(init.policyName)} not found. No policies are registered.`;
    super(message, init.context);
    this.policyName = init.policyName;
    this.available = available;
  }
}

export interface ProviderErrorInit {
  message: string;
  providerName?: string;
  statusCode?: number | null;
  originalError?: unknown;
  context?: Record<string, unknown>;
}

export class ProviderError extends LLMSecurityError {
  readonly providerName: string;
  readonly statusCode: number | null;
  readonly originalError: unknown;

  constructor(init: ProviderErrorInit) {
    const providerName = init.providerName ?? "unknown";
    const statusPart = init.statusCode ? ` (HTTP ${init.statusCode})` : "";
    const fullMessage = `[${providerName}]${statusPart} ${init.message}`;
    super(fullMessage, init.context);
    this.providerName = providerName;
    this.statusCode = init.statusCode ?? null;
    this.originalError = init.originalError;
  }

  toDict(): Record<string, unknown> {
    return {
      error: this.name,
      provider_name: this.providerName,
      status_code: this.statusCode,
      message: this.message,
    };
  }
}

export interface ProviderTimeoutErrorInit {
  providerName?: string;
  timeoutSeconds?: number | null;
  originalError?: unknown;
  context?: Record<string, unknown>;
}

export class ProviderTimeoutError extends ProviderError {
  readonly timeoutSeconds: number | null;

  constructor(init: ProviderTimeoutErrorInit = {}) {
    const timeoutPart = init.timeoutSeconds != null ? ` after ${init.timeoutSeconds}s` : "";
    super({
      message: `Provider request timed out${timeoutPart}.`,
      providerName: init.providerName ?? "unknown",
      statusCode: 408,
      originalError: init.originalError,
      context: init.context,
    });
    this.timeoutSeconds = init.timeoutSeconds ?? null;
  }
}

export interface GuardErrorInit {
  guardName: string;
  message: string;
  originalError?: unknown;
  context?: Record<string, unknown>;
}

export class GuardError extends LLMSecurityError {
  readonly guardName: string;
  readonly originalError: unknown;

  constructor(init: GuardErrorInit) {
    super(`Guard fault in ${JSON.stringify(init.guardName)}: ${init.message}`, init.context);
    this.guardName = init.guardName;
    this.originalError = init.originalError;
  }
}
