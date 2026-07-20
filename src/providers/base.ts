/**
 * The abstract BaseProvider: orchestrates the full guard pipeline — input scan
 * → forward to the model → output scan — and returns a GuardDecision.
 *
 * Note on `providerName`: Python resolves `self.provider_name` dynamically via
 * the instance's class (MRO), so a subclass's class-level override is visible
 * even from code running inside the base class's `__init__`. JS class-field
 * initializers don't have that property (a subclass field only overwrites the
 * base's after `super()` returns), so this port takes `providerName` as an
 * explicit constructor argument instead of relying on field-initializer order.
 */
import { getDefaultPolicy } from "../config.js";
import {
  BlockedByPolicyError,
  GuardError,
  OutputBlockedError,
  PromptBlockedError,
  ProviderError,
} from "../exceptions.js";
import { aggregateToolScans, validateToolCalls } from "../guards/tools.js";
import { scanAndRedact } from "../guards/outputs.js";
import { aggregatePromptScans, scanMessages } from "../guards/prompts.js";
import { LogFormat, SecurityEventLogger } from "../logging.js";
import { Policy } from "../policies.js";
import { GuardDecision, GuardType, PolicyAction, ScanResult, ToolCall } from "../types.js";

export interface ChatMessage {
  role: string;
  content: string;
  [key: string]: unknown;
}

export interface ProviderConfigInit {
  timeoutSeconds?: number;
  maxRetries?: number;
  logFormat?: LogFormat;
  extraHeaders?: Record<string, string>;
  defaultExtra?: Record<string, unknown>;
  rolesToScan?: string[];
}

export class ProviderConfig {
  readonly timeoutSeconds: number;
  readonly maxRetries: number;
  readonly logFormat: LogFormat;
  readonly extraHeaders: Record<string, string>;
  readonly defaultExtra: Record<string, unknown>;
  readonly rolesToScan: string[];

  constructor(init: ProviderConfigInit = {}) {
    this.timeoutSeconds = init.timeoutSeconds ?? 30.0;
    this.maxRetries = init.maxRetries ?? 0;
    this.logFormat = init.logFormat ?? LogFormat.JSON;
    this.extraHeaders = init.extraHeaders ?? {};
    this.defaultExtra = init.defaultExtra ?? {};
    this.rolesToScan = init.rolesToScan ?? ["user"];
  }
}

export interface ChatOptions {
  tools?: ToolCall[];
  policy?: Policy;
  extra?: Record<string, unknown>;
  kwargs?: Record<string, unknown>;
}

function snippet(messages: ChatMessage[], maxLen = 120): string {
  for (let i = messages.length - 1; i >= 0; i--) {
    const msg = messages[i];
    if (msg && msg.role === "user") {
      return (msg.content ?? "").slice(0, maxLen);
    }
  }
  return "";
}

export abstract class BaseProvider {
  readonly providerName: string;
  protected _policy: Policy;
  protected _config: ProviderConfig;
  protected _secLogger: SecurityEventLogger;

  protected constructor(providerName: string, policy?: Policy, config?: ProviderConfig) {
    this.providerName = providerName;
    this._policy = policy ?? getDefaultPolicy();
    this._config = config ?? new ProviderConfig();
    this._secLogger = new SecurityEventLogger({
      policy: this._policy,
      providerName: this.providerName,
      fmt: this._config.logFormat,
      defaultExtra: this._config.defaultExtra,
    });
  }

  get policy(): Policy {
    return this._policy;
  }

  set policy(value: Policy) {
    if (!(value instanceof Policy)) {
      throw new TypeError(`policy must be a Policy instance, got ${typeof value}`);
    }
    this._policy = value;
    this._secLogger.policy = value;
  }

  get config(): ProviderConfig {
    return this._config;
  }

  /**
   * Make the raw API call to the LLM provider. Called by chat() after all
   * pre-call guards pass. The return value is passed to extractText().
   * Concrete providers should wrap SDK-specific exceptions in ProviderError /
   * ProviderTimeoutError before re-raising.
   */
  protected abstract callModel(messages: ChatMessage[], kwargs: Record<string, unknown>): Promise<unknown>;

  /** Extract the assistant's text content from the SDK response. Return "" if none. */
  protected abstract extractText(response: unknown): string;

  protected extractToolCalls(_response: unknown): ToolCall[] {
    return [];
  }

  /** Optional hook called just before a BlockedByPolicyError is raised. Default: no-op. */
  protected onBlocked(_exc: BlockedByPolicyError, _messages: ChatMessage[]): void {
    // no-op by default
  }

  async chat(messages: ChatMessage[], options: ChatOptions = {}): Promise<GuardDecision> {
    const activePolicy = options.policy ?? this._policy;
    const tools = options.tools;
    const extra = options.extra;
    const kwargs = { ...(options.kwargs ?? {}) };

    if (!messages || messages.length === 0) {
      throw new Error("messages must be a non-empty list");
    }

    const start = performance.now();
    const scanResults: ScanResult[] = [];

    const promptScan = this.runPromptGuard(messages, activePolicy);
    scanResults.push(promptScan);

    if (!promptScan.allowed) {
      const decision = this.buildBlockedDecision(scanResults);
      await this.logAndMaybeRaise({
        decision,
        policy: activePolicy,
        messages,
        start,
        extra,
        makeError: (reasons, score) =>
          new PromptBlockedError({
            reasons,
            score,
            decision,
            policyName: activePolicy.name,
            promptSnippet: snippet(messages),
          }),
      });
      return decision;
    }

    if (tools && tools.length > 0) {
      const toolScan = this.runToolGuard(tools, activePolicy);
      scanResults.push(toolScan);

      if (!toolScan.allowed) {
        const decision = this.buildBlockedDecision(scanResults);
        await this.logAndMaybeRaise({
          decision,
          policy: activePolicy,
          messages,
          start,
          extra,
          makeError: (reasons, score) =>
            new BlockedByPolicyError({ reasons, score, decision, policyName: activePolicy.name }),
        });
        return decision;
      }

      if (!("tools" in kwargs)) kwargs.tools = tools;
    }

    let response: unknown;
    let rawText: string;
    try {
      response = await this.callModel(messages, kwargs);
      rawText = this.extractText(response);
    } catch (exc) {
      if (exc instanceof ProviderError || exc instanceof BlockedByPolicyError) {
        throw exc;
      }
      throw new ProviderError({
        message: String((exc as Error)?.message ?? exc),
        providerName: this.providerName,
        originalError: exc,
      });
    }

    const responseTools = this.extractToolCalls(response);
    if (responseTools.length > 0 && activePolicy.isGuardEnabled(GuardType.TOOL)) {
      const respToolScan = this.runToolGuard(responseTools, activePolicy);
      scanResults.push(respToolScan);

      if (!respToolScan.allowed) {
        const decision = this.buildBlockedDecision(scanResults);
        await this.logAndMaybeRaise({
          decision,
          policy: activePolicy,
          messages,
          start,
          extra,
          makeError: (reasons, score) =>
            new BlockedByPolicyError({ reasons, score, decision, policyName: activePolicy.name }),
        });
        return decision;
      }
    }

    let outputScan: ScanResult;
    if (rawText) {
      outputScan = this.runOutputGuard(rawText, activePolicy);
      scanResults.push(outputScan);

      if (!outputScan.allowed) {
        const decision = this.buildBlockedDecision(scanResults, outputScan.safeOutput);
        await this.logAndMaybeRaise({
          decision,
          policy: activePolicy,
          messages,
          start,
          extra,
          makeError: (reasons, score) =>
            new OutputBlockedError({
              reasons,
              score,
              decision,
              policyName: activePolicy.name,
              outputSnippet: (rawText ?? "").slice(0, 120),
            }),
        });
        return decision;
      }
    } else {
      outputScan = new ScanResult({
        allowed: true,
        score: 0.0,
        reasons: [],
        guardType: GuardType.OUTPUT,
        metadata: { skipped: true, reason: "empty model response" },
      });
      scanResults.push(outputScan);
    }

    const decision = this.buildCleanDecision(scanResults, activePolicy, outputScan.safeOutput ?? rawText);

    const elapsedMs = performance.now() - start;
    this._secLogger.logDecision(decision, { durationMs: elapsedMs, extra });

    return decision;
  }

  private runPromptGuard(messages: ChatMessage[], policy: Policy): ScanResult {
    try {
      const perMessage = scanMessages(messages, policy, { rolesToScan: this._config.rolesToScan });
      return aggregatePromptScans(perMessage, policy);
    } catch (exc) {
      throw new GuardError({ guardName: "prompt_guard", message: String((exc as Error)?.message ?? exc), originalError: exc });
    }
  }

  private runToolGuard(tools: ToolCall[], policy: Policy): ScanResult {
    try {
      const perCall = validateToolCalls(tools, policy);
      return aggregateToolScans(perCall, policy);
    } catch (exc) {
      throw new GuardError({ guardName: "tool_guard", message: String((exc as Error)?.message ?? exc), originalError: exc });
    }
  }

  private runOutputGuard(text: string, policy: Policy): ScanResult {
    try {
      return scanAndRedact(text, policy);
    } catch (exc) {
      throw new GuardError({ guardName: "output_guard", message: String((exc as Error)?.message ?? exc), originalError: exc });
    }
  }

  private buildBlockedDecision(scanResults: ScanResult[], safeOutput: string | null = null): GuardDecision {
    const maxScore = scanResults.reduce((m, r) => Math.max(m, r.score), 0.0);
    const allReasons = scanResults.flatMap((sr) => sr.reasons);

    return new GuardDecision({
      allowed: false,
      score: Math.round(maxScore * 10000) / 10000,
      reasons: allReasons,
      safeOutput,
      warned: false,
      scanResults: [...scanResults],
      action: PolicyAction.BLOCK,
    });
  }

  private buildCleanDecision(scanResults: ScanResult[], policy: Policy, safeOutput: string): GuardDecision {
    const maxScore = scanResults.reduce((m, r) => Math.max(m, r.score), 0.0);
    const allReasons = scanResults.flatMap((sr) => sr.reasons);

    const warnThreshold = policy.effectiveWarnThreshold(GuardType.OUTPUT);
    const warned = maxScore >= warnThreshold;
    const action = warned ? PolicyAction.WARN : PolicyAction.LOG;

    return new GuardDecision({
      allowed: true,
      score: Math.round(maxScore * 10000) / 10000,
      reasons: allReasons,
      safeOutput,
      warned,
      scanResults: [...scanResults],
      action,
    });
  }

  private async logAndMaybeRaise(params: {
    decision: GuardDecision;
    policy: Policy;
    messages: ChatMessage[];
    start: number;
    extra?: Record<string, unknown>;
    makeError: (reasons: string[], score: number) => BlockedByPolicyError;
  }): Promise<void> {
    const elapsedMs = performance.now() - params.start;
    this._secLogger.logDecision(params.decision, { durationMs: elapsedMs, extra: params.extra });

    if (params.policy.raiseOnBlock) {
      const exc = params.makeError(params.decision.reasons, params.decision.score);
      this.onBlocked(exc, params.messages);
      throw exc;
    }
  }
}
