/**
 * Concrete adapter wrapping the official `openai` npm SDK. Runs all guards
 * automatically around every chat() call, plus a streaming variant.
 *
 * `openai` is an optional peer dependency, loaded lazily via createRequire so
 * the constructor can fail fast (mirroring Python's eager `_get_openai()`)
 * without forcing every consumer of the package to install it.
 */
import { getSyncRequire } from "../internal/optionalRequire.js";
import { ProviderError, ProviderTimeoutError } from "../exceptions.js";
import { scanAndRedact } from "../guards/outputs.js";
import { aggregatePromptScans, scanMessages } from "../guards/prompts.js";
import { Policy } from "../policies.js";
import { GuardDecision, GuardType, PolicyAction, ToolCall } from "../types.js";
import { BaseProvider, ChatMessage, ProviderConfig } from "./base.js";

const requireOptional = getSyncRequire();

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type OpenAiModule = any;

let cachedOpenAiModule: OpenAiModule | null = null;

function getOpenAiModule(): OpenAiModule {
  if (cachedOpenAiModule) return cachedOpenAiModule;
  try {
    cachedOpenAiModule = requireOptional("openai");
    return cachedOpenAiModule;
  } catch (exc) {
    throw new ProviderError({
      message: "The openai package is required to use OpenAIProvider. Install it with: npm install openai",
      providerName: "openai",
      originalError: exc,
    });
  }
}

function wrapOpenAiError(exc: unknown, providerName: string, timeoutSeconds: number): Error {
  if (exc instanceof ProviderError || exc instanceof ProviderTimeoutError) return exc;

  const err = exc as { status?: number; message?: string; name?: string; code?: string };

  if (err?.name === "AbortError" || err?.code === "ETIMEDOUT" || err?.name === "APIConnectionTimeoutError") {
    return new ProviderTimeoutError({ providerName, timeoutSeconds, originalError: exc });
  }

  const status = err?.status;
  if (status === undefined) {
    return new ProviderError({
      message: `Could not connect to the OpenAI API: ${err?.message ?? String(exc)}`,
      providerName,
      originalError: exc,
    });
  }

  const messages: Record<number, string> = {
    401: "OpenAI API key is invalid or has expired.",
    403: "OpenAI request denied (permission error).",
    404: `OpenAI model or resource not found: ${err?.message ?? ""}`,
    400: `OpenAI rejected the request: ${err?.message ?? ""}`,
    429: "OpenAI rate limit exceeded. Retry after backing off.",
  };

  return new ProviderError({
    message: messages[status] ?? `OpenAI API error: ${err?.message ?? String(exc)}`,
    providerName,
    statusCode: status,
    originalError: exc,
  });
}

function parseOpenAiToolCalls(rawToolCalls: unknown): ToolCall[] {
  if (!Array.isArray(rawToolCalls) || rawToolCalls.length === 0) return [];

  const result: ToolCall[] = [];
  for (const tc of rawToolCalls) {
    try {
      const entry = tc as { function?: { name?: string; arguments?: string }; name?: string; arguments?: string; id?: string };
      if (entry.function) {
        const name = entry.function.name ?? "";
        let args: Record<string, unknown> = {};
        try {
          args = JSON.parse(entry.function.arguments || "{}");
        } catch {
          args = {};
        }
        result.push(new ToolCall({ name, args, callId: entry.id ?? null }));
      } else if (entry.name) {
        let args: Record<string, unknown> = {};
        try {
          args = JSON.parse(entry.arguments || "{}");
        } catch {
          args = {};
        }
        result.push(new ToolCall({ name: entry.name, args, callId: null }));
      }
    } catch {
      // skip unparsable tool call
    }
  }
  return result;
}

function buildOpenAiToolSchema(toolCall: ToolCall): Record<string, unknown> {
  const schema = toolCall.schema;
  const parameters = schema.parameters ?? schema;
  return {
    type: "function",
    function: {
      name: toolCall.name,
      description: schema.description ?? "",
      parameters,
    },
  };
}

export interface OpenAIProviderInit {
  apiKey?: string;
  model?: string;
  organization?: string;
  baseURL?: string;
  policy?: Policy;
  config?: ProviderConfig;
  defaultParams?: Record<string, unknown>;
}

export class OpenAIProvider extends BaseProvider {
  private _model: string;
  private readonly _defaultParams: Record<string, unknown>;
  private readonly _client: OpenAiModule;

  constructor(init: OpenAIProviderInit = {}) {
    super("openai", init.policy, init.config);

    this._model = init.model ?? "gpt-4o";
    this._defaultParams = init.defaultParams ?? {};

    const resolvedKey = init.apiKey || process.env.OPENAI_API_KEY || "";
    const resolvedOrg = init.organization || process.env.OPENAI_ORG_ID;

    if (!resolvedKey) {
      throw new ProviderError({
        message: "No OpenAI API key provided. Pass apiKey or set the OPENAI_API_KEY environment variable.",
        providerName: "openai",
      });
    }

    const openaiMod = getOpenAiModule();
    const OpenAiCtor = openaiMod.default ?? openaiMod;

    const clientOptions: Record<string, unknown> = {
      apiKey: resolvedKey,
      timeout: this.config.timeoutSeconds * 1000,
    };
    if (resolvedOrg) clientOptions.organization = resolvedOrg;
    if (init.baseURL) clientOptions.baseURL = init.baseURL;
    if (Object.keys(this.config.extraHeaders).length > 0) clientOptions.defaultHeaders = this.config.extraHeaders;

    this._client = new OpenAiCtor(clientOptions);
  }

  protected override async callModel(messages: ChatMessage[], kwargs: Record<string, unknown>): Promise<unknown> {
    const params: Record<string, unknown> = { ...this._defaultParams, ...kwargs };
    if (!("model" in params)) params.model = this._model;

    if (Array.isArray(params.tools)) {
      params.tools = (params.tools as unknown[]).map((item) =>
        item instanceof ToolCall ? buildOpenAiToolSchema(item) : item,
      );
    }

    try {
      return await this._client.chat.completions.create({
        messages,
        ...params,
      });
    } catch (exc) {
      throw wrapOpenAiError(exc, "openai", this.config.timeoutSeconds);
    }
  }

  protected override extractText(response: unknown): string {
    try {
      const r = response as { choices: Array<{ message: { content: unknown } }> };
      const content = r.choices[0]?.message.content;
      return typeof content === "string" ? content : "";
    } catch {
      return "";
    }
  }

  protected override extractToolCalls(response: unknown): ToolCall[] {
    try {
      const r = response as { choices: Array<{ message: { tool_calls?: unknown } }> };
      return parseOpenAiToolCalls(r.choices[0]?.message.tool_calls);
    } catch {
      return [];
    }
  }

  /**
   * Streams the model's response text chunk by chunk, then yields a final
   * GuardDecision as the generator's return value once the full text has
   * been assembled and output-scanned.
   */
  async *streamChat(
    messages: ChatMessage[],
    options: { policy?: Policy; extra?: Record<string, unknown>; kwargs?: Record<string, unknown> } = {},
  ): AsyncGenerator<string, GuardDecision | void, void> {
    const { PromptBlockedError, OutputBlockedError } = await import("../exceptions.js");

    const activePolicy = options.policy ?? this.policy;
    const start = performance.now();

    const perMsg = scanMessages(messages, activePolicy, { rolesToScan: this.config.rolesToScan });
    const combined = aggregatePromptScans(perMsg, activePolicy);

    if (!combined.allowed) {
      const decision = new GuardDecision({
        allowed: false,
        score: Math.round(combined.score * 10000) / 10000,
        reasons: combined.reasons,
        safeOutput: null,
        warned: false,
        scanResults: [combined],
        action: PolicyAction.BLOCK,
      });
      this._secLogger.logDecision(decision, { durationMs: performance.now() - start, extra: options.extra });

      if (activePolicy.raiseOnBlock) {
        throw new PromptBlockedError({
          reasons: combined.reasons,
          score: combined.score,
          decision,
          policyName: activePolicy.name,
          promptSnippet: lastUserSnippet(messages),
        });
      }
      return;
    }

    const params: Record<string, unknown> = { ...this._defaultParams, ...(options.kwargs ?? {}) };
    if (!("model" in params)) params.model = this._model;
    params.stream = true;

    let stream: AsyncIterable<{ choices?: Array<{ delta?: { content?: string } }> }>;
    try {
      stream = await this._client.chat.completions.create({ messages, ...params });
    } catch (exc) {
      throw wrapOpenAiError(exc, "openai", this.config.timeoutSeconds);
    }

    let fullText = "";
    for await (const chunk of stream) {
      const delta = chunk.choices?.[0]?.delta;
      const text = delta?.content ?? "";
      if (text) {
        fullText += text;
        yield text;
      }
    }

    const outputScan = scanAndRedact(fullText, activePolicy);
    const scanResults = [combined, outputScan];

    if (!outputScan.allowed) {
      const decision = new GuardDecision({
        allowed: false,
        score: Math.round(outputScan.score * 10000) / 10000,
        reasons: outputScan.reasons,
        safeOutput: outputScan.safeOutput,
        warned: false,
        scanResults,
        action: PolicyAction.BLOCK,
      });
      this._secLogger.logDecision(decision, { durationMs: performance.now() - start, extra: options.extra });

      if (activePolicy.raiseOnBlock) {
        throw new OutputBlockedError({
          reasons: outputScan.reasons,
          score: outputScan.score,
          outputSnippet: fullText.slice(0, 120),
          decision,
          policyName: activePolicy.name,
        });
      }
      yield "[BLOCKED]";
      return;
    }

    const maxScore = Math.max(combined.score, outputScan.score);
    const warnThreshold = activePolicy.effectiveWarnThreshold(GuardType.OUTPUT);
    const warned = maxScore >= warnThreshold;
    const action = warned ? PolicyAction.WARN : PolicyAction.LOG;

    const decision = new GuardDecision({
      allowed: true,
      score: Math.round(maxScore * 10000) / 10000,
      reasons: [...combined.reasons, ...outputScan.reasons],
      safeOutput: outputScan.safeOutput ?? fullText,
      warned,
      scanResults,
      action,
    });
    this._secLogger.logDecision(decision, { durationMs: performance.now() - start, extra: options.extra });
    return decision;
  }

  async chatWithToolDefinitions(
    messages: ChatMessage[],
    toolDefinitions: Array<Record<string, unknown>>,
    options: { policy?: Policy; extra?: Record<string, unknown>; kwargs?: Record<string, unknown> } = {},
  ): Promise<GuardDecision> {
    const guardTools = toolDefinitions
      .filter((td) => {
        const fn = td.function as Record<string, unknown> | undefined;
        return typeof fn?.name === "string" && fn.name.length > 0;
      })
      .map((td) => {
        const fn = td.function as Record<string, unknown>;
        return new ToolCall({ name: fn.name as string, args: {}, schema: fn });
      });

    return this.chat(messages, {
      policy: options.policy,
      extra: options.extra,
      tools: guardTools,
      kwargs: options.kwargs,
    });
  }

  get model(): string {
    return this._model;
  }

  set model(value: string) {
    if (!value || !value.trim()) throw new Error("model must be a non-empty string");
    this._model = value;
  }

  get client(): OpenAiModule {
    return this._client;
  }
}

function lastUserSnippet(messages: ChatMessage[], maxLen = 120): string {
  for (let i = messages.length - 1; i >= 0; i--) {
    const msg = messages[i];
    if (msg && msg.role === "user") return (msg.content ?? "").slice(0, maxLen);
  }
  return "";
}
