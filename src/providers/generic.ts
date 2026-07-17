/**
 * A provider that accepts any callable as the LLM client — the caller supplies
 * a call function and an extractor; this adapter runs the full guard pipeline
 * around it.
 */
import { ProviderError, ProviderTimeoutError } from "../exceptions.js";
import { Policy } from "../policies.js";
import { ToolCall } from "../types.js";
import { BaseProvider, ChatMessage, ProviderConfig } from "./base.js";

export type CallFn = (
  messages: ChatMessage[],
  kwargs: Record<string, unknown>,
) => unknown | Promise<unknown>;

export type ExtractFn = (response: unknown) => string;

export type ExtractToolsFn = (response: unknown) => ToolCall[];

export interface GenericProviderInit {
  callFn: CallFn;
  extractFn: ExtractFn;
  extractToolsFn?: ExtractToolsFn;
  providerName?: string;
  policy?: Policy;
  config?: ProviderConfig;
}

export class GenericProvider extends BaseProvider {
  private readonly callFn: CallFn;
  private readonly extractFn: ExtractFn;
  private readonly extractToolsFn?: ExtractToolsFn;

  constructor(init: GenericProviderInit) {
    super(init.providerName ?? "generic", init.policy, init.config);

    if (typeof init.callFn !== "function") {
      throw new TypeError(`callFn must be callable, got ${typeof init.callFn}`);
    }
    if (typeof init.extractFn !== "function") {
      throw new TypeError(`extractFn must be callable, got ${typeof init.extractFn}`);
    }
    if (init.extractToolsFn !== undefined && typeof init.extractToolsFn !== "function") {
      throw new TypeError(`extractToolsFn must be callable or undefined, got ${typeof init.extractToolsFn}`);
    }

    this.callFn = init.callFn;
    this.extractFn = init.extractFn;
    this.extractToolsFn = init.extractToolsFn;
  }

  protected override async callModel(messages: ChatMessage[], kwargs: Record<string, unknown>): Promise<unknown> {
    try {
      return await this.callFn(messages, kwargs);
    } catch (exc) {
      if (exc instanceof ProviderError || exc instanceof ProviderTimeoutError) throw exc;
      throw new ProviderError({
        message: String((exc as Error)?.message ?? exc),
        providerName: this.providerName,
        originalError: exc,
      });
    }
  }

  protected override extractText(response: unknown): string {
    try {
      const result = this.extractFn(response);
      return typeof result === "string" ? result : result ? String(result) : "";
    } catch {
      return "";
    }
  }

  protected override extractToolCalls(response: unknown): ToolCall[] {
    if (!this.extractToolsFn) return [];
    try {
      const result = this.extractToolsFn(response);
      return Array.isArray(result) ? result : [];
    } catch {
      return [];
    }
  }

  static fromOpenAiCompatibleUrl(options: {
    url: string;
    model: string;
    apiKey?: string;
    providerName?: string;
    policy?: Policy;
    config?: ProviderConfig;
    extraHeaders?: Record<string, string>;
  }): GenericProvider {
    const providerName = options.providerName ?? "generic-openai-compat";
    const resolvedConfig = options.config ?? new ProviderConfig();
    const timeout = resolvedConfig.timeoutSeconds;

    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      Accept: "application/json",
    };
    if (options.apiKey) headers.Authorization = `Bearer ${options.apiKey}`;
    if (options.extraHeaders) Object.assign(headers, options.extraHeaders);

    const callFn: CallFn = async (messages, kwargs) => {
      const { model: modelOverride, ...rest } = kwargs;
      const body = {
        model: modelOverride ?? options.model,
        messages,
        ...rest,
      };

      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeout * 1000);
      try {
        const resp = await fetch(options.url, {
          method: "POST",
          headers,
          body: JSON.stringify(body),
          signal: controller.signal,
        });

        if (!resp.ok) {
          const bodyText = (await resp.text().catch(() => "")).slice(0, 300);
          throw new ProviderError({
            message: `HTTP ${resp.status} from ${providerName}: ${resp.statusText}. Body: ${bodyText}`,
            providerName,
            statusCode: resp.status,
          });
        }
        return await resp.json();
      } catch (exc) {
        if (exc instanceof ProviderError) throw exc;
        if (exc instanceof Error && exc.name === "AbortError") {
          throw new ProviderTimeoutError({ providerName, timeoutSeconds: timeout, originalError: exc });
        }
        throw new ProviderError({
          message: `Request to ${providerName} failed: ${String((exc as Error)?.message ?? exc)}`,
          providerName,
          originalError: exc,
        });
      } finally {
        clearTimeout(timer);
      }
    };

    const extractFn: ExtractFn = (response) => {
      try {
        const r = response as { choices?: Array<{ message?: { content?: string } }> };
        return r.choices?.[0]?.message?.content ?? "";
      } catch {
        return "";
      }
    };

    return new GenericProvider({
      callFn,
      extractFn,
      providerName,
      policy: options.policy,
      config: resolvedConfig,
    });
  }

  static fromCallable(
    fn: (messages: ChatMessage[], kwargs: Record<string, unknown>) => unknown | Promise<unknown>,
    options: { providerName?: string; policy?: Policy; config?: ProviderConfig } = {},
  ): GenericProvider {
    return new GenericProvider({
      callFn: fn,
      extractFn: (r) => (typeof r === "string" ? r : String(r)),
      providerName: options.providerName ?? "callable",
      policy: options.policy,
      config: options.config,
    });
  }
}
