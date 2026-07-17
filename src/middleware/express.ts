/**
 * Express integration. Combines the two patterns the Python package offered
 * separately per-framework:
 *   - `guardRoute` (+ `quisiumErrorHandler`): a per-route guard that throws
 *     PromptBlockedError/OutputBlockedError, caught by an Express error
 *     middleware — the Node analogue of FastAPI's GuardedRoute dependency
 *     and add_exception_handlers().
 *   - `quisiumMiddleware`: a blanket, path-filtered middleware that scans
 *     both the request and the JSON response body directly, writing a
 *     blocked JSON response itself with no error-handler required — the
 *     analogue of QuisiumMiddleware in both fastapi.py and flask.py.
 *
 * Express doesn't auto-parse JSON bodies, so `express.json()` must run
 * upstream of these middlewares — they read `req.body`, not raw bytes.
 */
import type { ErrorRequestHandler, NextFunction, Request, RequestHandler, Response } from "express";
import { BlockedByPolicyError, OutputBlockedError, PromptBlockedError } from "../exceptions.js";
import { scanAndRedact } from "../guards/outputs.js";
import { aggregatePromptScans, scanMessages, type ChatMessageLike } from "../guards/prompts.js";
import { getDefaultPolicy } from "../config.js";
import { LogFormat, SecurityEventLogger } from "../logging.js";
import { Policy } from "../policies.js";
import { GuardDecision, GuardType, PolicyAction } from "../types.js";

/** Request property where guard middleware stores the GuardDecision. */
export const GUARD_DECISION_KEY = "quisiumDecision" as const;
/** Request property where guard middleware stores the active policy. */
export const GUARD_POLICY_KEY = "quisiumPolicy" as const;

declare module "express-serve-static-core" {
  interface Request {
    [GUARD_DECISION_KEY]?: GuardDecision;
    [GUARD_POLICY_KEY]?: Policy;
  }
}

const DEFAULT_SCAN_PATHS = ["/chat", "/v1/chat", "/v1/messages", "/api/chat"];
const MESSAGE_FIELD_NAMES = ["messages", "prompt", "input", "query", "text"];
const OUTPUT_FIELD_NAMES = ["content", "output", "text", "response", "message", "choices"];

function normaliseMessages(raw: unknown[]): ChatMessageLike[] {
  const out: ChatMessageLike[] = [];
  for (const item of raw) {
    if (item && typeof item === "object" && !Array.isArray(item)) {
      const obj = item as Record<string, unknown>;
      const content = obj.content;
      const role = obj.role ?? "user";
      if (typeof content === "string") {
        out.push({ role: String(role), content });
      }
    } else if (typeof item === "string" && item.trim()) {
      out.push({ role: "user", content: item });
    }
  }
  return out;
}

function extractMessagesFromBody(body: unknown, messagesField?: string): ChatMessageLike[] {
  if (!body || typeof body !== "object" || Array.isArray(body)) return [];
  const obj = body as Record<string, unknown>;

  if (messagesField) {
    const value = obj[messagesField];
    if (Array.isArray(value)) return normaliseMessages(value);
    if (typeof value === "string" && value.trim()) return [{ role: "user", content: value }];
  }

  for (const field of MESSAGE_FIELD_NAMES) {
    const value = obj[field];
    if (Array.isArray(value) && value.length > 0) return normaliseMessages(value);
    if (typeof value === "string" && value.trim()) return [{ role: "user", content: value }];
  }

  return [];
}

function extractLastUserContent(messages: ChatMessageLike[]): string {
  for (let i = messages.length - 1; i >= 0; i--) {
    const msg = messages[i];
    if (msg && msg.role === "user") return (msg.content ?? "").slice(0, 120);
  }
  return "";
}

function extractOutputText(body: unknown): string {
  if (!body || typeof body !== "object" || Array.isArray(body)) return "";
  const obj = body as Record<string, unknown>;

  const choices = obj.choices;
  if (Array.isArray(choices) && choices.length > 0) {
    const first = choices[0];
    if (first && typeof first === "object") {
      const f = first as Record<string, unknown>;
      const msg = f.message as Record<string, unknown> | undefined;
      if (msg && typeof msg.content === "string" && msg.content.trim()) return msg.content;
      const delta = f.delta as Record<string, unknown> | undefined;
      if (delta && typeof delta.content === "string" && delta.content.trim()) return delta.content;
    }
  }

  for (const field of OUTPUT_FIELD_NAMES) {
    const value = obj[field];
    if (typeof value === "string" && value.trim()) return value;
  }

  return "";
}

function replaceOutputText(body: unknown, originalText: string, safeText: string): unknown {
  if (originalText === safeText) return body;
  if (!body || typeof body !== "object" || Array.isArray(body)) return body;
  const obj = body as Record<string, unknown>;

  const choices = obj.choices;
  if (Array.isArray(choices) && choices.length > 0) {
    const first = choices[0];
    if (first && typeof first === "object") {
      const f = first as Record<string, unknown>;
      const msg = f.message as Record<string, unknown> | undefined;
      if (msg && msg.content === originalText) {
        msg.content = safeText;
        return obj;
      }
    }
  }

  for (const field of OUTPUT_FIELD_NAMES) {
    if (obj[field] === originalText) {
      obj[field] = safeText;
      return obj;
    }
  }

  return obj;
}

function blockedBody(decision: GuardDecision, includeReasons: boolean): Record<string, unknown> {
  const body: Record<string, unknown> = {
    error: "request_blocked",
    message: "This request was blocked by the LLM security policy.",
    score: decision.score,
    action: decision.action,
  };
  if (includeReasons) body.reasons = decision.reasons;
  return body;
}

export interface DecisionResponseOptions {
  blockedStatusCode?: number;
  includeReasons?: boolean;
}

/** Returns `{ status, body }` if the decision was blocked, else null. */
export function decisionResponse(
  decision: GuardDecision,
  options: DecisionResponseOptions = {},
): { status: number; body: Record<string, unknown> } | null {
  if (decision.allowed) return null;
  return {
    status: options.blockedStatusCode ?? 400,
    body: blockedBody(decision, options.includeReasons ?? true),
  };
}

export interface GuardMessagesOptions {
  rolesToScan?: string[];
  raiseOnBlock?: boolean;
  extra?: Record<string, unknown>;
}

export function guardMessages(
  messages: ChatMessageLike[],
  policy?: Policy,
  options: GuardMessagesOptions = {},
): GuardDecision {
  const activePolicy = policy ?? getDefaultPolicy();
  const perMsg = scanMessages(messages, activePolicy, { rolesToScan: options.rolesToScan ?? ["user"] });
  const combined = aggregatePromptScans(perMsg, activePolicy);
  const action = activePolicy.actionForScore(combined.score, GuardType.PROMPT);

  const decision = new GuardDecision({
    allowed: combined.allowed,
    score: combined.score,
    reasons: combined.reasons,
    safeOutput: null,
    warned: action === PolicyAction.WARN,
    scanResults: perMsg,
    action,
  });

  const shouldRaise = options.raiseOnBlock ?? activePolicy.raiseOnBlock;
  if (!combined.allowed && shouldRaise) {
    throw new PromptBlockedError({
      reasons: combined.reasons,
      score: combined.score,
      decision,
      policyName: activePolicy.name,
      promptSnippet: extractLastUserContent(messages),
    });
  }

  return decision;
}

export interface GuardOutputOptions {
  raiseOnBlock?: boolean;
  extra?: Record<string, unknown>;
}

export function guardOutput(text: string, policy?: Policy, options: GuardOutputOptions = {}): GuardDecision {
  const activePolicy = policy ?? getDefaultPolicy();
  const scan = scanAndRedact(text, activePolicy);
  const action = activePolicy.actionForScore(scan.score, GuardType.OUTPUT);

  const decision = new GuardDecision({
    allowed: scan.allowed,
    score: scan.score,
    reasons: scan.reasons,
    safeOutput: scan.safeOutput,
    warned: action === PolicyAction.WARN,
    scanResults: [scan],
    action,
  });

  const shouldRaise = options.raiseOnBlock ?? activePolicy.raiseOnBlock;
  if (!scan.allowed && shouldRaise) {
    throw new OutputBlockedError({
      reasons: scan.reasons,
      score: scan.score,
      outputSnippet: text.slice(0, 120),
      decision,
      policyName: activePolicy.name,
    });
  }

  return decision;
}

export function getDecision(req: Request): GuardDecision | undefined {
  return req[GUARD_DECISION_KEY];
}

export interface GuardRouteOptions {
  policy?: Policy;
  rolesToScan?: string[];
  messagesField?: string;
  provider_name?: string;
}

/**
 * Per-route request guard. Scans req.body for messages, attaches the
 * decision to req[GUARD_DECISION_KEY], and calls next(err) with a
 * PromptBlockedError when blocked and policy.raiseOnBlock is true — pair
 * with quisiumErrorHandler() to render the JSON response.
 */
export function guardRoute(options: GuardRouteOptions = {}): RequestHandler {
  const policy = options.policy ?? getDefaultPolicy();
  const rolesToScan = options.rolesToScan ?? ["user"];
  const secLogger = new SecurityEventLogger({ policy, providerName: "express" });

  return (req: Request, _res: Response, next: NextFunction) => {
    const start = performance.now();
    const messages = extractMessagesFromBody(req.body, options.messagesField);

    if (messages.length === 0) {
      const clean = GuardDecision.clean(null);
      req[GUARD_DECISION_KEY] = clean;
      req[GUARD_POLICY_KEY] = policy;
      next();
      return;
    }

    const perMsg = scanMessages(messages, policy, { rolesToScan });
    const combined = aggregatePromptScans(perMsg, policy);
    const action = policy.actionForScore(combined.score, GuardType.PROMPT);

    const decision = new GuardDecision({
      allowed: combined.allowed,
      score: combined.score,
      reasons: combined.reasons,
      safeOutput: null,
      warned: action === PolicyAction.WARN,
      scanResults: perMsg,
      action,
    });

    secLogger.logDecision(decision, { durationMs: performance.now() - start });

    req[GUARD_DECISION_KEY] = decision;
    req[GUARD_POLICY_KEY] = policy;

    if (!decision.allowed && policy.raiseOnBlock) {
      next(
        new PromptBlockedError({
          reasons: decision.reasons,
          score: decision.score,
          decision,
          policyName: policy.name,
          promptSnippet: extractLastUserContent(messages),
        }),
      );
      return;
    }

    next();
  };
}

export interface QuisiumErrorHandlerOptions {
  includeReasons?: boolean;
}

/** Express error middleware rendering PromptBlockedError/OutputBlockedError/BlockedByPolicyError as JSON. */
export function quisiumErrorHandler(options: QuisiumErrorHandlerOptions = {}): ErrorRequestHandler {
  return (err: unknown, _req: Request, res: Response, next: NextFunction) => {
    if (err instanceof PromptBlockedError) {
      res.status(400).json({
        error: "prompt_blocked",
        message: "The request was blocked by the prompt security policy.",
        score: err.score,
        reasons: options.includeReasons === false ? undefined : err.reasons,
      });
      return;
    }
    if (err instanceof OutputBlockedError) {
      res.status(400).json({
        error: "output_blocked",
        message: "The model response was blocked by the output security policy.",
        score: err.score,
        reasons: options.includeReasons === false ? undefined : err.reasons,
      });
      return;
    }
    if (err instanceof BlockedByPolicyError) {
      res.status(400).json({
        error: "blocked_by_policy",
        message: "The request was blocked by the security policy.",
        score: err.score,
        reasons: options.includeReasons === false ? undefined : err.reasons,
      });
      return;
    }
    next(err);
  };
}

export interface QuisiumMiddlewareOptions {
  policy?: Policy;
  scanPaths?: string[];
  scanOutput?: boolean;
  rolesToScan?: string[];
  blockStatus?: number;
  includeReasons?: boolean;
  logFormat?: LogFormat;
  messagesField?: string;
}

/**
 * Blanket middleware: scans the request body for the configured path
 * prefixes, then (if scanOutput) wraps res.json to scan/redact the response
 * body too. Blocked requests get a JSON response written directly — no
 * error handler needed.
 */
export function quisiumMiddleware(options: QuisiumMiddlewareOptions = {}): RequestHandler {
  const policy = options.policy ?? getDefaultPolicy();
  const scanPaths = options.scanPaths ?? DEFAULT_SCAN_PATHS;
  const scanOutputEnabled = options.scanOutput ?? true;
  const rolesToScan = options.rolesToScan ?? ["user"];
  const blockStatus = options.blockStatus ?? 400;
  const includeReasons = options.includeReasons ?? true;
  const secLogger = new SecurityEventLogger({
    policy,
    providerName: "express-middleware",
    fmt: options.logFormat ?? LogFormat.JSON,
  });

  const shouldScan = (path: string) => scanPaths.some((p) => path.startsWith(p));

  return (req: Request, res: Response, next: NextFunction) => {
    if (!shouldScan(req.path)) {
      next();
      return;
    }

    const start = performance.now();
    const messages = extractMessagesFromBody(req.body, options.messagesField);

    if (messages.length > 0) {
      const perMsg = scanMessages(messages, policy, { rolesToScan });
      const combined = aggregatePromptScans(perMsg, policy);
      const action = policy.actionForScore(combined.score, GuardType.PROMPT);

      const pDecision = new GuardDecision({
        allowed: combined.allowed,
        score: combined.score,
        reasons: combined.reasons,
        safeOutput: null,
        warned: action === PolicyAction.WARN,
        scanResults: perMsg,
        action,
      });
      secLogger.logDecision(pDecision, { durationMs: performance.now() - start });

      req[GUARD_DECISION_KEY] = pDecision;
      req[GUARD_POLICY_KEY] = policy;

      if (!combined.allowed) {
        res.status(blockStatus).json(blockedBody(pDecision, includeReasons));
        return;
      }
    }

    if (!scanOutputEnabled) {
      next();
      return;
    }

    const originalJson = res.json.bind(res);
    res.json = ((body: unknown) => {
      const text = extractOutputText(body);
      if (!text) {
        return originalJson(body);
      }

      const outScan = scanAndRedact(text, policy);
      const outAction = policy.actionForScore(outScan.score, GuardType.OUTPUT);

      const oDecision = new GuardDecision({
        allowed: outScan.allowed,
        score: outScan.score,
        reasons: outScan.reasons,
        safeOutput: outScan.safeOutput,
        warned: outAction === PolicyAction.WARN,
        scanResults: [outScan],
        action: outAction,
      });
      secLogger.logDecision(oDecision, { durationMs: performance.now() - start });

      if (!outScan.allowed) {
        res.status(blockStatus);
        return originalJson(blockedBody(oDecision, includeReasons));
      }

      const safeText = outScan.safeOutput ?? text;
      const newBody = replaceOutputText(body, text, safeText);
      return originalJson(newBody);
    }) as Response["json"];

    next();
  };
}

/** Deprecated alias, kept for parity with the Python package's naming. */
export const LLMSecurityMiddleware = quisiumMiddleware;
