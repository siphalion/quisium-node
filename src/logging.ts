/**
 * Structured security-event logging: SecurityEvent, a pluggable handler registry,
 * and log_decision / log_scan_result / log_tool_call helpers.
 */
import type { Policy } from "./policies.js";
import type { GuardDecision, ScanResult, ToolCall } from "./types.js";

export const LogFormat = {
  JSON: "json",
  TEXT: "text",
} as const;
export type LogFormat = (typeof LogFormat)[keyof typeof LogFormat];

export const EventType = {
  DECISION: "decision",
  SCAN: "scan",
  TOOL_CALL: "tool_call",
} as const;
export type EventType = (typeof EventType)[keyof typeof EventType];

export interface SecurityLogger {
  info: (message: string) => void;
  warn: (message: string) => void;
  error: (message: string) => void;
}

const defaultLogger: SecurityLogger = {
  info: (m) => console.log(m),
  warn: (m) => console.warn(m),
  error: (m) => console.error(m),
};

const internalLogger: SecurityLogger = defaultLogger;

export interface SecurityEventInit {
  eventType: EventType;
  timestamp: string;
  allowed: boolean;
  score: number;
  riskLevel: string;
  reasons: string[];
  action: string;
  guardType?: string | null;
  policyName?: string;
  providerName?: string;
  toolName?: string | null;
  toolCallId?: string | null;
  safeOutputPresent?: boolean;
  durationMs?: number | null;
  traceId?: string | null;
  spanId?: string | null;
  extra?: Record<string, unknown>;
}

export interface SecurityEventDict {
  event_type: EventType;
  timestamp: string;
  allowed: boolean;
  score: number;
  risk_level: string;
  reasons: string[];
  action: string;
  guard_type: string | null;
  policy_name: string;
  provider_name: string;
  tool_name: string | null;
  tool_call_id: string | null;
  safe_output_present: boolean;
  duration_ms: number | null;
  trace_id: string | null;
  span_id: string | null;
  extra: Record<string, unknown>;
}

export class SecurityEvent {
  readonly eventType: EventType;
  readonly timestamp: string;
  readonly allowed: boolean;
  readonly score: number;
  readonly riskLevel: string;
  readonly reasons: string[];
  readonly action: string;
  readonly guardType: string | null;
  readonly policyName: string;
  readonly providerName: string;
  readonly toolName: string | null;
  readonly toolCallId: string | null;
  readonly safeOutputPresent: boolean;
  readonly durationMs: number | null;
  readonly traceId: string | null;
  readonly spanId: string | null;
  readonly extra: Record<string, unknown>;

  constructor(init: SecurityEventInit) {
    this.eventType = init.eventType;
    this.timestamp = init.timestamp;
    this.allowed = init.allowed;
    this.score = init.score;
    this.riskLevel = init.riskLevel;
    this.reasons = init.reasons;
    this.action = init.action;
    this.guardType = init.guardType ?? null;
    this.policyName = init.policyName ?? "unknown";
    this.providerName = init.providerName ?? "unknown";
    this.toolName = init.toolName ?? null;
    this.toolCallId = init.toolCallId ?? null;
    this.safeOutputPresent = init.safeOutputPresent ?? false;
    this.durationMs = init.durationMs ?? null;
    this.traceId = init.traceId ?? null;
    this.spanId = init.spanId ?? null;
    this.extra = init.extra ?? {};
  }

  toDict(): SecurityEventDict {
    return {
      event_type: this.eventType,
      timestamp: this.timestamp,
      allowed: this.allowed,
      score: this.score,
      risk_level: this.riskLevel,
      reasons: this.reasons,
      action: this.action,
      guard_type: this.guardType,
      policy_name: this.policyName,
      provider_name: this.providerName,
      tool_name: this.toolName,
      tool_call_id: this.toolCallId,
      safe_output_present: this.safeOutputPresent,
      duration_ms: this.durationMs,
      trace_id: this.traceId,
      span_id: this.spanId,
      extra: this.extra,
    };
  }

  toJSON(): SecurityEventDict {
    return this.toDict();
  }

  toText(): string {
    const parts: string[] = [
      `event=${this.eventType}`,
      `ts=${this.timestamp.slice(0, 19)}Z`,
      `allowed=${this.allowed}`,
      `score=${this.score.toFixed(4)}`,
      `risk=${this.riskLevel}`,
      `action=${this.action}`,
      `policy=${this.policyName}`,
      `provider=${this.providerName}`,
    ];
    if (this.guardType) parts.push(`guard=${this.guardType}`);
    if (this.toolName) parts.push(`tool=${this.toolName}`);
    if (this.toolCallId) parts.push(`call_id=${this.toolCallId}`);
    if (this.durationMs !== null) parts.push(`duration_ms=${this.durationMs.toFixed(1)}`);
    if (this.traceId) parts.push(`trace_id=${this.traceId}`);
    if (this.reasons.length > 0) parts.push(`reasons="${this.reasons.join("; ")}"`);
    for (const [k, v] of Object.entries(this.extra)) {
      parts.push(`${k}=${JSON.stringify(v)}`);
    }
    return parts.join(" ");
  }
}

export type SecurityEventHandler = (event: SecurityEvent) => void;

const handlers: SecurityEventHandler[] = [];

export function addHandler(handler: SecurityEventHandler): void {
  handlers.push(handler);
}

export function removeHandler(handler: SecurityEventHandler): void {
  const idx = handlers.indexOf(handler);
  if (idx !== -1) handlers.splice(idx, 1);
}

export function clearHandlers(): void {
  handlers.length = 0;
}

function dispatch(event: SecurityEvent): void {
  for (const handler of handlers) {
    try {
      handler(event);
    } catch (exc) {
      internalLogger.error(
        `Quisium: custom handler ${String(handler)} raised an exception:\n${String(exc)}`,
      );
    }
  }
}

function utcNowIso(): string {
  return new Date().toISOString();
}

function writeToLogger(event: SecurityEvent, logger: SecurityLogger, fmt: LogFormat): void {
  const message = fmt === LogFormat.JSON ? JSON.stringify(event.toDict()) : event.toText();
  if (!event.allowed) {
    logger.error(message);
  } else if (event.action === "warn") {
    logger.warn(message);
  } else {
    logger.info(message);
  }
}

export interface LogDecisionOptions {
  policy?: Policy | null;
  providerName?: string;
  logger?: SecurityLogger;
  fmt?: LogFormat;
  durationMs?: number | null;
  traceId?: string | null;
  spanId?: string | null;
  extra?: Record<string, unknown>;
}

export function logDecision(decision: GuardDecision, options: LogDecisionOptions = {}): SecurityEvent {
  const targetLogger = options.logger ?? internalLogger;
  const event = new SecurityEvent({
    eventType: EventType.DECISION,
    timestamp: utcNowIso(),
    allowed: decision.allowed,
    score: Math.round(decision.score * 10000) / 10000,
    riskLevel: decision.riskLevel,
    reasons: [...decision.reasons],
    action: decision.action,
    policyName: options.policy?.name ?? "unknown",
    providerName: options.providerName ?? "unknown",
    safeOutputPresent: decision.safeOutput !== null,
    durationMs: options.durationMs ?? null,
    traceId: options.traceId ?? null,
    spanId: options.spanId ?? null,
    extra: options.extra ?? {},
  });

  writeToLogger(event, targetLogger, options.fmt ?? LogFormat.JSON);
  dispatch(event);
  return event;
}

export interface LogScanResultOptions {
  policy?: Policy | null;
  providerName?: string;
  logger?: SecurityLogger;
  fmt?: LogFormat;
  extra?: Record<string, unknown>;
}

export function logScanResult(result: ScanResult, options: LogScanResultOptions = {}): SecurityEvent {
  const targetLogger = options.logger ?? internalLogger;
  const event = new SecurityEvent({
    eventType: EventType.SCAN,
    timestamp: utcNowIso(),
    allowed: result.allowed,
    score: Math.round(result.score * 10000) / 10000,
    riskLevel: result.riskLevel,
    reasons: [...result.reasons],
    action: result.allowed ? "log" : "block",
    guardType: result.guardType,
    policyName: options.policy?.name ?? "unknown",
    providerName: options.providerName ?? "unknown",
    extra: options.extra ?? {},
  });

  writeToLogger(event, targetLogger, options.fmt ?? LogFormat.JSON);
  dispatch(event);
  return event;
}

export interface LogToolCallOptions {
  policy?: Policy | null;
  providerName?: string;
  logger?: SecurityLogger;
  fmt?: LogFormat;
  extra?: Record<string, unknown>;
}

export function logToolCall(
  toolCall: ToolCall,
  result: ScanResult | null = null,
  options: LogToolCallOptions = {},
): SecurityEvent {
  const targetLogger = options.logger ?? internalLogger;

  const allowed = result ? result.allowed : true;
  const score = result ? Math.round(result.score * 10000) / 10000 : 0.0;
  const riskLevel = result ? result.riskLevel : "none";
  const reasons = result ? [...result.reasons] : [];
  const action = result ? (result.allowed ? "log" : "block") : "log";

  const event = new SecurityEvent({
    eventType: EventType.TOOL_CALL,
    timestamp: utcNowIso(),
    allowed,
    score,
    riskLevel,
    reasons,
    action,
    guardType: "tool",
    policyName: options.policy?.name ?? "unknown",
    providerName: options.providerName ?? "unknown",
    toolName: toolCall.name,
    toolCallId: toolCall.callId,
    extra: options.extra ?? {},
  });

  writeToLogger(event, targetLogger, options.fmt ?? LogFormat.JSON);
  dispatch(event);
  return event;
}

export interface SecurityEventLoggerInit {
  policy?: Policy | null;
  providerName?: string;
  fmt?: LogFormat;
  logger?: SecurityLogger;
  defaultExtra?: Record<string, unknown>;
}

/** A stateful wrapper around log_decision/log_scan_result/log_tool_call bound to one policy/provider. */
export class SecurityEventLogger {
  policy: Policy | null;
  providerName: string;
  fmt: LogFormat;
  logger: SecurityLogger;
  defaultExtra: Record<string, unknown>;

  constructor(init: SecurityEventLoggerInit = {}) {
    this.policy = init.policy ?? null;
    this.providerName = init.providerName ?? "unknown";
    this.fmt = init.fmt ?? LogFormat.JSON;
    this.logger = init.logger ?? internalLogger;
    this.defaultExtra = init.defaultExtra ?? {};
  }

  private mergeExtra(extra?: Record<string, unknown>): Record<string, unknown> {
    return { ...this.defaultExtra, ...(extra ?? {}) };
  }

  logDecision(
    decision: GuardDecision,
    options: { durationMs?: number | null; traceId?: string | null; spanId?: string | null; extra?: Record<string, unknown> } = {},
  ): SecurityEvent {
    return logDecision(decision, {
      policy: this.policy,
      providerName: this.providerName,
      logger: this.logger,
      fmt: this.fmt,
      durationMs: options.durationMs,
      traceId: options.traceId,
      spanId: options.spanId,
      extra: this.mergeExtra(options.extra),
    });
  }

  logScanResult(result: ScanResult, options: { extra?: Record<string, unknown> } = {}): SecurityEvent {
    return logScanResult(result, {
      policy: this.policy,
      providerName: this.providerName,
      logger: this.logger,
      fmt: this.fmt,
      extra: this.mergeExtra(options.extra),
    });
  }

  logToolCall(
    toolCall: ToolCall,
    result: ScanResult | null = null,
    options: { extra?: Record<string, unknown> } = {},
  ): SecurityEvent {
    return logToolCall(toolCall, result, {
      policy: this.policy,
      providerName: this.providerName,
      logger: this.logger,
      fmt: this.fmt,
      extra: this.mergeExtra(options.extra),
    });
  }
}
