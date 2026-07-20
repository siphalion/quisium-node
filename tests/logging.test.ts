import { describe, it, expect, vi } from "vitest";
import {
  EventType,
  LogFormat,
  SecurityEvent,
  SecurityEventLogger,
  addHandler,
  clearHandlers,
  removeHandler,
  logDecision,
  logScanResult,
  logToolCall,
  type SecurityEventInit,
} from "../src/logging.js";
import { GuardDecision, GuardType, ScanResult, ToolCall } from "../src/types.js";
import { balancedPolicy } from "./helpers.js";

function cleanDecision() {
  return GuardDecision.clean("The capital is Paris.");
}

function blockedDecision() {
  return GuardDecision.blocked(["injection detected"], 0.92);
}

function cleanScan() {
  return new ScanResult({ allowed: true, score: 0.0, guardType: GuardType.PROMPT });
}

function blockedScan() {
  return new ScanResult({
    allowed: false,
    score: 0.92,
    reasons: ["injection"],
    guardType: GuardType.PROMPT,
  });
}

function safeToolCall() {
  return new ToolCall({ name: "search_web", args: { query: "python" }, callId: "call_abc" });
}

/** Registers a handler collecting every dispatched SecurityEvent, mirroring the Python captured_events fixture. */
function captureEvents(): SecurityEvent[] {
  const events: SecurityEvent[] = [];
  addHandler((e) => events.push(e));
  return events;
}

const baseEventInit: SecurityEventInit = {
  eventType: EventType.DECISION,
  timestamp: "2025-03-09T14:23:01.456789+00:00",
  allowed: true,
  score: 0.0,
  riskLevel: "none",
  reasons: [],
  action: "log",
};

function makeEvent(overrides: Partial<SecurityEventInit> = {}): SecurityEvent {
  return new SecurityEvent({ ...baseEventInit, ...overrides });
}

describe("LogFormat", () => {
  it("JSON value is 'json'", () => {
    expect(LogFormat.JSON).toBe("json");
  });

  it("TEXT value is 'text'", () => {
    expect(LogFormat.TEXT).toBe("text");
  });
});

describe("EventType", () => {
  it("DECISION value is 'decision'", () => {
    expect(EventType.DECISION).toBe("decision");
  });

  it("SCAN value is 'scan'", () => {
    expect(EventType.SCAN).toBe("scan");
  });

  it("TOOL_CALL value is 'tool_call'", () => {
    expect(EventType.TOOL_CALL).toBe("tool_call");
  });
});

describe("SecurityEvent construction", () => {
  it("stores eventType", () => {
    expect(makeEvent({ eventType: EventType.SCAN }).eventType).toBe(EventType.SCAN);
  });

  it("stores timestamp", () => {
    const ts = "2025-03-09T14:23:01.456789+00:00";
    expect(makeEvent({ timestamp: ts }).timestamp).toBe(ts);
  });

  it("stores allowed", () => {
    expect(makeEvent({ allowed: false }).allowed).toBe(false);
  });

  it("stores score", () => {
    expect(makeEvent({ score: 0.92 }).score).toBe(0.92);
  });

  it("stores riskLevel", () => {
    expect(makeEvent({ riskLevel: "critical" }).riskLevel).toBe("critical");
  });

  it("stores reasons", () => {
    expect(makeEvent({ reasons: ["r1", "r2"] }).reasons).toEqual(["r1", "r2"]);
  });

  it("stores action", () => {
    expect(makeEvent({ action: "block" }).action).toBe("block");
  });

  it("defaults guardType to null", () => {
    expect(makeEvent().guardType).toBeNull();
  });

  it("defaults policyName to 'unknown'", () => {
    expect(makeEvent().policyName).toBe("unknown");
  });

  it("defaults providerName to 'unknown'", () => {
    expect(makeEvent().providerName).toBe("unknown");
  });

  it("defaults toolName to null", () => {
    expect(makeEvent().toolName).toBeNull();
  });

  it("defaults toolCallId to null", () => {
    expect(makeEvent().toolCallId).toBeNull();
  });

  it("defaults safeOutputPresent to false", () => {
    expect(makeEvent().safeOutputPresent).toBe(false);
  });

  it("defaults durationMs to null", () => {
    expect(makeEvent().durationMs).toBeNull();
  });

  it("defaults traceId to null", () => {
    expect(makeEvent().traceId).toBeNull();
  });

  it("defaults spanId to null", () => {
    expect(makeEvent().spanId).toBeNull();
  });

  it("defaults extra to an empty object", () => {
    expect(makeEvent().extra).toEqual({});
  });

  it("does not share extra between instances", () => {
    const e1 = makeEvent();
    const e2 = makeEvent();
    e1.extra["k"] = "v";
    expect(e2.extra).not.toHaveProperty("k");
  });
});

describe("SecurityEvent.toDict", () => {
  const EXPECTED_KEYS = [
    "event_type",
    "timestamp",
    "allowed",
    "score",
    "risk_level",
    "reasons",
    "action",
    "guard_type",
    "policy_name",
    "provider_name",
    "tool_name",
    "tool_call_id",
    "safe_output_present",
    "duration_ms",
    "trace_id",
    "span_id",
    "extra",
  ].sort();

  it("contains all expected keys", () => {
    expect(Object.keys(makeEvent().toDict()).sort()).toEqual(EXPECTED_KEYS);
  });

  it("event_type is a string", () => {
    expect(typeof makeEvent().toDict().event_type).toBe("string");
  });

  it("event_type value is 'decision'", () => {
    expect(makeEvent().toDict().event_type).toBe("decision");
  });

  it("scan event_type value is 'scan'", () => {
    const evt = makeEvent({ eventType: EventType.SCAN });
    expect(evt.toDict().event_type).toBe("scan");
  });

  it("tool_call event_type value is 'tool_call'", () => {
    const evt = makeEvent({ eventType: EventType.TOOL_CALL });
    expect(evt.toDict().event_type).toBe("tool_call");
  });

  it("allowed field is true", () => {
    expect(makeEvent().toDict().allowed).toBe(true);
  });

  it("optional none fields are present as null", () => {
    const d = makeEvent().toDict();
    expect(d.guard_type).toBeNull();
    expect(d.tool_name).toBeNull();
    expect(d.duration_ms).toBeNull();
    expect(d.trace_id).toBeNull();
    expect(d.span_id).toBeNull();
  });

  it("preserves extra", () => {
    const evt = makeEvent({ extra: { req_id: "r1" } });
    expect(evt.toDict().extra).toEqual({ req_id: "r1" });
  });
});

describe("SecurityEvent JSON serialization (toJSON via JSON.stringify)", () => {
  it("JSON.stringify returns a string", () => {
    expect(typeof JSON.stringify(makeEvent())).toBe("string");
  });

  it("stringified output is valid JSON parsing back to an object", () => {
    const parsed = JSON.parse(JSON.stringify(makeEvent()));
    expect(typeof parsed).toBe("object");
    expect(parsed).not.toBeNull();
  });

  it("event_type in the JSON is a string", () => {
    const parsed = JSON.parse(JSON.stringify(makeEvent()));
    expect(parsed.event_type).toBe("decision");
  });

  it("all keys present in the JSON", () => {
    const parsed = JSON.parse(JSON.stringify(makeEvent()));
    expect(parsed).toHaveProperty("allowed");
    expect(parsed).toHaveProperty("score");
    expect(parsed).toHaveProperty("timestamp");
  });

  it("single line, no newline", () => {
    expect(JSON.stringify(makeEvent())).not.toContain("\n");
  });
});

describe("SecurityEvent.toText (full event)", () => {
  function fullEvent(): SecurityEvent {
    return new SecurityEvent({
      eventType: EventType.DECISION,
      timestamp: "2025-03-09T14:23:01.456789+00:00",
      allowed: false,
      score: 0.92,
      riskLevel: "critical",
      reasons: ["injection detected"],
      action: "block",
      policyName: "balanced",
      providerName: "openai",
      guardType: "prompt",
      toolName: "my_tool",
      toolCallId: "call_123",
      durationMs: 12.5,
      traceId: "trace-abc",
    });
  }

  it("contains event type", () => {
    expect(fullEvent().toText()).toContain("event=decision");
  });

  it("contains allowed=False", () => {
    expect(fullEvent().toText()).toContain("allowed=false");
  });

  it("contains score", () => {
    expect(fullEvent().toText()).toContain("score=0.9200");
  });

  it("contains risk", () => {
    expect(fullEvent().toText()).toContain("risk=critical");
  });

  it("contains action", () => {
    expect(fullEvent().toText()).toContain("action=block");
  });

  it("contains policy", () => {
    expect(fullEvent().toText()).toContain("policy=balanced");
  });

  it("contains provider", () => {
    expect(fullEvent().toText()).toContain("provider=openai");
  });

  it("contains guard", () => {
    expect(fullEvent().toText()).toContain("guard=prompt");
  });

  it("contains tool", () => {
    expect(fullEvent().toText()).toContain("tool=my_tool");
  });

  it("contains call_id", () => {
    expect(fullEvent().toText()).toContain("call_id=call_123");
  });

  it("contains duration_ms", () => {
    expect(fullEvent().toText()).toContain("duration_ms=12.5");
  });

  it("contains trace_id", () => {
    expect(fullEvent().toText()).toContain("trace_id=trace-abc");
  });

  it("contains reasons", () => {
    const text = fullEvent().toText();
    expect(text).toContain("reasons=");
    expect(text).toContain("injection detected");
  });

  it("returns a single line", () => {
    expect(fullEvent().toText()).not.toContain("\n");
  });

  it("includes extra key/value", () => {
    const evt = makeEvent({ extra: { req_id: "r123" } });
    expect(evt.toText()).toContain("req_id");
  });
});

describe("SecurityEvent.toText (clean event)", () => {
  function cleanEvent(): SecurityEvent {
    return makeEvent();
  }

  it("omits guard field when null", () => {
    expect(cleanEvent().toText()).not.toContain("guard=");
  });

  it("omits tool field when null", () => {
    expect(cleanEvent().toText()).not.toContain("tool=");
  });

  it("omits call_id field when null", () => {
    expect(cleanEvent().toText()).not.toContain("call_id=");
  });

  it("omits reasons field when empty", () => {
    expect(cleanEvent().toText()).not.toContain("reasons=");
  });

  it("omits duration_ms when null", () => {
    expect(cleanEvent().toText()).not.toContain("duration_ms");
  });

  it("omits trace_id when null", () => {
    expect(cleanEvent().toText()).not.toContain("trace_id");
  });

  it("includes allowed=true", () => {
    expect(cleanEvent().toText()).toContain("allowed=true");
  });
});

describe("Handler registry", () => {
  it("addHandler receives events", () => {
    const events = captureEvents();
    logDecision(cleanDecision(), { policy: balancedPolicy() });
    expect(events).toHaveLength(1);
  });

  it("handler receives a SecurityEvent instance", () => {
    const events = captureEvents();
    logDecision(cleanDecision(), { policy: balancedPolicy() });
    expect(events[0]).toBeInstanceOf(SecurityEvent);
  });

  it("multiple handlers are all called", () => {
    const a: SecurityEvent[] = [];
    const b: SecurityEvent[] = [];
    addHandler((e) => a.push(e));
    addHandler((e) => b.push(e));
    logDecision(cleanDecision(), { policy: balancedPolicy() });
    expect(a).toHaveLength(1);
    expect(b).toHaveLength(1);
  });

  it("handlers are called in registration order", () => {
    const order: string[] = [];
    addHandler(() => order.push("first"));
    addHandler(() => order.push("second"));
    logDecision(cleanDecision(), { policy: balancedPolicy() });
    expect(order).toEqual(["first", "second"]);
  });

  it("removeHandler stops dispatch", () => {
    const events: SecurityEvent[] = [];
    const fn = (e: SecurityEvent) => events.push(e);
    addHandler(fn);
    removeHandler(fn);
    logDecision(cleanDecision(), { policy: balancedPolicy() });
    expect(events).toHaveLength(0);
  });

  it("removing a non-existent handler is silent", () => {
    expect(() => removeHandler(() => undefined)).not.toThrow();
  });

  it("clearHandlers removes all handlers", () => {
    const events = captureEvents();
    clearHandlers();
    logDecision(cleanDecision(), { policy: balancedPolicy() });
    expect(events).toHaveLength(0);
  });

  it("multiple log calls accumulate events", () => {
    const events = captureEvents();
    logDecision(cleanDecision(), { policy: balancedPolicy() });
    logDecision(blockedDecision(), { policy: balancedPolicy() });
    expect(events).toHaveLength(2);
  });

  it("removing one of two handlers leaves the other active", () => {
    const e1: SecurityEvent[] = [];
    const e2: SecurityEvent[] = [];
    const fn1 = (e: SecurityEvent) => e1.push(e);
    addHandler(fn1);
    addHandler((e) => e2.push(e));
    removeHandler(fn1);
    logDecision(cleanDecision(), { policy: balancedPolicy() });
    expect(e1).toHaveLength(0);
    expect(e2).toHaveLength(1);
  });
});

describe("Handler failure isolation", () => {
  it("exception in a handler does not propagate", () => {
    addHandler(() => {
      throw new RangeError("crash");
    });
    expect(() => logDecision(cleanDecision(), { policy: balancedPolicy() })).not.toThrow();
  });

  it("subsequent handler is still called after a crash", () => {
    const good: SecurityEvent[] = [];
    addHandler(() => {
      throw new Error("oops");
    });
    addHandler((e) => good.push(e));
    logDecision(cleanDecision(), { policy: balancedPolicy() });
    expect(good).toHaveLength(1);
  });

  it("all subsequent handlers are called after a crash", () => {
    const counts: number[] = [];
    addHandler(() => {
      throw new Error("x");
    });
    addHandler(() => counts.push(1));
    addHandler(() => counts.push(2));
    logDecision(cleanDecision(), { policy: balancedPolicy() });
    expect(counts).toEqual([1, 2]);
  });
});

describe("logDecision", () => {
  it("returns a SecurityEvent", () => {
    expect(logDecision(cleanDecision(), { policy: balancedPolicy() })).toBeInstanceOf(SecurityEvent);
  });

  it("event_type is DECISION", () => {
    const events = captureEvents();
    logDecision(cleanDecision(), { policy: balancedPolicy() });
    expect(events[0].eventType).toBe(EventType.DECISION);
  });

  it("allowed is true for a clean decision", () => {
    const events = captureEvents();
    logDecision(cleanDecision(), { policy: balancedPolicy() });
    expect(events[0].allowed).toBe(true);
  });

  it("allowed is false for a blocked decision", () => {
    const events = captureEvents();
    logDecision(blockedDecision(), { policy: balancedPolicy() });
    expect(events[0].allowed).toBe(false);
  });

  it("score is taken from the decision", () => {
    const events = captureEvents();
    logDecision(blockedDecision(), { policy: balancedPolicy() });
    expect(events[0].score).toBe(0.92);
  });

  it("reasons are taken from the decision", () => {
    const events = captureEvents();
    logDecision(blockedDecision(), { policy: balancedPolicy() });
    expect(events[0].reasons).toEqual(["injection detected"]);
  });

  it("action is 'block' for a blocked decision", () => {
    const events = captureEvents();
    logDecision(blockedDecision(), { policy: balancedPolicy() });
    expect(events[0].action).toBe("block");
  });

  it("action is 'log' for a clean decision", () => {
    const events = captureEvents();
    logDecision(cleanDecision(), { policy: balancedPolicy() });
    expect(events[0].action).toBe("log");
  });

  it("policyName comes from the policy", () => {
    const events = captureEvents();
    logDecision(cleanDecision(), { policy: balancedPolicy() });
    expect(events[0].policyName).toBe("balanced");
  });

  it("providerName is set when passed", () => {
    const events = captureEvents();
    logDecision(cleanDecision(), { policy: balancedPolicy(), providerName: "openai" });
    expect(events[0].providerName).toBe("openai");
  });

  it("riskLevel is 'none' for a clean decision", () => {
    const events = captureEvents();
    logDecision(cleanDecision(), { policy: balancedPolicy() });
    expect(events[0].riskLevel).toBe("none");
  });

  it("riskLevel is 'critical' for a high score", () => {
    const events = captureEvents();
    logDecision(blockedDecision(), { policy: balancedPolicy() });
    expect(events[0].riskLevel).toBe("critical");
  });

  it("timestamp is ISO-8601 UTC", () => {
    const events = captureEvents();
    logDecision(cleanDecision(), { policy: balancedPolicy() });
    const ts = events[0].timestamp;
    expect(ts).toContain("T");
    expect(ts.includes("+") || ts.includes("Z")).toBe(true);
  });

  it("no policy defaults policyName to 'unknown'", () => {
    const events = captureEvents();
    logDecision(cleanDecision());
    expect(events[0].policyName).toBe("unknown");
  });

  it("no provider defaults providerName to 'unknown'", () => {
    const events = captureEvents();
    logDecision(cleanDecision());
    expect(events[0].providerName).toBe("unknown");
  });
});

describe("logDecision safeOutputPresent flag", () => {
  it("is true when safeOutput is set", () => {
    const events = captureEvents();
    logDecision(GuardDecision.clean("some output"), { policy: balancedPolicy() });
    expect(events[0].safeOutputPresent).toBe(true);
  });

  it("is false when blocked", () => {
    const events = captureEvents();
    logDecision(GuardDecision.blocked(["x"]), { policy: balancedPolicy() });
    expect(events[0].safeOutputPresent).toBe(false);
  });

  it("is false when clean with a null output", () => {
    const events = captureEvents();
    logDecision(GuardDecision.clean(null), { policy: balancedPolicy() });
    expect(events[0].safeOutputPresent).toBe(false);
  });

  it("is true when warned with an output", () => {
    const events = captureEvents();
    const d = GuardDecision.allowedWithWarning("response", ["r"], 0.45);
    logDecision(d, { policy: balancedPolicy() });
    expect(events[0].safeOutputPresent).toBe(true);
  });
});

describe("logDecision optional fields", () => {
  it("durationMs is forwarded", () => {
    const events = captureEvents();
    logDecision(cleanDecision(), { policy: balancedPolicy(), durationMs: 42.5 });
    expect(events[0].durationMs).toBe(42.5);
  });

  it("durationMs defaults to null", () => {
    const events = captureEvents();
    logDecision(cleanDecision(), { policy: balancedPolicy() });
    expect(events[0].durationMs).toBeNull();
  });

  it("traceId is forwarded", () => {
    const events = captureEvents();
    logDecision(cleanDecision(), { policy: balancedPolicy(), traceId: "t-abc" });
    expect(events[0].traceId).toBe("t-abc");
  });

  it("spanId is forwarded", () => {
    const events = captureEvents();
    logDecision(cleanDecision(), { policy: balancedPolicy(), spanId: "s-xyz" });
    expect(events[0].spanId).toBe("s-xyz");
  });

  it("traceId and spanId default to null", () => {
    const events = captureEvents();
    logDecision(cleanDecision(), { policy: balancedPolicy() });
    expect(events[0].traceId).toBeNull();
    expect(events[0].spanId).toBeNull();
  });

  it("extra is forwarded", () => {
    const events = captureEvents();
    logDecision(cleanDecision(), { policy: balancedPolicy(), extra: { req_id: "r123" } });
    expect(events[0].extra).toEqual({ req_id: "r123" });
  });

  it("extra defaults to an empty object", () => {
    const events = captureEvents();
    logDecision(cleanDecision(), { policy: balancedPolicy() });
    expect(events[0].extra).toEqual({});
  });
});

describe("logScanResult", () => {
  it("returns a SecurityEvent", () => {
    expect(logScanResult(cleanScan(), { policy: balancedPolicy() })).toBeInstanceOf(SecurityEvent);
  });

  it("event_type is SCAN", () => {
    const events = captureEvents();
    logScanResult(cleanScan(), { policy: balancedPolicy() });
    expect(events[0].eventType).toBe(EventType.SCAN);
  });

  it("guardType is 'prompt'", () => {
    const events = captureEvents();
    logScanResult(cleanScan(), { policy: balancedPolicy() });
    expect(events[0].guardType).toBe("prompt");
  });

  it("allowed comes from the scan result", () => {
    const events = captureEvents();
    logScanResult(cleanScan(), { policy: balancedPolicy() });
    expect(events[0].allowed).toBe(true);
  });

  it("blocked scan produces a blocked event", () => {
    const events = captureEvents();
    logScanResult(blockedScan(), { policy: balancedPolicy() });
    const evt = events[0];
    expect(evt.allowed).toBe(false);
    expect(evt.score).toBe(0.92);
    expect(evt.reasons).toEqual(["injection"]);
    expect(evt.action).toBe("block");
  });

  it("clean scan action is 'log'", () => {
    const events = captureEvents();
    logScanResult(cleanScan(), { policy: balancedPolicy() });
    expect(events[0].action).toBe("log");
  });

  it("output guardType", () => {
    const events = captureEvents();
    const sr = new ScanResult({ allowed: true, score: 0.0, guardType: GuardType.OUTPUT });
    logScanResult(sr, { policy: balancedPolicy() });
    expect(events[0].guardType).toBe("output");
  });

  it("tool guardType", () => {
    const events = captureEvents();
    const sr = new ScanResult({ allowed: true, score: 0.0, guardType: GuardType.TOOL });
    logScanResult(sr, { policy: balancedPolicy() });
    expect(events[0].guardType).toBe("tool");
  });

  it("policyName is attached", () => {
    const events = captureEvents();
    logScanResult(cleanScan(), { policy: balancedPolicy() });
    expect(events[0].policyName).toBe("balanced");
  });

  it("providerName is attached", () => {
    const events = captureEvents();
    logScanResult(cleanScan(), { policy: balancedPolicy(), providerName: "anthropic" });
    expect(events[0].providerName).toBe("anthropic");
  });

  it("extra is forwarded", () => {
    const events = captureEvents();
    logScanResult(cleanScan(), { policy: balancedPolicy(), extra: { env: "prod" } });
    expect(events[0].extra).toEqual({ env: "prod" });
  });

  it.each(Object.values(GuardType))("guardType %s produces the matching field", (guardType) => {
    const events = captureEvents();
    const sr = new ScanResult({ allowed: true, score: 0.0, guardType });
    logScanResult(sr, { policy: balancedPolicy() });
    expect(events.at(-1)!.guardType).toBe(guardType);
  });
});

describe("logToolCall", () => {
  it("returns a SecurityEvent", () => {
    expect(logToolCall(safeToolCall(), null, { policy: balancedPolicy() })).toBeInstanceOf(SecurityEvent);
  });

  it("event_type is TOOL_CALL", () => {
    const events = captureEvents();
    logToolCall(safeToolCall(), null, { policy: balancedPolicy() });
    expect(events[0].eventType).toBe(EventType.TOOL_CALL);
  });

  it("toolName is set", () => {
    const events = captureEvents();
    logToolCall(safeToolCall(), null, { policy: balancedPolicy() });
    expect(events[0].toolName).toBe("search_web");
  });

  it("toolCallId is set", () => {
    const events = captureEvents();
    logToolCall(safeToolCall(), null, { policy: balancedPolicy() });
    expect(events[0].toolCallId).toBe("call_abc");
  });

  it("guardType is 'tool'", () => {
    const events = captureEvents();
    logToolCall(safeToolCall(), null, { policy: balancedPolicy() });
    expect(events[0].guardType).toBe("tool");
  });

  it("without a result, allowed is true", () => {
    const events = captureEvents();
    logToolCall(safeToolCall(), null, { policy: balancedPolicy() });
    expect(events[0].allowed).toBe(true);
  });

  it("without a result, score is zero", () => {
    const events = captureEvents();
    logToolCall(safeToolCall(), null, { policy: balancedPolicy() });
    expect(events[0].score).toBe(0.0);
  });

  it("without a result, action is 'log'", () => {
    const events = captureEvents();
    logToolCall(safeToolCall(), null, { policy: balancedPolicy() });
    expect(events[0].action).toBe("log");
  });

  it("with a blocked result", () => {
    const events = captureEvents();
    const sr = new ScanResult({
      allowed: false,
      score: 0.88,
      reasons: ["dangerous"],
      guardType: GuardType.TOOL,
    });
    logToolCall(safeToolCall(), sr, { policy: balancedPolicy() });
    const evt = events[0];
    expect(evt.allowed).toBe(false);
    expect(evt.score).toBe(0.88);
    expect(evt.reasons).toEqual(["dangerous"]);
    expect(evt.action).toBe("block");
  });

  it("without a call id, toolCallId is null", () => {
    const events = captureEvents();
    const tc = new ToolCall({ name: "ping", args: {} });
    logToolCall(tc, null, { policy: balancedPolicy() });
    expect(events[0].toolCallId).toBeNull();
  });

  it("policyName is attached", () => {
    const events = captureEvents();
    logToolCall(safeToolCall(), null, { policy: balancedPolicy() });
    expect(events[0].policyName).toBe("balanced");
  });

  it("providerName is attached", () => {
    const events = captureEvents();
    logToolCall(safeToolCall(), null, { policy: balancedPolicy(), providerName: "openai" });
    expect(events[0].providerName).toBe("openai");
  });

  it("extra is forwarded", () => {
    const events = captureEvents();
    logToolCall(safeToolCall(), null, { policy: balancedPolicy(), extra: { env: "test" } });
    expect(events[0].extra).toEqual({ env: "test" });
  });
});

describe("Logger level selection", () => {
  it("a blocked decision logs at error", () => {
    const logger = { info: vi.fn(), warn: vi.fn(), error: vi.fn() };
    logDecision(GuardDecision.blocked(["x"]), { policy: balancedPolicy(), logger });
    expect(logger.error).toHaveBeenCalledTimes(1);
    expect(logger.warn).not.toHaveBeenCalled();
    expect(logger.info).not.toHaveBeenCalled();
  });

  it("a warned decision logs at warn", () => {
    const logger = { info: vi.fn(), warn: vi.fn(), error: vi.fn() };
    const d = GuardDecision.allowedWithWarning("x", ["r"], 0.45);
    logDecision(d, { policy: balancedPolicy(), logger });
    expect(logger.warn).toHaveBeenCalledTimes(1);
    expect(logger.error).not.toHaveBeenCalled();
    expect(logger.info).not.toHaveBeenCalled();
  });

  it("a clean decision logs at info", () => {
    const logger = { info: vi.fn(), warn: vi.fn(), error: vi.fn() };
    logDecision(GuardDecision.clean("hi"), { policy: balancedPolicy(), logger });
    expect(logger.info).toHaveBeenCalledTimes(1);
    expect(logger.warn).not.toHaveBeenCalled();
    expect(logger.error).not.toHaveBeenCalled();
  });

  it("a blocked scan result logs at error", () => {
    const logger = { info: vi.fn(), warn: vi.fn(), error: vi.fn() };
    logScanResult(blockedScan(), { policy: balancedPolicy(), logger });
    expect(logger.error).toHaveBeenCalledTimes(1);
  });

  it("a clean scan result logs at info", () => {
    const logger = { info: vi.fn(), warn: vi.fn(), error: vi.fn() };
    logScanResult(cleanScan(), { policy: balancedPolicy(), logger });
    expect(logger.info).toHaveBeenCalledTimes(1);
  });

  it("a blocked tool call result logs at error", () => {
    const logger = { info: vi.fn(), warn: vi.fn(), error: vi.fn() };
    const sr = new ScanResult({ allowed: false, score: 0.9, reasons: ["x"], guardType: GuardType.TOOL });
    logToolCall(safeToolCall(), sr, { policy: balancedPolicy(), logger });
    expect(logger.error).toHaveBeenCalledTimes(1);
  });

  it("a tool call with no result logs at info", () => {
    const logger = { info: vi.fn(), warn: vi.fn(), error: vi.fn() };
    logToolCall(safeToolCall(), null, { policy: balancedPolicy(), logger });
    expect(logger.info).toHaveBeenCalledTimes(1);
  });

  it("the JSON format logger message parses back to the event's dict", () => {
    const logger = { info: vi.fn(), warn: vi.fn(), error: vi.fn() };
    logDecision(GuardDecision.clean("hi"), { policy: balancedPolicy(), logger, fmt: LogFormat.JSON });
    const [message] = logger.info.mock.calls[0] as [string];
    expect(() => JSON.parse(message)).not.toThrow();
    expect(JSON.parse(message).event_type).toBe("decision");
  });

  it("the TEXT format logger message matches toText output", () => {
    const logger = { info: vi.fn(), warn: vi.fn(), error: vi.fn() };
    logDecision(GuardDecision.clean("hi"), { policy: balancedPolicy(), logger, fmt: LogFormat.TEXT });
    const [message] = logger.info.mock.calls[0] as [string];
    expect(message).toContain("event=decision");
    expect(message).toContain("allowed=true");
  });
});

describe("SecurityEventLogger", () => {
  it("stores the policy", () => {
    const policy = balancedPolicy();
    expect(new SecurityEventLogger({ policy }).policy).toBe(policy);
  });

  it("stores providerName", () => {
    expect(new SecurityEventLogger({ providerName: "anthropic" }).providerName).toBe("anthropic");
  });

  it("fmt defaults to JSON", () => {
    expect(new SecurityEventLogger().fmt).toBe(LogFormat.JSON);
  });

  it("fmt TEXT is accepted", () => {
    expect(new SecurityEventLogger({ fmt: LogFormat.TEXT }).fmt).toBe(LogFormat.TEXT);
  });

  it("defaultExtra defaults to an empty object", () => {
    expect(new SecurityEventLogger().defaultExtra).toEqual({});
  });

  it("logDecision attaches providerName", () => {
    const events = captureEvents();
    new SecurityEventLogger({ policy: balancedPolicy(), providerName: "openai" }).logDecision(
      GuardDecision.clean("hi"),
    );
    expect(events[0].providerName).toBe("openai");
  });

  it("logDecision attaches policyName", () => {
    const events = captureEvents();
    new SecurityEventLogger({ policy: balancedPolicy(), providerName: "x" }).logDecision(
      GuardDecision.clean("hi"),
    );
    expect(events[0].policyName).toBe("balanced");
  });

  it("logDecision returns a SecurityEvent", () => {
    const logger = new SecurityEventLogger({ policy: balancedPolicy(), providerName: "x" });
    expect(logger.logDecision(GuardDecision.clean("hi"))).toBeInstanceOf(SecurityEvent);
  });

  it("logDecision forwards durationMs", () => {
    const events = captureEvents();
    new SecurityEventLogger({ policy: balancedPolicy(), providerName: "x" }).logDecision(
      GuardDecision.clean("hi"),
      { durationMs: 15.0 },
    );
    expect(events[0].durationMs).toBe(15.0);
  });

  it("logDecision forwards traceId", () => {
    const events = captureEvents();
    new SecurityEventLogger({ policy: balancedPolicy(), providerName: "x" }).logDecision(
      GuardDecision.clean("hi"),
      { traceId: "t1" },
    );
    expect(events[0].traceId).toBe("t1");
  });

  it("logDecision forwards spanId", () => {
    const events = captureEvents();
    new SecurityEventLogger({ policy: balancedPolicy(), providerName: "x" }).logDecision(
      GuardDecision.clean("hi"),
      { spanId: "s1" },
    );
    expect(events[0].spanId).toBe("s1");
  });

  it("logScanResult delegates", () => {
    const events = captureEvents();
    const logger = new SecurityEventLogger({ policy: balancedPolicy(), providerName: "openai" });
    const sr = new ScanResult({ allowed: true, score: 0.0, guardType: GuardType.PROMPT });
    const result = logger.logScanResult(sr);
    expect(result).toBeInstanceOf(SecurityEvent);
    expect(events[0].eventType).toBe(EventType.SCAN);
    expect(events[0].providerName).toBe("openai");
  });

  it("logToolCall delegates", () => {
    const events = captureEvents();
    const logger = new SecurityEventLogger({ policy: balancedPolicy(), providerName: "openai" });
    const tc = new ToolCall({ name: "search", args: {} });
    const result = logger.logToolCall(tc);
    expect(result).toBeInstanceOf(SecurityEvent);
    expect(events[0].eventType).toBe(EventType.TOOL_CALL);
    expect(events[0].providerName).toBe("openai");
    expect(events[0].toolName).toBe("search");
  });

  it("no policy defaults policyName to 'unknown'", () => {
    const events = captureEvents();
    new SecurityEventLogger({ policy: null, providerName: "x" }).logDecision(GuardDecision.clean("hi"));
    expect(events[0].policyName).toBe("unknown");
  });
});

describe("SecurityEventLogger extra merging", () => {
  it("defaultExtra is included in every event", () => {
    const events = captureEvents();
    const logger = new SecurityEventLogger({
      policy: balancedPolicy(),
      providerName: "x",
      defaultExtra: { service: "chat-api" },
    });
    logger.logDecision(GuardDecision.clean("hi"));
    expect(events[0].extra.service).toBe("chat-api");
  });

  it("per-call extra is merged with defaultExtra", () => {
    const events = captureEvents();
    const logger = new SecurityEventLogger({
      policy: balancedPolicy(),
      providerName: "x",
      defaultExtra: { service: "chat-api" },
    });
    logger.logDecision(GuardDecision.clean("hi"), { extra: { req_id: "r1" } });
    const evt = events[0];
    expect(evt.extra.service).toBe("chat-api");
    expect(evt.extra.req_id).toBe("r1");
  });

  it("per-call extra overrides defaultExtra on key collision", () => {
    const events = captureEvents();
    const logger = new SecurityEventLogger({
      policy: balancedPolicy(),
      providerName: "x",
      defaultExtra: { service: "chat-api" },
    });
    logger.logDecision(GuardDecision.clean("hi"), { extra: { service: "override" } });
    expect(events[0].extra.service).toBe("override");
  });

  it("defaultExtra is not mutated by per-call extra", () => {
    const logger = new SecurityEventLogger({
      policy: balancedPolicy(),
      providerName: "x",
      defaultExtra: { service: "chat-api" },
    });
    logger.logDecision(GuardDecision.clean("hi"), { extra: { req_id: "r1" } });
    expect(logger.defaultExtra).not.toHaveProperty("req_id");
  });

  it("no extras gives an empty object", () => {
    const events = captureEvents();
    new SecurityEventLogger({ policy: balancedPolicy(), providerName: "x" }).logDecision(
      GuardDecision.clean("hi"),
    );
    expect(events[0].extra).toEqual({});
  });

  it("defaultExtra applies on logScanResult", () => {
    const events = captureEvents();
    const logger = new SecurityEventLogger({
      policy: balancedPolicy(),
      providerName: "x",
      defaultExtra: { env: "staging" },
    });
    const sr = new ScanResult({ allowed: true, score: 0.0, guardType: GuardType.PROMPT });
    logger.logScanResult(sr);
    expect(events[0].extra.env).toBe("staging");
  });

  it("defaultExtra applies on logToolCall", () => {
    const events = captureEvents();
    const logger = new SecurityEventLogger({
      policy: balancedPolicy(),
      providerName: "x",
      defaultExtra: { env: "staging" },
    });
    logger.logToolCall(new ToolCall({ name: "search", args: {} }));
    expect(events[0].extra.env).toBe("staging");
  });
});
