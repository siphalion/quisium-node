import { describe, it, expect } from "vitest";
import {
  GuardDecision,
  GuardType,
  PolicyAction,
  RiskLevel,
  riskLevelFromScore,
  ScanResult,
  ToolCall,
} from "../src/types.js";

describe("riskLevelFromScore", () => {
  it("score zero is none", () => {
    expect(riskLevelFromScore(0.0)).toBe(RiskLevel.NONE);
  });

  it("score mid none band", () => {
    expect(riskLevelFromScore(0.05)).toBe(RiskLevel.NONE);
  });

  it("score just below low is none", () => {
    expect(riskLevelFromScore(0.099)).toBe(RiskLevel.NONE);
  });

  it("score at low boundary", () => {
    expect(riskLevelFromScore(0.1)).toBe(RiskLevel.LOW);
  });

  it("score mid low band", () => {
    expect(riskLevelFromScore(0.25)).toBe(RiskLevel.LOW);
  });

  it("score just below medium is low", () => {
    expect(riskLevelFromScore(0.39)).toBe(RiskLevel.LOW);
  });

  it("score at medium boundary", () => {
    expect(riskLevelFromScore(0.4)).toBe(RiskLevel.MEDIUM);
  });

  it("score mid medium band", () => {
    expect(riskLevelFromScore(0.55)).toBe(RiskLevel.MEDIUM);
  });

  it("score just below high is medium", () => {
    expect(riskLevelFromScore(0.74)).toBe(RiskLevel.MEDIUM);
  });

  it("score at high boundary", () => {
    expect(riskLevelFromScore(0.75)).toBe(RiskLevel.HIGH);
  });

  it("score mid high band", () => {
    expect(riskLevelFromScore(0.82)).toBe(RiskLevel.HIGH);
  });

  it("score just below critical is high", () => {
    expect(riskLevelFromScore(0.899)).toBe(RiskLevel.HIGH);
  });

  it("score at critical boundary", () => {
    expect(riskLevelFromScore(0.9)).toBe(RiskLevel.CRITICAL);
  });

  it("score mid critical band", () => {
    expect(riskLevelFromScore(0.95)).toBe(RiskLevel.CRITICAL);
  });

  it("score one is critical", () => {
    expect(riskLevelFromScore(1.0)).toBe(RiskLevel.CRITICAL);
  });

  it("negative score raises RangeError", () => {
    expect(() => riskLevelFromScore(-0.01)).toThrow(RangeError);
    expect(() => riskLevelFromScore(-0.01)).toThrow(/score must be in/);
  });

  it("score above one raises RangeError", () => {
    expect(() => riskLevelFromScore(1.01)).toThrow(RangeError);
    expect(() => riskLevelFromScore(1.01)).toThrow(/score must be in/);
  });

  it("large negative raises RangeError", () => {
    expect(() => riskLevelFromScore(-99.0)).toThrow(RangeError);
  });
});

describe("RiskLevel enum", () => {
  it("none value", () => {
    expect(RiskLevel.NONE).toBe("none");
  });

  it("low value", () => {
    expect(RiskLevel.LOW).toBe("low");
  });

  it("medium value", () => {
    expect(RiskLevel.MEDIUM).toBe("medium");
  });

  it("high value", () => {
    expect(RiskLevel.HIGH).toBe("high");
  });

  it("critical value", () => {
    expect(RiskLevel.CRITICAL).toBe("critical");
  });

  it("is a plain string value", () => {
    expect(RiskLevel.NONE).toBe("none");
    expect(RiskLevel.CRITICAL).toBe("critical");
  });
});

describe("GuardType enum", () => {
  it("prompt value", () => {
    expect(GuardType.PROMPT).toBe("prompt");
  });

  it("output value", () => {
    expect(GuardType.OUTPUT).toBe("output");
  });

  it("tool value", () => {
    expect(GuardType.TOOL).toBe("tool");
  });
});

describe("PolicyAction enum", () => {
  it("block value", () => {
    expect(PolicyAction.BLOCK).toBe("block");
  });

  it("warn value", () => {
    expect(PolicyAction.WARN).toBe("warn");
  });

  it("log value", () => {
    expect(PolicyAction.LOG).toBe("log");
  });
});

describe("ScanResult construction", () => {
  it("minimal clean construction", () => {
    const r = new ScanResult({ allowed: true, score: 0.0 });
    expect(r.allowed).toBe(true);
    expect(r.score).toBe(0.0);
    expect(r.reasons).toEqual([]);
    expect(r.safeOutput).toBeNull();
    expect(r.guardType).toBe(GuardType.PROMPT); // default
    expect(r.metadata).toEqual({});
  });

  it("full construction", () => {
    const r = new ScanResult({
      allowed: false,
      score: 0.92,
      reasons: ["Injection detected"],
      safeOutput: "[REDACTED]",
      guardType: GuardType.OUTPUT,
      metadata: { pattern: "dan" },
    });
    expect(r.allowed).toBe(false);
    expect(r.score).toBe(0.92);
    expect(r.reasons).toEqual(["Injection detected"]);
    expect(r.safeOutput).toBe("[REDACTED]");
    expect(r.guardType).toBe(GuardType.OUTPUT);
    expect(r.metadata).toEqual({ pattern: "dan" });
  });

  it("score above one raises", () => {
    expect(() => new ScanResult({ allowed: true, score: 1.1 })).toThrow(RangeError);
  });

  it("score below zero raises", () => {
    expect(() => new ScanResult({ allowed: true, score: -0.01 })).toThrow(RangeError);
  });

  it("score exactly one is valid", () => {
    const r = new ScanResult({ allowed: false, score: 1.0 });
    expect(r.score).toBe(1.0);
  });

  it("score exactly zero is valid", () => {
    const r = new ScanResult({ allowed: true, score: 0.0 });
    expect(r.score).toBe(0.0);
  });

  it.each(Object.values(GuardType))("all guard types accepted: %s", (gt) => {
    const r = new ScanResult({ allowed: true, score: 0.0, guardType: gt });
    expect(r.guardType).toBe(gt);
  });
});

describe("ScanResult riskLevel", () => {
  it("score zero is none", () => {
    const r = new ScanResult({ allowed: true, score: 0.0, guardType: GuardType.PROMPT });
    expect(r.riskLevel).toBe(RiskLevel.NONE);
  });

  it("score 0.92 is critical", () => {
    const r = new ScanResult({ allowed: false, score: 0.92, guardType: GuardType.PROMPT });
    expect(r.riskLevel).toBe(RiskLevel.CRITICAL);
  });

  it("score 0.75 is high", () => {
    const r = new ScanResult({ allowed: false, score: 0.75, guardType: GuardType.PROMPT });
    expect(r.riskLevel).toBe(RiskLevel.HIGH);
  });

  it("score 0.50 is medium", () => {
    const r = new ScanResult({ allowed: true, score: 0.5, guardType: GuardType.PROMPT });
    expect(r.riskLevel).toBe(RiskLevel.MEDIUM);
  });
});

describe("ScanResult isClean", () => {
  it("clean at score zero", () => {
    const r = new ScanResult({ allowed: true, score: 0.0, guardType: GuardType.PROMPT });
    expect(r.isClean).toBe(true);
  });

  it("clean at score 0.09", () => {
    const r = new ScanResult({ allowed: true, score: 0.09, guardType: GuardType.PROMPT });
    expect(r.isClean).toBe(true);
  });

  it("not clean at score 0.10", () => {
    // 0.10 crosses into the LOW band — no longer "clean"
    const r = new ScanResult({ allowed: true, score: 0.1, guardType: GuardType.PROMPT });
    expect(r.isClean).toBe(false);
  });

  it("not clean when blocked", () => {
    const r = new ScanResult({ allowed: false, score: 0.0, guardType: GuardType.PROMPT });
    expect(r.isClean).toBe(false);
  });

  it("not clean when blocked and high score", () => {
    const r = new ScanResult({ allowed: false, score: 0.92, guardType: GuardType.PROMPT });
    expect(r.isClean).toBe(false);
  });
});

describe("ScanResult toDict", () => {
  it("contains all required keys", () => {
    const r = new ScanResult({ allowed: true, score: 0.0, guardType: GuardType.PROMPT });
    const d = r.toDict();
    expect(new Set(Object.keys(d))).toEqual(
      new Set(["allowed", "score", "risk_level", "reasons", "safe_output", "guard_type", "metadata"]),
    );
  });

  it("score rounded to 4 decimal places", () => {
    const r = new ScanResult({ allowed: false, score: 0.921234, guardType: GuardType.PROMPT });
    expect(r.toDict().score).toBe(0.9212);
  });

  it("guard_type is string value", () => {
    const r = new ScanResult({ allowed: true, score: 0.0, guardType: GuardType.OUTPUT });
    expect(r.toDict().guard_type).toBe("output");
  });

  it("risk_level is string value", () => {
    const r = new ScanResult({ allowed: false, score: 0.92, guardType: GuardType.PROMPT });
    expect(r.toDict().risk_level).toBe("critical");
  });

  it("safe_output included", () => {
    const r = new ScanResult({
      allowed: true,
      score: 0.3,
      safeOutput: "redacted",
      guardType: GuardType.OUTPUT,
    });
    expect(r.toDict().safe_output).toBe("redacted");
  });

  it("safe_output none when not set", () => {
    const r = new ScanResult({ allowed: true, score: 0.0, guardType: GuardType.PROMPT });
    expect(r.toDict().safe_output).toBeNull();
  });

  it("metadata preserved", () => {
    const r = new ScanResult({
      allowed: false,
      score: 0.8,
      guardType: GuardType.TOOL,
      metadata: { tool: "delete_file" },
    });
    expect(r.toDict().metadata).toEqual({ tool: "delete_file" });
  });

  it("reasons list preserved", () => {
    const r = new ScanResult({
      allowed: false,
      score: 0.9,
      reasons: ["reason A", "reason B"],
      guardType: GuardType.PROMPT,
    });
    expect(r.toDict().reasons).toEqual(["reason A", "reason B"]);
  });

  it("empty reasons is empty list", () => {
    const r = new ScanResult({ allowed: true, score: 0.0, guardType: GuardType.PROMPT });
    expect(r.toDict().reasons).toEqual([]);
  });
});

describe("GuardDecision class methods", () => {
  it("clean allowed true", () => {
    const d = GuardDecision.clean("The answer is 42.");
    expect(d.allowed).toBe(true);
  });

  it("clean score zero", () => {
    const d = GuardDecision.clean("ok");
    expect(d.score).toBe(0.0);
  });

  it("clean not warned", () => {
    const d = GuardDecision.clean("ok");
    expect(d.warned).toBe(false);
  });

  it("clean reasons empty", () => {
    const d = GuardDecision.clean("ok");
    expect(d.reasons).toEqual([]);
  });

  it("clean action log", () => {
    const d = GuardDecision.clean("ok");
    expect(d.action).toBe(PolicyAction.LOG);
  });

  it("clean safe_output stored", () => {
    const d = GuardDecision.clean("The capital is Paris.");
    expect(d.safeOutput).toBe("The capital is Paris.");
  });

  it("clean safe_output none accepted", () => {
    const d = GuardDecision.clean(null);
    expect(d.safeOutput).toBeNull();
  });

  it("clean with scan results", () => {
    const sr = new ScanResult({ allowed: true, score: 0.0, guardType: GuardType.PROMPT });
    const d = GuardDecision.clean("ok", [sr]);
    expect(d.scanResults.length).toBe(1);
    expect(d.scanResults[0]).toBe(sr);
  });

  it("clean no scan results defaults to empty", () => {
    const d = GuardDecision.clean("ok");
    expect(d.scanResults).toEqual([]);
  });

  it("blocked allowed false", () => {
    const d = GuardDecision.blocked(["Injection"], 0.92);
    expect(d.allowed).toBe(false);
  });

  it("blocked score stored", () => {
    const d = GuardDecision.blocked(["x"], 0.85);
    expect(d.score).toBe(0.85);
  });

  it("blocked default score is one", () => {
    const d = GuardDecision.blocked(["x"]);
    expect(d.score).toBe(1.0);
  });

  it("blocked reasons stored", () => {
    const d = GuardDecision.blocked(["reason A", "reason B"], 0.9);
    expect(d.reasons).toEqual(["reason A", "reason B"]);
  });

  it("blocked action is block", () => {
    const d = GuardDecision.blocked(["x"]);
    expect(d.action).toBe(PolicyAction.BLOCK);
  });

  it("blocked not warned", () => {
    const d = GuardDecision.blocked(["x"]);
    expect(d.warned).toBe(false);
  });

  it("blocked safe_output is none", () => {
    const d = GuardDecision.blocked(["x"]);
    expect(d.safeOutput).toBeNull();
  });

  it("blocked with scan results", () => {
    const sr = new ScanResult({ allowed: false, score: 0.9, guardType: GuardType.PROMPT });
    const d = GuardDecision.blocked(["x"], 0.9, [sr]);
    expect(d.scanResults.length).toBe(1);
  });

  it("warning allowed true", () => {
    const d = GuardDecision.allowedWithWarning("response", ["credential redacted"], 0.45);
    expect(d.allowed).toBe(true);
  });

  it("warning warned true", () => {
    const d = GuardDecision.allowedWithWarning("response", ["r"], 0.45);
    expect(d.warned).toBe(true);
  });

  it("warning action warn", () => {
    const d = GuardDecision.allowedWithWarning("response", ["r"], 0.45);
    expect(d.action).toBe(PolicyAction.WARN);
  });

  it("warning safe_output stored", () => {
    const d = GuardDecision.allowedWithWarning("safe text", ["r"], 0.45);
    expect(d.safeOutput).toBe("safe text");
  });

  it("warning score stored", () => {
    const d = GuardDecision.allowedWithWarning("x", ["r"], 0.55);
    expect(d.score).toBe(0.55);
  });
});

describe("GuardDecision validation", () => {
  it("score above one raises", () => {
    expect(() => new GuardDecision({ allowed: true, score: 1.5 })).toThrow(RangeError);
  });

  it("score below zero raises", () => {
    expect(() => new GuardDecision({ allowed: true, score: -0.1 })).toThrow(RangeError);
  });

  it("score exactly one valid", () => {
    const d = new GuardDecision({ allowed: false, score: 1.0 });
    expect(d.score).toBe(1.0);
  });

  it("score exactly zero valid", () => {
    const d = new GuardDecision({ allowed: true, score: 0.0 });
    expect(d.score).toBe(0.0);
  });
});

describe("GuardDecision properties", () => {
  it("wasBlocked true when not allowed", () => {
    const d = GuardDecision.blocked(["x"], 0.9);
    expect(d.wasBlocked).toBe(true);
  });

  it("wasBlocked false when allowed", () => {
    const d = GuardDecision.clean("ok");
    expect(d.wasBlocked).toBe(false);
  });

  it("riskLevel critical", () => {
    const d = GuardDecision.blocked(["x"], 0.92);
    expect(d.riskLevel).toBe(RiskLevel.CRITICAL);
  });

  it("riskLevel none for clean", () => {
    const d = GuardDecision.clean("ok");
    expect(d.riskLevel).toBe(RiskLevel.NONE);
  });

  it("promptResults filter", () => {
    const srP = new ScanResult({ allowed: false, score: 0.9, guardType: GuardType.PROMPT });
    const srO = new ScanResult({ allowed: true, score: 0.0, guardType: GuardType.OUTPUT });
    const srT = new ScanResult({ allowed: true, score: 0.0, guardType: GuardType.TOOL });
    const d = new GuardDecision({ allowed: false, score: 0.9, scanResults: [srP, srO, srT] });
    expect(d.promptResults).toEqual([srP]);
  });

  it("outputResults filter", () => {
    const srP = new ScanResult({ allowed: true, score: 0.0, guardType: GuardType.PROMPT });
    const srO = new ScanResult({ allowed: false, score: 0.9, guardType: GuardType.OUTPUT });
    const d = new GuardDecision({ allowed: false, score: 0.9, scanResults: [srP, srO] });
    expect(d.outputResults).toEqual([srO]);
  });

  it("toolResults filter", () => {
    const srT = new ScanResult({ allowed: false, score: 0.88, guardType: GuardType.TOOL });
    const d = new GuardDecision({ allowed: false, score: 0.88, scanResults: [srT] });
    expect(d.toolResults).toEqual([srT]);
  });

  it("filter returns empty list when none match", () => {
    const srP = new ScanResult({ allowed: true, score: 0.0, guardType: GuardType.PROMPT });
    const d = GuardDecision.clean("ok", [srP]);
    expect(d.outputResults).toEqual([]);
    expect(d.toolResults).toEqual([]);
  });

  it("multiple results of same type all returned", () => {
    const sr1 = new ScanResult({ allowed: true, score: 0.0, guardType: GuardType.PROMPT });
    const sr2 = new ScanResult({ allowed: false, score: 0.92, guardType: GuardType.PROMPT });
    const d = new GuardDecision({ allowed: false, score: 0.92, scanResults: [sr1, sr2] });
    expect(d.promptResults.length).toBe(2);
  });
});

describe("GuardDecision toDict", () => {
  it("contains all required keys", () => {
    const d = GuardDecision.clean("hi").toDict();
    expect(new Set(Object.keys(d))).toEqual(
      new Set(["allowed", "score", "risk_level", "reasons", "safe_output", "warned", "action", "scan_results"]),
    );
  });

  it("allowed field", () => {
    expect(GuardDecision.clean("ok").toDict().allowed).toBe(true);
    expect(GuardDecision.blocked(["x"]).toDict().allowed).toBe(false);
  });

  it("action is string value", () => {
    expect(GuardDecision.clean("ok").toDict().action).toBe("log");
    expect(GuardDecision.blocked(["x"]).toDict().action).toBe("block");
  });

  it("risk_level is string value", () => {
    const d = GuardDecision.blocked(["x"], 0.92).toDict();
    expect(d.risk_level).toBe("critical");
  });

  it("scan_results serialised as list of dicts", () => {
    const sr = new ScanResult({ allowed: true, score: 0.0, guardType: GuardType.PROMPT });
    const d = GuardDecision.clean("ok", [sr]).toDict();
    expect(Array.isArray(d.scan_results)).toBe(true);
    expect(typeof d.scan_results[0]).toBe("object");
  });

  it("scan_results guard_type serialised", () => {
    const sr = new ScanResult({ allowed: true, score: 0.0, guardType: GuardType.OUTPUT });
    const d = GuardDecision.clean("ok", [sr]).toDict();
    expect(d.scan_results[0].guard_type).toBe("output");
  });

  it("empty scan_results is empty list", () => {
    const d = GuardDecision.clean("ok").toDict();
    expect(d.scan_results).toEqual([]);
  });

  it("warned field", () => {
    const dWarn = GuardDecision.allowedWithWarning("x", ["r"], 0.45);
    expect(dWarn.toDict().warned).toBe(true);
    expect(GuardDecision.clean("ok").toDict().warned).toBe(false);
  });

  it("score preserved", () => {
    const d = GuardDecision.blocked(["x"], 0.87).toDict();
    expect(d.score).toBe(0.87);
  });
});

describe("ToolCall construction", () => {
  it("minimal construction", () => {
    const tc = new ToolCall({ name: "search_web", args: { query: "python" } });
    expect(tc.name).toBe("search_web");
    expect(tc.args).toEqual({ query: "python" });
    expect(tc.schema).toEqual({});
    expect(tc.callId).toBeNull();
  });

  it("with schema", () => {
    const schema = { type: "object", properties: { query: { type: "string" } } };
    const tc = new ToolCall({ name: "search_web", args: { query: "x" }, schema });
    expect(tc.schema).toEqual(schema);
  });

  it("with call_id", () => {
    const tc = new ToolCall({ name: "search_web", args: {}, callId: "call_abc123" });
    expect(tc.callId).toBe("call_abc123");
  });

  it("empty name raises", () => {
    expect(() => new ToolCall({ name: "", args: {} })).toThrow(/non-empty/);
  });

  it("whitespace only name raises", () => {
    expect(() => new ToolCall({ name: "   ", args: {} })).toThrow(/non-empty/);
  });

  it("single char name valid", () => {
    const tc = new ToolCall({ name: "x", args: {} });
    expect(tc.name).toBe("x");
  });

  it("name with underscores valid", () => {
    const tc = new ToolCall({ name: "read_file_contents", args: {} });
    expect(tc.name).toBe("read_file_contents");
  });

  it("args can be empty dict", () => {
    const tc = new ToolCall({ name: "ping", args: {} });
    expect(tc.args).toEqual({});
  });

  it("args with nested values", () => {
    const tc = new ToolCall({ name: "query", args: { filters: { age: 30, active: true } } });
    expect((tc.args.filters as Record<string, unknown>).age).toBe(30);
  });
});

describe("ToolCall hasSchema", () => {
  it("hasSchema false when empty dict", () => {
    const tc = new ToolCall({ name: "search", args: {}, schema: {} });
    expect(tc.hasSchema).toBe(false);
  });

  it("hasSchema true when schema present", () => {
    const tc = new ToolCall({
      name: "search",
      args: {},
      schema: { type: "object", properties: {} },
    });
    expect(tc.hasSchema).toBe(true);
  });

  it("hasSchema true with minimal schema", () => {
    const tc = new ToolCall({ name: "search", args: {}, schema: { type: "object" } });
    expect(tc.hasSchema).toBe(true);
  });
});

describe("ToolCall toDict", () => {
  it("contains all keys", () => {
    const tc = new ToolCall({ name: "search", args: { q: "py" }, callId: "c1" });
    const d = tc.toDict();
    expect(new Set(Object.keys(d))).toEqual(new Set(["name", "args", "schema", "call_id"]));
  });

  it("name value", () => {
    const tc = new ToolCall({ name: "do_thing", args: {} });
    expect(tc.toDict().name).toBe("do_thing");
  });

  it("args value", () => {
    const tc = new ToolCall({ name: "x", args: { a: 1, b: "two" } });
    expect(tc.toDict().args).toEqual({ a: 1, b: "two" });
  });

  it("call_id none when not set", () => {
    const tc = new ToolCall({ name: "x", args: {} });
    expect(tc.toDict().call_id).toBeNull();
  });

  it("call_id value", () => {
    const tc = new ToolCall({ name: "x", args: {}, callId: "call_xyz" });
    expect(tc.toDict().call_id).toBe("call_xyz");
  });

  it("schema preserved", () => {
    const schema = { type: "object", required: ["path"] };
    const tc = new ToolCall({ name: "read", args: {}, schema });
    expect(tc.toDict().schema).toEqual(schema);
  });

  it("empty schema in dict", () => {
    const tc = new ToolCall({ name: "x", args: {} });
    expect(tc.toDict().schema).toEqual({});
  });
});
