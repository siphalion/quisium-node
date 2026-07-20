import { describe, it, expect } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import {
  BalancedPolicy,
  GuardConfig,
  LoggingOnlyPolicy,
  Policy,
  StrictPolicy,
  loadPolicyFromDict,
  loadPolicyFromYaml,
} from "../src/policies.js";
import { GuardType, PolicyAction } from "../src/types.js";

describe("GuardConfig construction", () => {
  it("defaults enabled to true", () => {
    const cfg = new GuardConfig();
    expect(cfg.enabled).toBe(true);
  });

  it("defaults blockThreshold to null", () => {
    const cfg = new GuardConfig();
    expect(cfg.blockThreshold).toBeNull();
  });

  it("defaults warnThreshold to null", () => {
    const cfg = new GuardConfig();
    expect(cfg.warnThreshold).toBeNull();
  });

  it("accepts explicit enabled=false", () => {
    const cfg = new GuardConfig({ enabled: false });
    expect(cfg.enabled).toBe(false);
  });

  it("accepts explicit thresholds", () => {
    const cfg = new GuardConfig({ blockThreshold: 0.8, warnThreshold: 0.3 });
    expect(cfg.blockThreshold).toBe(0.8);
    expect(cfg.warnThreshold).toBe(0.3);
  });

  it("accepts only blockThreshold", () => {
    const cfg = new GuardConfig({ blockThreshold: 0.6 });
    expect(cfg.blockThreshold).toBe(0.6);
    expect(cfg.warnThreshold).toBeNull();
  });

  it("accepts only warnThreshold", () => {
    const cfg = new GuardConfig({ warnThreshold: 0.2 });
    expect(cfg.warnThreshold).toBe(0.2);
    expect(cfg.blockThreshold).toBeNull();
  });

  it("accepts boundary blockThreshold of 0.0", () => {
    const cfg = new GuardConfig({ blockThreshold: 0.0 });
    expect(cfg.blockThreshold).toBe(0.0);
  });

  it("accepts boundary blockThreshold of 1.0", () => {
    const cfg = new GuardConfig({ blockThreshold: 1.0 });
    expect(cfg.blockThreshold).toBe(1.0);
  });
});

describe("GuardConfig validation", () => {
  it("rejects blockThreshold below zero", () => {
    expect(() => new GuardConfig({ blockThreshold: -0.1 })).toThrow(/blockThreshold/);
  });

  it("rejects blockThreshold above one", () => {
    expect(() => new GuardConfig({ blockThreshold: 1.1 })).toThrow(/blockThreshold/);
  });

  it("rejects warnThreshold below zero", () => {
    expect(() => new GuardConfig({ warnThreshold: -0.01 })).toThrow(/warnThreshold/);
  });

  it("rejects warnThreshold above one", () => {
    expect(() => new GuardConfig({ warnThreshold: 1.01 })).toThrow(/warnThreshold/);
  });

  it("rejects warn equal to block", () => {
    expect(() => new GuardConfig({ blockThreshold: 0.5, warnThreshold: 0.5 })).toThrow(
      /warnThreshold must be strictly less/,
    );
  });

  it("rejects warn greater than block", () => {
    expect(() => new GuardConfig({ blockThreshold: 0.4, warnThreshold: 0.6 })).toThrow(
      /warnThreshold must be strictly less/,
    );
  });

  it("accepts warn strictly less than block", () => {
    const cfg = new GuardConfig({ blockThreshold: 0.8, warnThreshold: 0.3 });
    expect(cfg.blockThreshold).toBe(0.8);
    expect(cfg.warnThreshold).toBe(0.3);
  });
});

describe("Policy construction", () => {
  it("defaults name to 'default'", () => {
    const p = new Policy({ blockThreshold: 0.75, warnThreshold: 0.4 });
    expect(p.name).toBe("default");
  });

  it("stores blockThreshold", () => {
    const p = new Policy({ name: "x", blockThreshold: 0.8, warnThreshold: 0.3 });
    expect(p.blockThreshold).toBe(0.8);
  });

  it("stores warnThreshold", () => {
    const p = new Policy({ name: "x", blockThreshold: 0.8, warnThreshold: 0.3 });
    expect(p.warnThreshold).toBe(0.3);
  });

  it("defaults raiseOnBlock to true", () => {
    const p = new Policy({ name: "x", blockThreshold: 0.75, warnThreshold: 0.4 });
    expect(p.raiseOnBlock).toBe(true);
  });

  it("defaults redactOnWarn to true", () => {
    const p = new Policy({ name: "x", blockThreshold: 0.75, warnThreshold: 0.4 });
    expect(p.redactOnWarn).toBe(true);
  });

  it("defaults logCleanRequests to false", () => {
    const p = new Policy({ name: "x", blockThreshold: 0.75, warnThreshold: 0.4 });
    expect(p.logCleanRequests).toBe(false);
  });

  it("defaults allowedTools to null", () => {
    const p = new Policy({ name: "x", blockThreshold: 0.75, warnThreshold: 0.4 });
    expect(p.allowedTools).toBeNull();
  });

  it("defaults blockedTools to an empty set", () => {
    const p = new Policy({ name: "x", blockThreshold: 0.75, warnThreshold: 0.4 });
    expect(p.blockedTools).toEqual(new Set());
  });

  it("defaults metadata to an empty object", () => {
    const p = new Policy({ name: "x", blockThreshold: 0.75, warnThreshold: 0.4 });
    expect(p.metadata).toEqual({});
  });

  it("defaults all guard configs to enabled", () => {
    const p = new Policy({ name: "x", blockThreshold: 0.75, warnThreshold: 0.4 });
    expect(p.promptGuard.enabled).toBe(true);
    expect(p.outputGuard.enabled).toBe(true);
    expect(p.toolGuard.enabled).toBe(true);
  });

  it("normalises allowedTools to lowercase", () => {
    const p = new Policy({
      name: "x",
      blockThreshold: 0.75,
      warnThreshold: 0.4,
      allowedTools: ["Search_Web", "READ_FILE"],
    });
    expect(p.allowedTools).toContain("search_web");
    expect(p.allowedTools).toContain("read_file");
    expect(p.allowedTools).not.toContain("Search_Web");
  });

  it("normalises blockedTools to lowercase", () => {
    const p = new Policy({
      name: "x",
      blockThreshold: 0.75,
      warnThreshold: 0.4,
      blockedTools: new Set(["DELETE_FILE"]),
    });
    expect(p.blockedTools.has("delete_file")).toBe(true);
  });
});

describe("Policy validation", () => {
  it("rejects an empty name", () => {
    expect(() => new Policy({ name: "", blockThreshold: 0.75, warnThreshold: 0.4 })).toThrow(
      /non-empty/,
    );
  });

  it("rejects a whitespace-only name", () => {
    expect(() => new Policy({ name: "   ", blockThreshold: 0.75, warnThreshold: 0.4 })).toThrow(
      /non-empty/,
    );
  });

  it("rejects blockThreshold above one", () => {
    expect(() => new Policy({ name: "x", blockThreshold: 1.5, warnThreshold: 0.4 })).toThrow(
      /blockThreshold/,
    );
  });

  it("rejects blockThreshold below zero", () => {
    expect(() => new Policy({ name: "x", blockThreshold: -0.1, warnThreshold: 0.0 })).toThrow(
      /blockThreshold/,
    );
  });

  it("rejects warnThreshold above one", () => {
    expect(() => new Policy({ name: "x", blockThreshold: 0.75, warnThreshold: 1.1 })).toThrow(
      /warnThreshold/,
    );
  });

  it("rejects warnThreshold below zero", () => {
    expect(() => new Policy({ name: "x", blockThreshold: 0.75, warnThreshold: -0.1 })).toThrow(
      /warnThreshold/,
    );
  });

  it("rejects warn equal to block", () => {
    expect(() => new Policy({ name: "x", blockThreshold: 0.5, warnThreshold: 0.5 })).toThrow(
      /warnThreshold must be strictly less/,
    );
  });

  it("rejects warn greater than block", () => {
    expect(() => new Policy({ name: "x", blockThreshold: 0.4, warnThreshold: 0.6 })).toThrow(
      /warnThreshold must be strictly less/,
    );
  });

  it("allows the boundary block=1.0, warn=0.0 (LoggingOnly pattern)", () => {
    const p = new Policy({ name: "x", blockThreshold: 1.0, warnThreshold: 0.0 });
    expect(p.blockThreshold).toBe(1.0);
    expect(p.warnThreshold).toBe(0.0);
  });
});

describe("Preset defaults", () => {
  it("BalancedPolicy has name 'balanced'", () => {
    expect(BalancedPolicy().name).toBe("balanced");
  });

  it("BalancedPolicy blockThreshold", () => {
    expect(BalancedPolicy().blockThreshold).toBe(0.75);
  });

  it("BalancedPolicy warnThreshold", () => {
    expect(BalancedPolicy().warnThreshold).toBe(0.4);
  });

  it("BalancedPolicy raiseOnBlock", () => {
    expect(BalancedPolicy().raiseOnBlock).toBe(true);
  });

  it("BalancedPolicy redactOnWarn", () => {
    expect(BalancedPolicy().redactOnWarn).toBe(true);
  });

  it("BalancedPolicy logCleanRequests", () => {
    expect(BalancedPolicy().logCleanRequests).toBe(false);
  });

  it("StrictPolicy has name 'strict'", () => {
    expect(StrictPolicy().name).toBe("strict");
  });

  it("StrictPolicy blockThreshold", () => {
    expect(StrictPolicy().blockThreshold).toBe(0.4);
  });

  it("StrictPolicy warnThreshold", () => {
    expect(StrictPolicy().warnThreshold).toBe(0.15);
  });

  it("StrictPolicy raiseOnBlock", () => {
    expect(StrictPolicy().raiseOnBlock).toBe(true);
  });

  it("StrictPolicy redactOnWarn", () => {
    expect(StrictPolicy().redactOnWarn).toBe(true);
  });

  it("StrictPolicy logCleanRequests", () => {
    expect(StrictPolicy().logCleanRequests).toBe(true);
  });

  it("LoggingOnlyPolicy has name 'logging-only'", () => {
    expect(LoggingOnlyPolicy().name).toBe("logging-only");
  });

  it("LoggingOnlyPolicy blockThreshold", () => {
    expect(LoggingOnlyPolicy().blockThreshold).toBe(1.0);
  });

  it("LoggingOnlyPolicy warnThreshold", () => {
    expect(LoggingOnlyPolicy().warnThreshold).toBe(0.99);
  });

  it("LoggingOnlyPolicy raiseOnBlock", () => {
    expect(LoggingOnlyPolicy().raiseOnBlock).toBe(false);
  });

  it("LoggingOnlyPolicy redactOnWarn", () => {
    expect(LoggingOnlyPolicy().redactOnWarn).toBe(false);
  });

  it("LoggingOnlyPolicy logCleanRequests", () => {
    expect(LoggingOnlyPolicy().logCleanRequests).toBe(true);
  });

  it("all presets return a Policy instance", () => {
    for (const factory of [BalancedPolicy, StrictPolicy, LoggingOnlyPolicy]) {
      expect(factory()).toBeInstanceOf(Policy);
    }
  });
});

describe("Preset overrides", () => {
  it("BalancedPolicy accepts a custom name", () => {
    const p = BalancedPolicy({ name: "my-policy" });
    expect(p.name).toBe("my-policy");
  });

  it("BalancedPolicy accepts a custom blockThreshold", () => {
    const p = BalancedPolicy({ blockThreshold: 0.9 });
    expect(p.blockThreshold).toBe(0.9);
  });

  it("BalancedPolicy accepts raiseOnBlock=false", () => {
    const p = BalancedPolicy({ raiseOnBlock: false });
    expect(p.raiseOnBlock).toBe(false);
  });

  it("StrictPolicy accepts a custom name", () => {
    const p = StrictPolicy({ name: "strict-prod" });
    expect(p.name).toBe("strict-prod");
  });

  it("StrictPolicy accepts a custom blockThreshold", () => {
    const p = StrictPolicy({ blockThreshold: 0.3 });
    expect(p.blockThreshold).toBe(0.3);
  });

  it("LoggingOnlyPolicy accepts a custom name", () => {
    const p = LoggingOnlyPolicy({ name: "dev-logging" });
    expect(p.name).toBe("dev-logging");
  });

  it("preset override of allowedTools", () => {
    const p = BalancedPolicy({ allowedTools: ["search_web"] });
    expect(p.isToolAllowed("search_web")).toBe(true);
    expect(p.isToolAllowed("delete_file")).toBe(false);
  });

  it("preset override of blockedTools", () => {
    const p = BalancedPolicy({ blockedTools: new Set(["exec_shell"]) });
    expect(p.isToolAllowed("exec_shell")).toBe(false);
  });

  it("preset override of metadata", () => {
    const p = BalancedPolicy({ metadata: { env: "production" } });
    expect(p.metadata).toEqual({ env: "production" });
  });
});

describe("actionForScore", () => {
  it("LOG at zero", () => {
    expect(BalancedPolicy().actionForScore(0.0, GuardType.PROMPT)).toBe(PolicyAction.LOG);
  });

  it("LOG in the middle of the log band", () => {
    expect(BalancedPolicy().actionForScore(0.2, GuardType.PROMPT)).toBe(PolicyAction.LOG);
  });

  it("LOG just below warn", () => {
    expect(BalancedPolicy().actionForScore(0.39, GuardType.PROMPT)).toBe(PolicyAction.LOG);
  });

  it("WARN at the boundary", () => {
    expect(BalancedPolicy().actionForScore(0.4, GuardType.PROMPT)).toBe(PolicyAction.WARN);
  });

  it("WARN in the middle of the warn band", () => {
    expect(BalancedPolicy().actionForScore(0.55, GuardType.PROMPT)).toBe(PolicyAction.WARN);
  });

  it("WARN just below block", () => {
    expect(BalancedPolicy().actionForScore(0.74, GuardType.PROMPT)).toBe(PolicyAction.WARN);
  });

  it("BLOCK at the boundary", () => {
    expect(BalancedPolicy().actionForScore(0.75, GuardType.PROMPT)).toBe(PolicyAction.BLOCK);
  });

  it("BLOCK in the middle of the block band", () => {
    expect(BalancedPolicy().actionForScore(0.92, GuardType.PROMPT)).toBe(PolicyAction.BLOCK);
  });

  it("BLOCK at one", () => {
    expect(BalancedPolicy().actionForScore(1.0, GuardType.PROMPT)).toBe(PolicyAction.BLOCK);
  });

  it("StrictPolicy blocks at its lower boundary", () => {
    expect(StrictPolicy().actionForScore(0.4, GuardType.PROMPT)).toBe(PolicyAction.BLOCK);
  });

  it("StrictPolicy blocks a medium score", () => {
    expect(StrictPolicy().actionForScore(0.55, GuardType.PROMPT)).toBe(PolicyAction.BLOCK);
  });

  it("StrictPolicy warns below its block threshold", () => {
    expect(StrictPolicy().actionForScore(0.2, GuardType.PROMPT)).toBe(PolicyAction.WARN);
  });

  it("LoggingOnlyPolicy never blocks a critical score", () => {
    const action = LoggingOnlyPolicy().actionForScore(0.92, GuardType.PROMPT);
    expect(action).not.toBe(PolicyAction.BLOCK);
  });

  it("LoggingOnlyPolicy logs a clean score", () => {
    const action = LoggingOnlyPolicy().actionForScore(0.0, GuardType.PROMPT);
    expect(action).toBe(PolicyAction.LOG);
  });

  it("LoggingOnlyPolicy logs a low score", () => {
    const action = LoggingOnlyPolicy().actionForScore(0.01, GuardType.PROMPT);
    expect(action).toBe(PolicyAction.LOG);
  });

  it("LoggingOnlyPolicy warns near a critical score", () => {
    const action = LoggingOnlyPolicy().actionForScore(0.99, GuardType.PROMPT);
    expect(action).toBe(PolicyAction.WARN);
  });

  it("accepts all guard types", () => {
    const p = BalancedPolicy();
    for (const gt of Object.values(GuardType)) {
      expect(p.actionForScore(0.92, gt)).toBe(PolicyAction.BLOCK);
    }
  });

  it("per-guard override: prompt blocks at a lower score", () => {
    const p = BalancedPolicy({ promptGuard: new GuardConfig({ blockThreshold: 0.5 }) });
    expect(p.actionForScore(0.6, GuardType.PROMPT)).toBe(PolicyAction.BLOCK);
  });

  it("per-guard override: tool still uses the policy-level threshold", () => {
    const p = BalancedPolicy({ promptGuard: new GuardConfig({ blockThreshold: 0.5 }) });
    expect(p.actionForScore(0.6, GuardType.TOOL)).toBe(PolicyAction.WARN);
  });

  it("per-guard warn override", () => {
    const p = BalancedPolicy({ outputGuard: new GuardConfig({ warnThreshold: 0.2 }) });
    expect(p.actionForScore(0.25, GuardType.OUTPUT)).toBe(PolicyAction.WARN);
    expect(BalancedPolicy().actionForScore(0.25, GuardType.OUTPUT)).toBe(PolicyAction.LOG);
  });
});

describe("effective thresholds", () => {
  it("effectiveBlockThreshold falls back to policy level with no override", () => {
    const p = BalancedPolicy();
    expect(p.effectiveBlockThreshold(GuardType.PROMPT)).toBe(0.75);
    expect(p.effectiveBlockThreshold(GuardType.OUTPUT)).toBe(0.75);
    expect(p.effectiveBlockThreshold(GuardType.TOOL)).toBe(0.75);
  });

  it("effectiveWarnThreshold falls back to policy level with no override", () => {
    const p = BalancedPolicy();
    expect(p.effectiveWarnThreshold(GuardType.PROMPT)).toBe(0.4);
    expect(p.effectiveWarnThreshold(GuardType.OUTPUT)).toBe(0.4);
    expect(p.effectiveWarnThreshold(GuardType.TOOL)).toBe(0.4);
  });

  it("effectiveBlockThreshold uses the guard override", () => {
    const p = BalancedPolicy({ promptGuard: new GuardConfig({ blockThreshold: 0.5 }) });
    expect(p.effectiveBlockThreshold(GuardType.PROMPT)).toBe(0.5);
  });

  it("other guards are unaffected by a prompt override", () => {
    const p = BalancedPolicy({ promptGuard: new GuardConfig({ blockThreshold: 0.5 }) });
    expect(p.effectiveBlockThreshold(GuardType.OUTPUT)).toBe(0.75);
    expect(p.effectiveBlockThreshold(GuardType.TOOL)).toBe(0.75);
  });

  it("effectiveWarnThreshold uses the guard override", () => {
    const p = BalancedPolicy({ outputGuard: new GuardConfig({ warnThreshold: 0.2 }) });
    expect(p.effectiveWarnThreshold(GuardType.OUTPUT)).toBe(0.2);
  });

  it("other guards are unaffected by an output warn override", () => {
    const p = BalancedPolicy({ outputGuard: new GuardConfig({ warnThreshold: 0.2 }) });
    expect(p.effectiveWarnThreshold(GuardType.PROMPT)).toBe(0.4);
  });

  it("both overrides can apply to the same guard", () => {
    const p = BalancedPolicy({
      toolGuard: new GuardConfig({ blockThreshold: 0.55, warnThreshold: 0.2 }),
    });
    expect(p.effectiveBlockThreshold(GuardType.TOOL)).toBe(0.55);
    expect(p.effectiveWarnThreshold(GuardType.TOOL)).toBe(0.2);
  });
});

describe("isGuardEnabled", () => {
  it("all guards enabled by default", () => {
    const p = BalancedPolicy();
    expect(p.isGuardEnabled(GuardType.PROMPT)).toBe(true);
    expect(p.isGuardEnabled(GuardType.OUTPUT)).toBe(true);
    expect(p.isGuardEnabled(GuardType.TOOL)).toBe(true);
  });

  it("disables the prompt guard", () => {
    const p = BalancedPolicy({ promptGuard: new GuardConfig({ enabled: false }) });
    expect(p.isGuardEnabled(GuardType.PROMPT)).toBe(false);
  });

  it("disables the output guard", () => {
    const p = BalancedPolicy({ outputGuard: new GuardConfig({ enabled: false }) });
    expect(p.isGuardEnabled(GuardType.OUTPUT)).toBe(false);
  });

  it("disables the tool guard", () => {
    const p = BalancedPolicy({ toolGuard: new GuardConfig({ enabled: false }) });
    expect(p.isGuardEnabled(GuardType.TOOL)).toBe(false);
  });

  it("disabling one guard leaves the others enabled", () => {
    const p = BalancedPolicy({ promptGuard: new GuardConfig({ enabled: false }) });
    expect(p.isGuardEnabled(GuardType.OUTPUT)).toBe(true);
    expect(p.isGuardEnabled(GuardType.TOOL)).toBe(true);
  });

  it("disables all guards", () => {
    const p = BalancedPolicy({
      promptGuard: new GuardConfig({ enabled: false }),
      outputGuard: new GuardConfig({ enabled: false }),
      toolGuard: new GuardConfig({ enabled: false }),
    });
    for (const gt of Object.values(GuardType)) {
      expect(p.isGuardEnabled(gt)).toBe(false);
    }
  });
});

describe("tool filtering", () => {
  it("allows any tool with no lists configured", () => {
    const p = BalancedPolicy();
    expect(p.isToolAllowed("search_web")).toBe(true);
    expect(p.isToolAllowed("delete_file")).toBe(true);
    expect(p.isToolAllowed("exec_shell")).toBe(true);
  });

  it("allowlist permits listed tools", () => {
    const p = BalancedPolicy({ allowedTools: ["search_web", "read_file"] });
    expect(p.isToolAllowed("search_web")).toBe(true);
    expect(p.isToolAllowed("read_file")).toBe(true);
  });

  it("allowlist blocks unlisted tools", () => {
    const p = BalancedPolicy({ allowedTools: ["search_web"] });
    expect(p.isToolAllowed("delete_file")).toBe(false);
    expect(p.isToolAllowed("exec_shell")).toBe(false);
  });

  it("an empty allowlist blocks all tools", () => {
    const p = BalancedPolicy({ allowedTools: [] });
    expect(p.isToolAllowed("search_web")).toBe(false);
  });

  it("blocklist denies listed tools", () => {
    const p = BalancedPolicy({ blockedTools: new Set(["delete_file", "exec_shell"]) });
    expect(p.isToolAllowed("delete_file")).toBe(false);
    expect(p.isToolAllowed("exec_shell")).toBe(false);
  });

  it("blocklist permits unlisted tools", () => {
    const p = BalancedPolicy({ blockedTools: new Set(["delete_file"]) });
    expect(p.isToolAllowed("search_web")).toBe(true);
  });

  it("blocklist beats allowlist for the same tool", () => {
    const p = BalancedPolicy({
      allowedTools: ["delete_file", "search_web"],
      blockedTools: new Set(["delete_file"]),
    });
    expect(p.isToolAllowed("delete_file")).toBe(false);
    expect(p.isToolAllowed("search_web")).toBe(true);
  });

  it("allowlist matching is case-insensitive", () => {
    const p = BalancedPolicy({ allowedTools: ["Search_Web"] });
    expect(p.isToolAllowed("search_web")).toBe(true);
    expect(p.isToolAllowed("SEARCH_WEB")).toBe(true);
    expect(p.isToolAllowed("Search_Web")).toBe(true);
  });

  it("blocklist matching is case-insensitive", () => {
    const p = BalancedPolicy({ blockedTools: new Set(["DELETE_FILE"]) });
    expect(p.isToolAllowed("delete_file")).toBe(false);
    expect(p.isToolAllowed("Delete_File")).toBe(false);
  });

  it("query is case-insensitive against no lists", () => {
    const p = BalancedPolicy();
    expect(p.isToolAllowed("SEARCH_WEB")).toBe(true);
  });

  it("withAllowedTools produces the expected result", () => {
    const p = BalancedPolicy().withAllowedTools(["search_web"]);
    expect(p.isToolAllowed("search_web")).toBe(true);
    expect(p.isToolAllowed("delete_file")).toBe(false);
  });

  it("withBlockedTools produces the expected result", () => {
    const p = BalancedPolicy().withBlockedTools(["exec_shell"]);
    expect(p.isToolAllowed("exec_shell")).toBe(false);
    expect(p.isToolAllowed("search_web")).toBe(true);
  });
});

describe("Policy mutators", () => {
  it("replace() returns a new instance", () => {
    const p = BalancedPolicy();
    const p2 = p.replace({ blockThreshold: 0.5 });
    expect(p2).not.toBe(p);
  });

  it("replace() applies the override", () => {
    const p = BalancedPolicy();
    const p2 = p.replace({ blockThreshold: 0.5 });
    expect(p2.blockThreshold).toBe(0.5);
  });

  it("replace() does not mutate the original", () => {
    const p = BalancedPolicy();
    p.replace({ blockThreshold: 0.5 });
    expect(p.blockThreshold).toBe(0.75);
  });

  it("replace() preserves unmentioned fields", () => {
    const p = BalancedPolicy({ name: "base", warnThreshold: 0.3 });
    const p2 = p.replace({ blockThreshold: 0.6 });
    expect(p2.name).toBe("base");
    expect(p2.warnThreshold).toBe(0.3);
  });

  it("replace() can change the name", () => {
    const p = BalancedPolicy();
    const p2 = p.replace({ name: "renamed" });
    expect(p2.name).toBe("renamed");
  });

  it("replace() can change raiseOnBlock", () => {
    const p = BalancedPolicy();
    const p2 = p.replace({ raiseOnBlock: false });
    expect(p2.raiseOnBlock).toBe(false);
  });

  it("replace() rejects an unknown field", () => {
    const p = BalancedPolicy();
    expect(() => p.replace({ nonexistentField: 99 } as never)).toThrow(/unknown field/);
  });

  it("replace() applies multiple fields at once", () => {
    const p = BalancedPolicy();
    const p2 = p.replace({ blockThreshold: 0.6, warnThreshold: 0.25, name: "custom" });
    expect(p2.blockThreshold).toBe(0.6);
    expect(p2.warnThreshold).toBe(0.25);
    expect(p2.name).toBe("custom");
  });

  it("withAllowedTools() returns a new policy", () => {
    const p = BalancedPolicy();
    const p2 = p.withAllowedTools(["search_web"]);
    expect(p2).not.toBe(p);
  });

  it("withAllowedTools() does not mutate the original", () => {
    const p = BalancedPolicy();
    p.withAllowedTools(["search_web"]);
    expect(p.allowedTools).toBeNull();
  });

  it("withBlockedTools() returns a new policy", () => {
    const p = BalancedPolicy();
    const p2 = p.withBlockedTools(["exec_shell"]);
    expect(p2).not.toBe(p);
  });

  it("withBlockedTools() does not mutate the original", () => {
    const p = BalancedPolicy();
    p.withBlockedTools(["exec_shell"]);
    expect(p.blockedTools).toEqual(new Set());
  });
});

describe("Policy.toDict()", () => {
  it("contains all required keys", () => {
    const d = BalancedPolicy().toDict();
    const expected = [
      "name",
      "block_threshold",
      "warn_threshold",
      "raise_on_block",
      "prompt_guard",
      "output_guard",
      "tool_guard",
      "allowed_tools",
      "blocked_tools",
      "redact_on_warn",
      "log_clean_requests",
      "metadata",
    ].sort();
    expect(Object.keys(d).sort()).toEqual(expected);
  });

  it("name value", () => {
    expect(BalancedPolicy().toDict().name).toBe("balanced");
  });

  it("block_threshold value", () => {
    expect(BalancedPolicy().toDict().block_threshold).toBe(0.75);
  });

  it("warn_threshold value", () => {
    expect(BalancedPolicy().toDict().warn_threshold).toBe(0.4);
  });

  it("allowed_tools is null when no list is set", () => {
    expect(BalancedPolicy().toDict().allowed_tools).toBeNull();
  });

  it("allowed_tools is a list when set", () => {
    const p = BalancedPolicy({ allowedTools: ["search_web"] });
    expect(p.toDict().allowed_tools).toEqual(["search_web"]);
  });

  it("blocked_tools is an empty list when no set is provided", () => {
    const d = BalancedPolicy().toDict();
    expect(Array.isArray(d.blocked_tools)).toBe(true);
    expect(d.blocked_tools).toEqual([]);
  });

  it("blocked_tools is a sorted list when set", () => {
    const p = BalancedPolicy({ blockedTools: new Set(["exec_shell", "delete_file"]) });
    const d = p.toDict();
    expect(Array.isArray(d.blocked_tools)).toBe(true);
    expect([...d.blocked_tools].sort()).toEqual(d.blocked_tools);
    expect(d.blocked_tools).toContain("delete_file");
    expect(d.blocked_tools).toContain("exec_shell");
  });

  it("guard configs are serialised as plain objects", () => {
    const d = BalancedPolicy().toDict();
    for (const key of ["prompt_guard", "output_guard", "tool_guard"] as const) {
      expect(typeof d[key]).toBe("object");
      expect(Object.keys(d[key]).sort()).toEqual(["block_threshold", "enabled", "warn_threshold"]);
    }
  });

  it("guard config enabled defaults to true", () => {
    const d = BalancedPolicy().toDict();
    expect(d.prompt_guard.enabled).toBe(true);
  });

  it("guard config thresholds are null when no override", () => {
    const d = BalancedPolicy().toDict();
    expect(d.prompt_guard.block_threshold).toBeNull();
    expect(d.prompt_guard.warn_threshold).toBeNull();
  });

  it("guard config override is serialised", () => {
    const p = BalancedPolicy({ promptGuard: new GuardConfig({ blockThreshold: 0.5 }) });
    const d = p.toDict();
    expect(d.prompt_guard.block_threshold).toBe(0.5);
  });

  it("metadata is preserved", () => {
    const p = BalancedPolicy({ metadata: { env: "prod", team: "platform" } });
    expect(p.toDict().metadata).toEqual({ env: "prod", team: "platform" });
  });

  it("log_clean_requests for balanced", () => {
    expect(BalancedPolicy().toDict().log_clean_requests).toBe(false);
  });

  it("log_clean_requests for strict", () => {
    expect(StrictPolicy().toDict().log_clean_requests).toBe(true);
  });
});

describe("Policy.toString()", () => {
  it("contains the name", () => {
    expect(BalancedPolicy().toString()).toContain("balanced");
  });

  it("contains the block threshold", () => {
    expect(BalancedPolicy().toString()).toContain("0.75");
  });

  it("contains the warn threshold", () => {
    expect(BalancedPolicy().toString()).toContain("0.4");
  });

  it("contains raiseOnBlock", () => {
    expect(BalancedPolicy().toString()).toContain("raiseOnBlock");
  });

  it("is a string", () => {
    expect(typeof BalancedPolicy().toString()).toBe("string");
  });
});

describe("loadPolicyFromDict", () => {
  it("returns a Policy instance", () => {
    const p = loadPolicyFromDict({ block_threshold: 0.75, warn_threshold: 0.4 });
    expect(p).toBeInstanceOf(Policy);
  });

  it("loads the name", () => {
    const p = loadPolicyFromDict({
      name: "my-policy",
      block_threshold: 0.75,
      warn_threshold: 0.4,
    });
    expect(p.name).toBe("my-policy");
  });

  it("loads block_threshold", () => {
    const p = loadPolicyFromDict({ block_threshold: 0.6, warn_threshold: 0.25 });
    expect(p.blockThreshold).toBe(0.6);
  });

  it("loads warn_threshold", () => {
    const p = loadPolicyFromDict({ block_threshold: 0.6, warn_threshold: 0.25 });
    expect(p.warnThreshold).toBe(0.25);
  });

  it("loads raise_on_block=false", () => {
    const p = loadPolicyFromDict({
      block_threshold: 0.75,
      warn_threshold: 0.4,
      raise_on_block: false,
    });
    expect(p.raiseOnBlock).toBe(false);
  });

  it("loads an allowed_tools list", () => {
    const p = loadPolicyFromDict({
      block_threshold: 0.75,
      warn_threshold: 0.4,
      allowed_tools: ["search_web", "read_file"],
    });
    expect(p.isToolAllowed("search_web")).toBe(true);
    expect(p.isToolAllowed("delete_file")).toBe(false);
  });

  it("converts a blocked_tools list into a set", () => {
    const p = loadPolicyFromDict({
      block_threshold: 0.75,
      warn_threshold: 0.4,
      blocked_tools: ["exec_shell"],
    });
    expect(p.isToolAllowed("exec_shell")).toBe(false);
  });

  it("converts a nested prompt_guard dict", () => {
    const p = loadPolicyFromDict({
      block_threshold: 0.75,
      warn_threshold: 0.4,
      prompt_guard: { enabled: false },
    });
    expect(p.promptGuard).toBeInstanceOf(GuardConfig);
    expect(p.promptGuard.enabled).toBe(false);
  });

  it("applies a nested guard block_threshold override", () => {
    const p = loadPolicyFromDict({
      block_threshold: 0.75,
      warn_threshold: 0.4,
      output_guard: { block_threshold: 0.55, warn_threshold: 0.2 },
    });
    expect(p.effectiveBlockThreshold(GuardType.OUTPUT)).toBe(0.55);
    expect(p.effectiveWarnThreshold(GuardType.OUTPUT)).toBe(0.2);
  });

  it("silently ignores unknown keys", () => {
    const p = loadPolicyFromDict({
      block_threshold: 0.75,
      warn_threshold: 0.4,
      future_field: "ignored",
      another_unknown: 42,
    });
    expect(p.blockThreshold).toBe(0.75);
  });

  it("returns a valid policy for an empty dict", () => {
    const p = loadPolicyFromDict({});
    expect(p).toBeInstanceOf(Policy);
  });

  it("uses Policy defaults for an empty dict", () => {
    const p = loadPolicyFromDict({});
    expect(p.blockThreshold).toBe(0.75);
    expect(p.warnThreshold).toBe(0.4);
  });

  it("loads metadata", () => {
    const p = loadPolicyFromDict({
      block_threshold: 0.75,
      warn_threshold: 0.4,
      metadata: { env: "staging" },
    });
    expect(p.metadata).toEqual({ env: "staging" });
  });

  it("does not mutate the input dict", () => {
    const original: Record<string, unknown> = {
      block_threshold: 0.75,
      warn_threshold: 0.4,
      blocked_tools: ["exec_shell"],
    };
    const originalCopy = JSON.parse(JSON.stringify(original));
    loadPolicyFromDict(original);
    expect(original).toEqual(originalCopy);
  });
});

describe("loadPolicyFromYaml", () => {
  let tmpDir: string;

  function writeYaml(contents: string): string {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "quisium-policy-"));
    const file = path.join(tmpDir, "policy.yaml");
    fs.writeFileSync(file, contents, "utf-8");
    return file;
  }

  it("loads a valid YAML file", async () => {
    const file = writeYaml("name: yaml-policy\nblock_threshold: 0.65\nwarn_threshold: 0.30\n");
    const p = await loadPolicyFromYaml(file);
    expect(p.name).toBe("yaml-policy");
    expect(p.blockThreshold).toBe(0.65);
  });

  it("rejects a missing file", async () => {
    await expect(loadPolicyFromYaml("/nonexistent/path/policy.yaml")).rejects.toThrow();
  });

  it("rejects a YAML file whose top level isn't a mapping", async () => {
    const file = writeYaml("- 1\n- 2\n- 3\n");
    await expect(loadPolicyFromYaml(file)).rejects.toThrow(/mapping/);
  });

  it("loads nested guard overrides from YAML", async () => {
    const file = writeYaml(
      "block_threshold: 0.75\nwarn_threshold: 0.40\noutput_guard:\n  block_threshold: 0.55\n  warn_threshold: 0.20\n",
    );
    const p = await loadPolicyFromYaml(file);
    expect(p.effectiveBlockThreshold(GuardType.OUTPUT)).toBe(0.55);
    expect(p.effectiveWarnThreshold(GuardType.OUTPUT)).toBe(0.2);
  });
});
