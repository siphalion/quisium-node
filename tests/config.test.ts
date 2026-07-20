import { describe, it, expect, afterEach } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import {
  ConfigError,
  ConfigSourceError,
  ConfigValidationError,
  getDefaultPolicy,
  loadConfig,
  resetDefaultPolicy,
  setDefaultPolicy,
  validateConfigDict,
} from "../src/config.js";
import { BalancedPolicy, GuardConfig, Policy, StrictPolicy } from "../src/policies.js";
import { GuardType } from "../src/types.js";

const ENV_VARS = [
  "LLM_SECURITY_NAME",
  "LLM_SECURITY_BLOCK_THRESHOLD",
  "LLM_SECURITY_WARN_THRESHOLD",
  "LLM_SECURITY_RAISE_ON_BLOCK",
  "LLM_SECURITY_REDACT_ON_WARN",
  "LLM_SECURITY_LOG_CLEAN_REQUESTS",
  "LLM_SECURITY_ALLOWED_TOOLS",
  "LLM_SECURITY_BLOCKED_TOOLS",
  "LLM_SECURITY_PROMPT_GUARD_ENABLED",
  "LLM_SECURITY_OUTPUT_GUARD_ENABLED",
  "LLM_SECURITY_TOOL_GUARD_ENABLED",
];

afterEach(() => {
  for (const key of ENV_VARS) delete process.env[key];
});

describe("config exceptions", () => {
  it("ConfigError is an Error", () => {
    const exc = new ConfigError("base error");
    expect(exc).toBeInstanceOf(Error);
  });

  it("ConfigValidationError is a ConfigError", () => {
    const exc = new ConfigValidationError(["error A"]);
    expect(exc).toBeInstanceOf(ConfigError);
  });

  it("ConfigSourceError is a ConfigError", () => {
    const exc = new ConfigSourceError("file missing");
    expect(exc).toBeInstanceOf(ConfigError);
  });

  it("stores the errors list", () => {
    const exc = new ConfigValidationError(["err A", "err B"]);
    expect(exc.errors).toEqual(["err A", "err B"]);
  });

  it("stores a single error", () => {
    const exc = new ConfigValidationError(["only error"]);
    expect(exc.errors).toHaveLength(1);
    expect(exc.errors[0]).toBe("only error");
  });

  it("message contains all errors", () => {
    const exc = new ConfigValidationError(["err A", "err B"]);
    expect(exc.message).toContain("err A");
    expect(exc.message).toContain("err B");
  });

  it("message contains the error count", () => {
    const exc = new ConfigValidationError(["err A", "err B"]);
    expect(exc.message).toContain("2");
  });

  it("accepts an empty error list without crashing", () => {
    const exc = new ConfigValidationError([]);
    expect(exc.errors).toEqual([]);
  });

  it("ConfigSourceError message is preserved", () => {
    const exc = new ConfigSourceError("policy.yaml not found");
    expect(exc.message).toContain("policy.yaml not found");
  });
});

// The Python suite unit-tests private helpers `_parse_bool`, `_parse_csv_list`,
// `_parse_csv_set`, and `_deep_merge` directly. The TS port keeps these as
// unexported implementation details of config.ts, so their behaviour is
// exercised here indirectly through the public `loadConfig` / env-var surface
// that calls them.
describe("boolean env var parsing (via LLM_SECURITY_RAISE_ON_BLOCK)", () => {
  it.each(["1", "true", "True", "TRUE", "yes", "Yes", "YES", "on", "ON"])(
    "%s is truthy",
    async (value) => {
      process.env.LLM_SECURITY_RAISE_ON_BLOCK = value;
      const p = await loadConfig({ useEnv: true, data: {} });
      expect(p.raiseOnBlock).toBe(true);
    },
  );

  it.each(["0", "false", "False", "FALSE", "no", "No", "NO", "off", "OFF"])(
    "%s is falsy",
    async (value) => {
      process.env.LLM_SECURITY_RAISE_ON_BLOCK = value;
      const p = await loadConfig({ useEnv: true, data: {} });
      expect(p.raiseOnBlock).toBe(false);
    },
  );

  it("trims surrounding whitespace on truthy values", async () => {
    process.env.LLM_SECURITY_RAISE_ON_BLOCK = "  true  ";
    const p = await loadConfig({ useEnv: true, data: {} });
    expect(p.raiseOnBlock).toBe(true);
  });

  it("trims surrounding whitespace on falsy values", async () => {
    process.env.LLM_SECURITY_RAISE_ON_BLOCK = "  false  ";
    const p = await loadConfig({ useEnv: true, data: {} });
    expect(p.raiseOnBlock).toBe(false);
  });

  it("rejects an unparsable string", async () => {
    process.env.LLM_SECURITY_RAISE_ON_BLOCK = "maybe";
    await expect(loadConfig({ useEnv: true, data: {} })).rejects.toBeInstanceOf(
      ConfigValidationError,
    );
  });

  it("rejects the numeral 2", async () => {
    process.env.LLM_SECURITY_RAISE_ON_BLOCK = "2";
    await expect(loadConfig({ useEnv: true, data: {} })).rejects.toBeInstanceOf(
      ConfigValidationError,
    );
  });
});

describe("CSV list env var parsing (via LLM_SECURITY_ALLOWED_TOOLS)", () => {
  it("parses two items", async () => {
    process.env.LLM_SECURITY_ALLOWED_TOOLS = "read_file,search_web";
    const p = await loadConfig({ useEnv: true, data: {} });
    expect(p.toDict().allowed_tools).toEqual(["read_file", "search_web"]);
  });

  it("strips whitespace around items", async () => {
    process.env.LLM_SECURITY_ALLOWED_TOOLS = "read_file, search_web , exec";
    const p = await loadConfig({ useEnv: true, data: {} });
    expect(p.toDict().allowed_tools).toEqual(["read_file", "search_web", "exec"]);
  });

  it("drops a trailing comma", async () => {
    process.env.LLM_SECURITY_ALLOWED_TOOLS = "read_file,search_web,";
    const p = await loadConfig({ useEnv: true, data: {} });
    expect(p.toDict().allowed_tools).toEqual(["read_file", "search_web"]);
  });

  it("commas with no real items yield an empty (blocking) allowlist", async () => {
    process.env.LLM_SECURITY_ALLOWED_TOOLS = ",,,";
    const p = await loadConfig({ useEnv: true, data: {} });
    expect(p.toDict().allowed_tools).toEqual([]);
  });

  it("single item", async () => {
    process.env.LLM_SECURITY_ALLOWED_TOOLS = "search_web";
    const p = await loadConfig({ useEnv: true, data: {} });
    expect(p.toDict().allowed_tools).toEqual(["search_web"]);
  });
});

describe("CSV set env var parsing (via LLM_SECURITY_BLOCKED_TOOLS)", () => {
  it("contains expected items", async () => {
    process.env.LLM_SECURITY_BLOCKED_TOOLS = "exec_shell,delete_file";
    const p = await loadConfig({ useEnv: true, data: {} });
    expect(p.isToolAllowed("exec_shell")).toBe(false);
    expect(p.isToolAllowed("delete_file")).toBe(false);
  });

  it("deduplicates items", async () => {
    process.env.LLM_SECURITY_BLOCKED_TOOLS = "search_web,search_web";
    const p = await loadConfig({ useEnv: true, data: {} });
    expect(p.toDict().blocked_tools).toEqual(["search_web"]);
  });

  it("empty string yields an empty blocklist", async () => {
    process.env.LLM_SECURITY_BLOCKED_TOOLS = "";
    const p = await loadConfig({ useEnv: true, data: {} });
    expect(p.toDict().blocked_tools).toEqual([]);
  });

  it("single item", async () => {
    process.env.LLM_SECURITY_BLOCKED_TOOLS = "exec_shell";
    const p = await loadConfig({ useEnv: true, data: {} });
    expect(p.toDict().blocked_tools).toEqual(["exec_shell"]);
  });
});

describe("deep merge behaviour (via loadConfig precedence)", () => {
  it("non-overlapping data keys are combined with the base policy", async () => {
    const p = await loadConfig({
      basePolicy: BalancedPolicy({ metadata: { a: 1 } }),
      data: { name: "combined" },
      useEnv: false,
    });
    expect(p.name).toBe("combined");
    expect(p.metadata).toEqual({ a: 1 });
  });

  it("data overrides a scalar base value", async () => {
    const p = await loadConfig({
      basePolicy: BalancedPolicy({ blockThreshold: 0.9, warnThreshold: 0.5 }),
      data: { block_threshold: 0.6, warn_threshold: 0.25 },
      useEnv: false,
    });
    expect(p.blockThreshold).toBe(0.6);
  });

  it("nested guard dicts are merged recursively, preserving untouched sub-fields", async () => {
    const p = await loadConfig({
      basePolicy: BalancedPolicy({ promptGuard: new GuardConfig({ enabled: false }) }),
      data: { prompt_guard: { block_threshold: 0.3 } },
      useEnv: false,
    });
    // enabled=false came from the base policy and must survive the merge
    // alongside the new block_threshold from `data`.
    expect(p.isGuardEnabled(GuardType.PROMPT)).toBe(false);
    expect(p.effectiveBlockThreshold(GuardType.PROMPT)).toBe(0.3);
  });

  it("does not mutate the caller's data object", async () => {
    const data = { block_threshold: 0.6, warn_threshold: 0.25 };
    const snapshot = JSON.parse(JSON.stringify(data));
    await loadConfig({ data, useEnv: false });
    expect(data).toEqual(snapshot);
  });

  it("does not mutate the base policy across repeated loads", async () => {
    const base = StrictPolicy();
    await loadConfig({ basePolicy: base, data: { block_threshold: 0.99 }, useEnv: false });
    expect(base.blockThreshold).toBe(0.4);
  });
});

describe("validateConfigDict", () => {
  it("a valid full dict passes", () => {
    expect(() =>
      validateConfigDict({
        name: "my-policy",
        block_threshold: 0.75,
        warn_threshold: 0.4,
        raise_on_block: true,
      }),
    ).not.toThrow();
  });

  it("an empty dict passes", () => {
    expect(() => validateConfigDict({})).not.toThrow();
  });

  it("allowed_tools: null passes", () => {
    expect(() => validateConfigDict({ allowed_tools: null })).not.toThrow();
  });

  it("allowed_tools: [] passes", () => {
    expect(() => validateConfigDict({ allowed_tools: [] })).not.toThrow();
  });

  it("blocked_tools as a list passes", () => {
    expect(() => validateConfigDict({ blocked_tools: ["exec_shell"] })).not.toThrow();
  });

  it("blocked_tools as a set passes", () => {
    expect(() => validateConfigDict({ blocked_tools: new Set(["exec_shell"]) })).not.toThrow();
  });

  it("a GuardConfig instance passes", () => {
    expect(() =>
      validateConfigDict({ prompt_guard: new GuardConfig({ enabled: false }) }),
    ).not.toThrow();
  });

  it("a valid guard dict passes", () => {
    expect(() =>
      validateConfigDict({
        prompt_guard: { enabled: true, block_threshold: 0.5, warn_threshold: 0.2 },
      }),
    ).not.toThrow();
  });

  it("block_threshold above one raises", () => {
    try {
      validateConfigDict({ block_threshold: 1.5 });
      expect.unreachable();
    } catch (exc) {
      expect(exc).toBeInstanceOf(ConfigValidationError);
      expect((exc as ConfigValidationError).errors.some((e) => e.includes("block_threshold"))).toBe(
        true,
      );
    }
  });

  it("block_threshold below zero raises", () => {
    try {
      validateConfigDict({ block_threshold: -0.1 });
      expect.unreachable();
    } catch (exc) {
      expect((exc as ConfigValidationError).errors.some((e) => e.includes("block_threshold"))).toBe(
        true,
      );
    }
  });

  it("a non-number block_threshold raises", () => {
    try {
      validateConfigDict({ block_threshold: "high" });
      expect.unreachable();
    } catch (exc) {
      expect((exc as ConfigValidationError).errors.some((e) => e.includes("block_threshold"))).toBe(
        true,
      );
    }
  });

  it("block=1.0 with a lower warn passes", () => {
    expect(() => validateConfigDict({ block_threshold: 1.0, warn_threshold: 0.0 })).not.toThrow();
  });

  it("block=1.0 passes", () => {
    expect(() => validateConfigDict({ block_threshold: 1.0, warn_threshold: 0.5 })).not.toThrow();
  });

  it("warn_threshold above one raises", () => {
    try {
      validateConfigDict({ warn_threshold: 1.1 });
      expect.unreachable();
    } catch (exc) {
      expect((exc as ConfigValidationError).errors.some((e) => e.includes("warn_threshold"))).toBe(
        true,
      );
    }
  });

  it("warn_threshold below zero raises", () => {
    try {
      validateConfigDict({ warn_threshold: -0.1 });
      expect.unreachable();
    } catch (exc) {
      expect((exc as ConfigValidationError).errors.some((e) => e.includes("warn_threshold"))).toBe(
        true,
      );
    }
  });

  it("warn equal to block raises", () => {
    try {
      validateConfigDict({ block_threshold: 0.5, warn_threshold: 0.5 });
      expect.unreachable();
    } catch (exc) {
      expect(
        (exc as ConfigValidationError).errors.some(
          (e) => e.includes("warn_threshold") && e.includes("block_threshold"),
        ),
      ).toBe(true);
    }
  });

  it("warn greater than block raises", () => {
    try {
      validateConfigDict({ block_threshold: 0.4, warn_threshold: 0.6 });
      expect.unreachable();
    } catch (exc) {
      expect((exc as ConfigValidationError).errors.some((e) => e.includes("warn_threshold"))).toBe(
        true,
      );
    }
  });

  it("raise_on_block as a string raises", () => {
    try {
      validateConfigDict({ raise_on_block: "true" });
      expect.unreachable();
    } catch (exc) {
      expect((exc as ConfigValidationError).errors.some((e) => e.includes("raise_on_block"))).toBe(
        true,
      );
    }
  });

  it("raise_on_block as a number raises", () => {
    try {
      validateConfigDict({ raise_on_block: 1 });
      expect.unreachable();
    } catch (exc) {
      expect((exc as ConfigValidationError).errors.some((e) => e.includes("raise_on_block"))).toBe(
        true,
      );
    }
  });

  it("redact_on_warn as a string raises", () => {
    try {
      validateConfigDict({ redact_on_warn: "yes" });
      expect.unreachable();
    } catch (exc) {
      expect((exc as ConfigValidationError).errors.some((e) => e.includes("redact_on_warn"))).toBe(
        true,
      );
    }
  });

  it("log_clean_requests as a string raises", () => {
    try {
      validateConfigDict({ log_clean_requests: "no" });
      expect.unreachable();
    } catch (exc) {
      expect(
        (exc as ConfigValidationError).errors.some((e) => e.includes("log_clean_requests")),
      ).toBe(true);
    }
  });

  it("an empty name raises", () => {
    try {
      validateConfigDict({ name: "" });
      expect.unreachable();
    } catch (exc) {
      expect((exc as ConfigValidationError).errors.some((e) => e.includes("name"))).toBe(true);
    }
  });

  it("a whitespace-only name raises", () => {
    try {
      validateConfigDict({ name: "   " });
      expect.unreachable();
    } catch (exc) {
      expect((exc as ConfigValidationError).errors.some((e) => e.includes("name"))).toBe(true);
    }
  });

  it("a valid name passes", () => {
    expect(() => validateConfigDict({ name: "my-policy" })).not.toThrow();
  });

  it("allowed_tools as a string raises", () => {
    try {
      validateConfigDict({ allowed_tools: "search_web" });
      expect.unreachable();
    } catch (exc) {
      expect((exc as ConfigValidationError).errors.some((e) => e.includes("allowed_tools"))).toBe(
        true,
      );
    }
  });

  it("allowed_tools with non-strings raises", () => {
    try {
      validateConfigDict({ allowed_tools: [1, 2, 3] });
      expect.unreachable();
    } catch (exc) {
      expect((exc as ConfigValidationError).errors.some((e) => e.includes("allowed_tools"))).toBe(
        true,
      );
    }
  });

  it("blocked_tools as a string raises", () => {
    try {
      validateConfigDict({ blocked_tools: "exec_shell" });
      expect.unreachable();
    } catch (exc) {
      expect((exc as ConfigValidationError).errors.some((e) => e.includes("blocked_tools"))).toBe(
        true,
      );
    }
  });

  it("blocked_tools with non-strings raises", () => {
    try {
      validateConfigDict({ blocked_tools: [42] });
      expect.unreachable();
    } catch (exc) {
      expect((exc as ConfigValidationError).errors.some((e) => e.includes("blocked_tools"))).toBe(
        true,
      );
    }
  });

  it("an unknown guard field raises", () => {
    try {
      validateConfigDict({ prompt_guard: { bad_key: true } });
      expect.unreachable();
    } catch (exc) {
      expect(
        (exc as ConfigValidationError).errors.some(
          (e) => e.includes("prompt_guard") && e.includes("bad_key"),
        ),
      ).toBe(true);
    }
  });

  it("a guard block_threshold out of range raises", () => {
    try {
      validateConfigDict({ prompt_guard: { block_threshold: 2.0 } });
      expect.unreachable();
    } catch (exc) {
      expect((exc as ConfigValidationError).errors.some((e) => e.includes("prompt_guard"))).toBe(
        true,
      );
    }
  });

  it("guard warn equal to block raises", () => {
    try {
      validateConfigDict({ prompt_guard: { block_threshold: 0.5, warn_threshold: 0.5 } });
      expect.unreachable();
    } catch (exc) {
      expect((exc as ConfigValidationError).errors.some((e) => e.includes("prompt_guard"))).toBe(
        true,
      );
    }
  });

  it("a non-dict guard value raises", () => {
    try {
      validateConfigDict({ output_guard: "enabled" });
      expect.unreachable();
    } catch (exc) {
      expect((exc as ConfigValidationError).errors.some((e) => e.includes("output_guard"))).toBe(
        true,
      );
    }
  });

  it("each of the three guards is validated independently", () => {
    for (const guardKey of ["prompt_guard", "output_guard", "tool_guard"]) {
      expect(() => validateConfigDict({ [guardKey]: { block_threshold: 9.9 } })).toThrow(
        ConfigValidationError,
      );
    }
  });

  it("multiple errors are collected before raising", () => {
    try {
      validateConfigDict({
        block_threshold: 2.0,
        warn_threshold: -0.1,
        raise_on_block: "yes",
      });
      expect.unreachable();
    } catch (exc) {
      expect((exc as ConfigValidationError).errors).toHaveLength(3);
    }
  });

  it("errors is a list of strings", () => {
    try {
      validateConfigDict({ block_threshold: 2.0 });
      expect.unreachable();
    } catch (exc) {
      expect(Array.isArray((exc as ConfigValidationError).errors)).toBe(true);
      expect((exc as ConfigValidationError).errors.every((e) => typeof e === "string")).toBe(true);
    }
  });
});

describe("default policy registry", () => {
  it("get after reset returns the balanced policy", () => {
    resetDefaultPolicy();
    expect(getDefaultPolicy().name).toBe("balanced");
  });

  it("get returns a Policy instance", () => {
    resetDefaultPolicy();
    expect(getDefaultPolicy()).toBeInstanceOf(Policy);
  });

  it("set then get returns the set policy", () => {
    setDefaultPolicy(StrictPolicy());
    expect(getDefaultPolicy().name).toBe("strict");
    resetDefaultPolicy();
  });

  it("set a custom policy", () => {
    const custom = BalancedPolicy({ name: "my-custom", blockThreshold: 0.6 });
    setDefaultPolicy(custom);
    const p = getDefaultPolicy();
    expect(p.name).toBe("my-custom");
    expect(p.blockThreshold).toBe(0.6);
    resetDefaultPolicy();
  });

  it("returns the same instance on repeated calls", () => {
    resetDefaultPolicy();
    const p1 = getDefaultPolicy();
    const p2 = getDefaultPolicy();
    expect(p1).toBe(p2);
  });

  it("reset after set restores balanced", () => {
    setDefaultPolicy(StrictPolicy());
    resetDefaultPolicy();
    expect(getDefaultPolicy().name).toBe("balanced");
  });

  it("set with a non-Policy value raises a TypeError", () => {
    expect(() => setDefaultPolicy("not-a-policy" as unknown as Policy)).toThrow(TypeError);
    resetDefaultPolicy();
  });

  it("set with null raises a TypeError", () => {
    expect(() => setDefaultPolicy(null as unknown as Policy)).toThrow(TypeError);
    resetDefaultPolicy();
  });

  it("set with a plain object raises a TypeError", () => {
    expect(() => setDefaultPolicy({ name: "balanced" } as unknown as Policy)).toThrow(TypeError);
    resetDefaultPolicy();
  });

  it("multiple resets are idempotent", () => {
    resetDefaultPolicy();
    resetDefaultPolicy();
    expect(getDefaultPolicy().name).toBe("balanced");
  });
});

describe("loadConfig defaults", () => {
  it("returns a Policy instance", async () => {
    const p = await loadConfig({ useEnv: false });
    expect(p).toBeInstanceOf(Policy);
  });

  it("default name is balanced", async () => {
    const p = await loadConfig({ useEnv: false });
    expect(p.name).toBe("balanced");
  });

  it("default block threshold", async () => {
    const p = await loadConfig({ useEnv: false });
    expect(p.blockThreshold).toBe(0.75);
  });

  it("default warn threshold", async () => {
    const p = await loadConfig({ useEnv: false });
    expect(p.warnThreshold).toBe(0.4);
  });

  it("default raise_on_block", async () => {
    const p = await loadConfig({ useEnv: false });
    expect(p.raiseOnBlock).toBe(true);
  });
});

describe("loadConfig data source", () => {
  it("block_threshold overridden", async () => {
    const p = await loadConfig({
      data: { block_threshold: 0.6, warn_threshold: 0.25 },
      useEnv: false,
    });
    expect(p.blockThreshold).toBe(0.6);
  });

  it("warn_threshold overridden", async () => {
    const p = await loadConfig({
      data: { block_threshold: 0.6, warn_threshold: 0.25 },
      useEnv: false,
    });
    expect(p.warnThreshold).toBe(0.25);
  });

  it("name overridden", async () => {
    const p = await loadConfig({ data: { name: "custom" }, useEnv: false });
    expect(p.name).toBe("custom");
  });

  it("raise_on_block overridden", async () => {
    const p = await loadConfig({ data: { raise_on_block: false }, useEnv: false });
    expect(p.raiseOnBlock).toBe(false);
  });

  it("allowed_tools overridden", async () => {
    const p = await loadConfig({ data: { allowed_tools: ["search_web"] }, useEnv: false });
    expect(p.isToolAllowed("search_web")).toBe(true);
    expect(p.isToolAllowed("delete_file")).toBe(false);
  });

  it("blocked_tools overridden", async () => {
    const p = await loadConfig({ data: { blocked_tools: ["exec_shell"] }, useEnv: false });
    expect(p.isToolAllowed("exec_shell")).toBe(false);
  });

  it("nested guard enabled=false", async () => {
    const p = await loadConfig({
      data: { prompt_guard: { enabled: false } },
      useEnv: false,
    });
    expect(p.isGuardEnabled(GuardType.PROMPT)).toBe(false);
    expect(p.isGuardEnabled(GuardType.OUTPUT)).toBe(true);
  });

  it("nested guard block_threshold overridden", async () => {
    const p = await loadConfig({
      data: { output_guard: { block_threshold: 0.55, warn_threshold: 0.2 } },
      useEnv: false,
    });
    expect(p.effectiveBlockThreshold(GuardType.OUTPUT)).toBe(0.55);
    expect(p.effectiveWarnThreshold(GuardType.OUTPUT)).toBe(0.2);
  });

  it("an empty data dict uses the defaults", async () => {
    const p = await loadConfig({ data: {}, useEnv: false });
    expect(p.blockThreshold).toBe(0.75);
  });
});

describe("loadConfig base policy", () => {
  it("base policy provides the defaults", async () => {
    const p = await loadConfig({ basePolicy: StrictPolicy(), useEnv: false });
    expect(p.blockThreshold).toBe(0.4);
  });

  it("base policy name is preserved", async () => {
    const p = await loadConfig({ basePolicy: StrictPolicy(), useEnv: false });
    expect(p.name).toBe("strict");
  });

  it("data overrides the base policy", async () => {
    const p = await loadConfig({
      basePolicy: StrictPolicy(),
      data: { block_threshold: 0.8, warn_threshold: 0.3 },
      useEnv: false,
    });
    expect(p.blockThreshold).toBe(0.8);
  });

  it("non-overridden base fields are preserved", async () => {
    const p = await loadConfig({
      basePolicy: StrictPolicy(),
      data: { block_threshold: 0.8, warn_threshold: 0.3 },
      useEnv: false,
    });
    expect(p.logCleanRequests).toBe(true);
  });

  it("an undefined base policy uses balanced", async () => {
    const p = await loadConfig({ basePolicy: undefined, useEnv: false });
    expect(p.blockThreshold).toBe(0.75);
  });
});

describe("loadConfig env overrides", () => {
  it("block_threshold from env", async () => {
    process.env.LLM_SECURITY_BLOCK_THRESHOLD = "0.50";
    const p = await loadConfig({ useEnv: true, data: {} });
    expect(p.blockThreshold).toBe(0.5);
  });

  it("warn_threshold from env", async () => {
    process.env.LLM_SECURITY_WARN_THRESHOLD = "0.20";
    const p = await loadConfig({ useEnv: true, data: {} });
    expect(p.warnThreshold).toBe(0.2);
  });

  it("name from env", async () => {
    process.env.LLM_SECURITY_NAME = "env-policy";
    const p = await loadConfig({ useEnv: true, data: {} });
    expect(p.name).toBe("env-policy");
  });

  it("raise_on_block=false from env", async () => {
    process.env.LLM_SECURITY_RAISE_ON_BLOCK = "false";
    const p = await loadConfig({ useEnv: true, data: {} });
    expect(p.raiseOnBlock).toBe(false);
  });

  it("raise_on_block=true from env", async () => {
    process.env.LLM_SECURITY_RAISE_ON_BLOCK = "true";
    const p = await loadConfig({ useEnv: true, data: {} });
    expect(p.raiseOnBlock).toBe(true);
  });

  it("raise_on_block=0 from env", async () => {
    process.env.LLM_SECURITY_RAISE_ON_BLOCK = "0";
    const p = await loadConfig({ useEnv: true, data: {} });
    expect(p.raiseOnBlock).toBe(false);
  });

  it("raise_on_block=1 from env", async () => {
    process.env.LLM_SECURITY_RAISE_ON_BLOCK = "1";
    const p = await loadConfig({ useEnv: true, data: {} });
    expect(p.raiseOnBlock).toBe(true);
  });

  it("allowed_tools CSV from env", async () => {
    process.env.LLM_SECURITY_ALLOWED_TOOLS = "search_web,read_file";
    const p = await loadConfig({ useEnv: true, data: {} });
    expect(p.isToolAllowed("search_web")).toBe(true);
    expect(p.isToolAllowed("read_file")).toBe(true);
    expect(p.isToolAllowed("delete_file")).toBe(false);
  });

  it("blocked_tools CSV from env", async () => {
    process.env.LLM_SECURITY_BLOCKED_TOOLS = "exec_shell,delete_file";
    const p = await loadConfig({ useEnv: true, data: {} });
    expect(p.isToolAllowed("exec_shell")).toBe(false);
    expect(p.isToolAllowed("delete_file")).toBe(false);
    expect(p.isToolAllowed("search_web")).toBe(true);
  });

  it("prompt_guard enabled=false from env", async () => {
    process.env.LLM_SECURITY_PROMPT_GUARD_ENABLED = "false";
    const p = await loadConfig({ useEnv: true, data: {} });
    expect(p.isGuardEnabled(GuardType.PROMPT)).toBe(false);
    expect(p.isGuardEnabled(GuardType.OUTPUT)).toBe(true);
  });

  it("output_guard enabled=false from env", async () => {
    process.env.LLM_SECURITY_OUTPUT_GUARD_ENABLED = "false";
    const p = await loadConfig({ useEnv: true, data: {} });
    expect(p.isGuardEnabled(GuardType.OUTPUT)).toBe(false);
  });

  it("tool_guard enabled=false from env", async () => {
    process.env.LLM_SECURITY_TOOL_GUARD_ENABLED = "false";
    const p = await loadConfig({ useEnv: true, data: {} });
    expect(p.isGuardEnabled(GuardType.TOOL)).toBe(false);
  });

  it("redact_on_warn from env", async () => {
    process.env.LLM_SECURITY_REDACT_ON_WARN = "false";
    const p = await loadConfig({ useEnv: true, data: {} });
    expect(p.redactOnWarn).toBe(false);
  });

  it("log_clean_requests from env", async () => {
    process.env.LLM_SECURITY_LOG_CLEAN_REQUESTS = "true";
    const p = await loadConfig({ useEnv: true, data: {} });
    expect(p.logCleanRequests).toBe(true);
  });

  it("env wins over data", async () => {
    process.env.LLM_SECURITY_BLOCK_THRESHOLD = "0.50";
    const p = await loadConfig({
      data: { block_threshold: 0.8, warn_threshold: 0.3 },
      useEnv: true,
    });
    expect(p.blockThreshold).toBe(0.5);
  });

  it("useEnv=false ignores env vars", async () => {
    process.env.LLM_SECURITY_BLOCK_THRESHOLD = "0.30";
    const p = await loadConfig({ useEnv: false, data: {} });
    expect(p.blockThreshold).toBe(0.75);
  });

  it("unset env vars are not applied", async () => {
    delete process.env.LLM_SECURITY_BLOCK_THRESHOLD;
    const p = await loadConfig({ useEnv: true, data: {} });
    expect(p.blockThreshold).toBe(0.75);
  });

  it("allowed_tools with spaces from env", async () => {
    process.env.LLM_SECURITY_ALLOWED_TOOLS = "search_web , read_file";
    const p = await loadConfig({ useEnv: true, data: {} });
    expect(p.isToolAllowed("search_web")).toBe(true);
    expect(p.isToolAllowed("read_file")).toBe(true);
  });
});

describe("loadConfig validation", () => {
  it("invalid data raises ConfigValidationError", async () => {
    await expect(
      loadConfig({ data: { block_threshold: 2.0 }, useEnv: false }),
    ).rejects.toBeInstanceOf(ConfigValidationError);
  });

  it("the validation error reports the field", async () => {
    try {
      await loadConfig({ data: { block_threshold: 2.0 }, useEnv: false });
      expect.unreachable();
    } catch (exc) {
      expect(
        (exc as ConfigValidationError).errors.some((e) => e.includes("block_threshold")),
      ).toBe(true);
    }
  });

  it("validate=false skips validation", async () => {
    const p = await loadConfig({
      data: { block_threshold: 0.75, warn_threshold: 0.4 },
      validate: false,
      useEnv: false,
    });
    expect(p.blockThreshold).toBe(0.75);
  });

  it("multiple errors in data are all reported", async () => {
    try {
      await loadConfig({
        data: { block_threshold: 2.0, warn_threshold: -0.5, raise_on_block: "yes" },
        useEnv: false,
      });
      expect.unreachable();
    } catch (exc) {
      expect((exc as ConfigValidationError).errors).toHaveLength(3);
    }
  });
});

describe("loadConfig yaml_path", () => {
  let tmpDir: string;

  function writeYaml(contents: string): string {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "quisium-config-"));
    const file = path.join(tmpDir, "policy.yaml");
    fs.writeFileSync(file, contents, "utf-8");
    return file;
  }

  it("a missing file raises ConfigSourceError", async () => {
    await expect(
      loadConfig({ yamlPath: "/nonexistent/path/policy.yaml", useEnv: false }),
    ).rejects.toBeInstanceOf(ConfigSourceError);
  });

  it("the missing-file error contains the path", async () => {
    const p = "/nonexistent/does_not_exist.yaml";
    try {
      await loadConfig({ yamlPath: p, useEnv: false });
      expect.unreachable();
    } catch (exc) {
      expect((exc as Error).message).toContain("does_not_exist.yaml");
    }
  });

  it("loads a valid YAML file", async () => {
    const file = writeYaml("name: yaml-policy\nblock_threshold: 0.65\nwarn_threshold: 0.30\n");
    const p = await loadConfig({ yamlPath: file, useEnv: false });
    expect(p.name).toBe("yaml-policy");
    expect(p.blockThreshold).toBe(0.65);
  });

  it("YAML is overridden by data", async () => {
    const file = writeYaml("block_threshold: 0.65\nwarn_threshold: 0.30\n");
    const p = await loadConfig({
      yamlPath: file,
      data: { block_threshold: 0.9, warn_threshold: 0.4 },
      useEnv: false,
    });
    expect(p.blockThreshold).toBe(0.9);
  });

  it("YAML is overridden by env", async () => {
    process.env.LLM_SECURITY_BLOCK_THRESHOLD = "0.50";
    const file = writeYaml("block_threshold: 0.65\nwarn_threshold: 0.30\n");
    const p = await loadConfig({ yamlPath: file, useEnv: true });
    expect(p.blockThreshold).toBe(0.5);
  });
});

describe("loadConfig priority", () => {
  it("data overrides the base policy", async () => {
    const p = await loadConfig({
      basePolicy: StrictPolicy(),
      data: { block_threshold: 0.8, warn_threshold: 0.3 },
      useEnv: false,
    });
    expect(p.blockThreshold).toBe(0.8);
  });

  it("env overrides data", async () => {
    process.env.LLM_SECURITY_BLOCK_THRESHOLD = "0.50";
    const p = await loadConfig({
      data: { block_threshold: 0.8, warn_threshold: 0.3 },
      useEnv: true,
    });
    expect(p.blockThreshold).toBe(0.5);
  });

  it("env overrides the base policy", async () => {
    process.env.LLM_SECURITY_BLOCK_THRESHOLD = "0.50";
    const p = await loadConfig({ basePolicy: StrictPolicy(), useEnv: true });
    expect(p.blockThreshold).toBe(0.5);
  });

  it("base policy provides a fallback when there is no other source", async () => {
    const p = await loadConfig({ basePolicy: StrictPolicy(), useEnv: false });
    expect(p.blockThreshold).toBe(0.4);
  });

  it("non-overridden base fields are preserved through a data override", async () => {
    const p = await loadConfig({
      basePolicy: StrictPolicy(),
      data: { block_threshold: 0.8, warn_threshold: 0.3 },
      useEnv: false,
    });
    expect(p.logCleanRequests).toBe(true);
  });
});
