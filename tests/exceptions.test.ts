import { describe, it, expect } from "vitest";
import {
  BlockedByPolicyError,
  GuardError,
  InvalidToolCallError,
  LLMSecurityError,
  OutputBlockedError,
  PolicyNotFoundError,
  PromptBlockedError,
  ProviderError,
  ProviderTimeoutError,
} from "../src/exceptions.js";
import { GuardDecision, GuardType, ScanResult } from "../src/types.js";

describe("LLMSecurityError", () => {
  it("is an Error", () => {
    expect(new LLMSecurityError("x")).toBeInstanceOf(Error);
  });

  it("message stored", () => {
    const exc = new LLMSecurityError("test message");
    expect(exc.message).toBe("test message");
  });

  it("message property equals message", () => {
    const exc = new LLMSecurityError("test message");
    expect(exc.message).toBe("test message");
  });

  it("context defaults to empty object", () => {
    const exc = new LLMSecurityError("x");
    expect(exc.context).toEqual({});
  });

  it("context stored", () => {
    const exc = new LLMSecurityError("x", { req_id: "abc", env: "prod" });
    expect(exc.context).toEqual({ req_id: "abc", env: "prod" });
  });

  it("context not shared between instances", () => {
    const exc1 = new LLMSecurityError("a");
    const exc2 = new LLMSecurityError("b");
    exc1.context.key = "val";
    expect(exc2.context.key).toBeUndefined();
  });

  it("toString contains class name", () => {
    const exc = new LLMSecurityError("test message");
    expect(exc.toString()).toContain("LLMSecurityError");
  });

  it("toString contains message", () => {
    const exc = new LLMSecurityError("test message");
    expect(exc.toString()).toContain("test message");
  });

  it("empty message allowed", () => {
    const exc = new LLMSecurityError("");
    expect(exc.message).toBe("");
  });
});

describe("BlockedByPolicyError", () => {
  it("is an LLMSecurityError", () => {
    expect(new BlockedByPolicyError({ reasons: ["x"] })).toBeInstanceOf(LLMSecurityError);
  });

  it("reasons stored", () => {
    const exc = new BlockedByPolicyError({ reasons: ["injection", "jailbreak"] });
    expect(exc.reasons).toEqual(["injection", "jailbreak"]);
  });

  it("score stored", () => {
    const exc = new BlockedByPolicyError({ reasons: ["x"], score: 0.92 });
    expect(exc.score).toBe(0.92);
  });

  it("score default is one", () => {
    const exc = new BlockedByPolicyError({ reasons: ["x"] });
    expect(exc.score).toBe(1.0);
  });

  it("policyName stored", () => {
    const exc = new BlockedByPolicyError({ reasons: ["x"], policyName: "strict" });
    expect(exc.policyName).toBe("strict");
  });

  it("policyName default is unknown", () => {
    const exc = new BlockedByPolicyError({ reasons: ["x"] });
    expect(exc.policyName).toBe("unknown");
  });

  it("decision default is null", () => {
    const exc = new BlockedByPolicyError({ reasons: ["x"] });
    expect(exc.decision).toBeNull();
  });

  it("decision stored", () => {
    const decision = GuardDecision.blocked(["x"], 0.9);
    const exc = new BlockedByPolicyError({ reasons: ["x"], decision });
    expect(exc.decision).toBe(decision);
  });

  it("context stored", () => {
    const exc = new BlockedByPolicyError({ reasons: ["x"], context: { req_id: "abc" } });
    expect(exc.context).toEqual({ req_id: "abc" });
  });

  it("message contains policy name", () => {
    const exc = new BlockedByPolicyError({ reasons: ["x"], policyName: "balanced" });
    expect(exc.message).toContain("balanced");
  });

  it("message contains score", () => {
    const exc = new BlockedByPolicyError({ reasons: ["x"], score: 0.92 });
    expect(exc.message).toContain("0.920");
  });

  it("message contains single reason", () => {
    const exc = new BlockedByPolicyError({ reasons: ["injection detected"] });
    expect(exc.message).toContain("injection detected");
  });

  it("message joins multiple reasons with semicolons", () => {
    const exc = new BlockedByPolicyError({ reasons: ["reason A", "reason B"], score: 0.9 });
    expect(exc.message).toContain("reason A; reason B");
  });

  it("empty reasons message has no details", () => {
    const exc = new BlockedByPolicyError({ reasons: [] });
    expect(exc.message).toContain("no details");
  });

  it("toDict keys", () => {
    const exc = new BlockedByPolicyError({ reasons: ["x"], score: 0.92, policyName: "bal" });
    expect(new Set(Object.keys(exc.toDict()))).toEqual(new Set(["error", "reasons", "score", "policy_name"]));
  });

  it("toDict error name", () => {
    const exc = new BlockedByPolicyError({ reasons: ["x"] });
    expect(exc.toDict().error).toBe("BlockedByPolicyError");
  });

  it("toDict reasons", () => {
    const exc = new BlockedByPolicyError({ reasons: ["r1", "r2"] });
    expect(exc.toDict().reasons).toEqual(["r1", "r2"]);
  });

  it("toDict score", () => {
    const exc = new BlockedByPolicyError({ reasons: ["x"], score: 0.85 });
    expect(exc.toDict().score).toBe(0.85);
  });

  it("toDict score rounded to 4 decimal places", () => {
    const exc = new BlockedByPolicyError({ reasons: ["x"], score: 0.921234 });
    expect(exc.toDict().score).toBe(0.9212);
  });

  it("toDict policy_name", () => {
    const exc = new BlockedByPolicyError({ reasons: ["x"], policyName: "strict" });
    expect(exc.toDict().policy_name).toBe("strict");
  });
});

describe("PromptBlockedError", () => {
  it("is a BlockedByPolicyError", () => {
    expect(new PromptBlockedError({ reasons: ["x"] })).toBeInstanceOf(BlockedByPolicyError);
  });

  it("is an LLMSecurityError", () => {
    expect(new PromptBlockedError({ reasons: ["x"] })).toBeInstanceOf(LLMSecurityError);
  });

  it("promptSnippet stored", () => {
    const exc = new PromptBlockedError({ reasons: ["x"], promptSnippet: "Ignore all previous" });
    expect(exc.promptSnippet).toBe("Ignore all previous");
  });

  it("promptSnippet default is empty string", () => {
    const exc = new PromptBlockedError({ reasons: ["x"] });
    expect(exc.promptSnippet).toBe("");
  });

  it("promptSnippet truncated to 120 chars", () => {
    const longSnippet = "A".repeat(200);
    const exc = new PromptBlockedError({ reasons: ["x"], promptSnippet: longSnippet });
    expect(exc.promptSnippet.length).toBe(120);
  });

  it("promptSnippet exact 120 chars not truncated", () => {
    const snippet = "B".repeat(120);
    const exc = new PromptBlockedError({ reasons: ["x"], promptSnippet: snippet });
    expect(exc.promptSnippet.length).toBe(120);
    expect(exc.promptSnippet).toBe(snippet);
  });

  it("promptSnippet short not truncated", () => {
    const exc = new PromptBlockedError({ reasons: ["x"], promptSnippet: "short text" });
    expect(exc.promptSnippet).toBe("short text");
  });

  it("promptSnippet truncated content is prefix", () => {
    const longSnippet = "X".repeat(50) + "Y".repeat(150);
    const exc = new PromptBlockedError({ reasons: ["x"], promptSnippet: longSnippet });
    expect(exc.promptSnippet).toBe("X".repeat(50) + "Y".repeat(70));
  });

  it("score inherited", () => {
    const exc = new PromptBlockedError({ reasons: ["x"], score: 0.92 });
    expect(exc.score).toBe(0.92);
  });

  it("reasons inherited", () => {
    const exc = new PromptBlockedError({ reasons: ["r1", "r2"] });
    expect(exc.reasons).toEqual(["r1", "r2"]);
  });

  it("policyName inherited", () => {
    const exc = new PromptBlockedError({ reasons: ["x"], policyName: "strict" });
    expect(exc.policyName).toBe("strict");
  });

  it("decision inherited", () => {
    const decision = GuardDecision.blocked(["x"]);
    const exc = new PromptBlockedError({ reasons: ["x"], decision });
    expect(exc.decision).toBe(decision);
  });

  it("toDict has prompt_snippet key", () => {
    const exc = new PromptBlockedError({ reasons: ["x"] });
    expect(exc.toDict()).toHaveProperty("prompt_snippet");
  });

  it("toDict error name", () => {
    const exc = new PromptBlockedError({ reasons: ["x"] });
    expect(exc.toDict().error).toBe("PromptBlockedError");
  });

  it("toDict snippet value", () => {
    const exc = new PromptBlockedError({ reasons: ["x"], promptSnippet: "bad prompt" });
    expect(exc.toDict().prompt_snippet).toBe("bad prompt");
  });

  it("toDict includes inherited fields", () => {
    const exc = new PromptBlockedError({ reasons: ["r"], score: 0.9, policyName: "bal" });
    const d = exc.toDict();
    expect(d.reasons).toEqual(["r"]);
    expect(d.score).toBe(0.9);
    expect(d.policy_name).toBe("bal");
  });
});

describe("OutputBlockedError", () => {
  it("is a BlockedByPolicyError", () => {
    expect(new OutputBlockedError({ reasons: ["x"] })).toBeInstanceOf(BlockedByPolicyError);
  });

  it("is an LLMSecurityError", () => {
    expect(new OutputBlockedError({ reasons: ["x"] })).toBeInstanceOf(LLMSecurityError);
  });

  it("outputSnippet stored", () => {
    const exc = new OutputBlockedError({ reasons: ["x"], outputSnippet: "sk-abc123..." });
    expect(exc.outputSnippet).toBe("sk-abc123...");
  });

  it("outputSnippet default is empty string", () => {
    const exc = new OutputBlockedError({ reasons: ["x"] });
    expect(exc.outputSnippet).toBe("");
  });

  it("outputSnippet truncated to 120 chars", () => {
    const exc = new OutputBlockedError({ reasons: ["x"], outputSnippet: "C".repeat(200) });
    expect(exc.outputSnippet.length).toBe(120);
  });

  it("outputSnippet exact 120 chars unchanged", () => {
    const snippet = "D".repeat(120);
    const exc = new OutputBlockedError({ reasons: ["x"], outputSnippet: snippet });
    expect(exc.outputSnippet).toBe(snippet);
  });

  it("outputSnippet truncated content is prefix", () => {
    const exc = new OutputBlockedError({ reasons: ["x"], outputSnippet: "X".repeat(50) + "Y".repeat(150) });
    expect(exc.outputSnippet).toBe("X".repeat(50) + "Y".repeat(70));
  });

  it("score inherited", () => {
    const exc = new OutputBlockedError({ reasons: ["x"], score: 0.95 });
    expect(exc.score).toBe(0.95);
  });

  it("policyName inherited", () => {
    const exc = new OutputBlockedError({ reasons: ["x"], policyName: "balanced" });
    expect(exc.policyName).toBe("balanced");
  });

  it("toDict has output_snippet key", () => {
    const exc = new OutputBlockedError({ reasons: ["x"] });
    expect(exc.toDict()).toHaveProperty("output_snippet");
  });

  it("toDict error name", () => {
    const exc = new OutputBlockedError({ reasons: ["x"] });
    expect(exc.toDict().error).toBe("OutputBlockedError");
  });

  it("toDict snippet value", () => {
    const exc = new OutputBlockedError({ reasons: ["x"], outputSnippet: "sk-secret" });
    expect(exc.toDict().output_snippet).toBe("sk-secret");
  });

  it("toDict includes inherited fields", () => {
    const exc = new OutputBlockedError({ reasons: ["r"], score: 0.95, policyName: "bal" });
    const d = exc.toDict();
    expect(d.reasons).toEqual(["r"]);
    expect(d.score).toBe(0.95);
    expect(d.policy_name).toBe("bal");
  });

  it("not instance of PromptBlockedError", () => {
    const exc = new OutputBlockedError({ reasons: ["x"] });
    expect(exc).not.toBeInstanceOf(PromptBlockedError);
  });

  it("PromptBlockedError not instance of OutputBlockedError", () => {
    const exc = new PromptBlockedError({ reasons: ["x"] });
    expect(exc).not.toBeInstanceOf(OutputBlockedError);
  });
});

describe("InvalidToolCallError", () => {
  it("is an LLMSecurityError", () => {
    expect(new InvalidToolCallError({ toolName: "x", reason: "y" })).toBeInstanceOf(LLMSecurityError);
  });

  it("is not a BlockedByPolicyError", () => {
    expect(new InvalidToolCallError({ toolName: "x", reason: "y" })).not.toBeInstanceOf(BlockedByPolicyError);
  });

  it("toolName stored", () => {
    const exc = new InvalidToolCallError({ toolName: "delete_file", reason: "dangerous" });
    expect(exc.toolName).toBe("delete_file");
  });

  it("reason stored", () => {
    const exc = new InvalidToolCallError({ toolName: "x", reason: "schema violation" });
    expect(exc.reason).toBe("schema violation");
  });

  it("callId default is null", () => {
    const exc = new InvalidToolCallError({ toolName: "x", reason: "y" });
    expect(exc.callId).toBeNull();
  });

  it("callId stored", () => {
    const exc = new InvalidToolCallError({ toolName: "x", reason: "y", callId: "call_abc" });
    expect(exc.callId).toBe("call_abc");
  });

  it("scanResult default is null", () => {
    const exc = new InvalidToolCallError({ toolName: "x", reason: "y" });
    expect(exc.scanResult).toBeNull();
  });

  it("scanResult stored", () => {
    const sr = new ScanResult({ allowed: false, score: 0.88, guardType: GuardType.TOOL });
    const exc = new InvalidToolCallError({ toolName: "x", reason: "y", scanResult: sr });
    expect(exc.scanResult).toBe(sr);
  });

  it("context stored", () => {
    const exc = new InvalidToolCallError({ toolName: "x", reason: "y", context: { extra: "data" } });
    expect(exc.context).toEqual({ extra: "data" });
  });

  it("message contains tool name", () => {
    const exc = new InvalidToolCallError({ toolName: "exec_shell", reason: "too dangerous" });
    expect(exc.message).toContain("exec_shell");
  });

  it("message contains reason", () => {
    const exc = new InvalidToolCallError({ toolName: "x", reason: "dangerous operation" });
    expect(exc.message).toContain("dangerous operation");
  });

  it("message contains call_id when set", () => {
    const exc = new InvalidToolCallError({ toolName: "x", reason: "y", callId: "call_123" });
    expect(exc.message).toContain("call_123");
  });

  it("message without call_id has no bracket", () => {
    const exc = new InvalidToolCallError({ toolName: "x", reason: "y" });
    // No call_id part in message
    expect(exc.message).not.toContain("call_id");
  });

  it("toDict keys", () => {
    const exc = new InvalidToolCallError({ toolName: "bad_tool", reason: "bad args", callId: "c1" });
    expect(new Set(Object.keys(exc.toDict()))).toEqual(new Set(["error", "tool_name", "reason", "call_id"]));
  });

  it("toDict error name", () => {
    const exc = new InvalidToolCallError({ toolName: "x", reason: "y" });
    expect(exc.toDict().error).toBe("InvalidToolCallError");
  });

  it("toDict tool_name", () => {
    const exc = new InvalidToolCallError({ toolName: "delete_file", reason: "reason" });
    expect(exc.toDict().tool_name).toBe("delete_file");
  });

  it("toDict reason", () => {
    const exc = new InvalidToolCallError({ toolName: "x", reason: "dangerous path traversal" });
    expect(exc.toDict().reason).toBe("dangerous path traversal");
  });

  it("toDict call_id none when not set", () => {
    const exc = new InvalidToolCallError({ toolName: "x", reason: "y" });
    expect(exc.toDict().call_id).toBeNull();
  });

  it("toDict call_id value", () => {
    const exc = new InvalidToolCallError({ toolName: "x", reason: "y", callId: "call_xyz" });
    expect(exc.toDict().call_id).toBe("call_xyz");
  });
});

describe("PolicyNotFoundError", () => {
  it("is an LLMSecurityError", () => {
    expect(new PolicyNotFoundError({ policyName: "x" })).toBeInstanceOf(LLMSecurityError);
  });

  it("policyName stored", () => {
    const exc = new PolicyNotFoundError({ policyName: "healthcare-strict" });
    expect(exc.policyName).toBe("healthcare-strict");
  });

  it("available default is empty list", () => {
    const exc = new PolicyNotFoundError({ policyName: "x" });
    expect(exc.available).toEqual([]);
  });

  it("available stored", () => {
    const exc = new PolicyNotFoundError({ policyName: "x", available: ["strict", "balanced"] });
    expect(exc.available).toEqual(["strict", "balanced"]);
  });

  it("message with no available has 'No policies' phrase", () => {
    const exc = new PolicyNotFoundError({ policyName: "x" });
    expect(exc.message).toContain("No policies");
  });

  it("message with no available contains policy name", () => {
    const exc = new PolicyNotFoundError({ policyName: "missing-policy" });
    expect(exc.message).toContain("missing-policy");
  });

  it("message with available contains policy name", () => {
    const exc = new PolicyNotFoundError({ policyName: "my-policy", available: ["strict"] });
    expect(exc.message).toContain("my-policy");
  });

  it("message with available lists available policies", () => {
    const exc = new PolicyNotFoundError({ policyName: "x", available: ["strict", "balanced"] });
    expect(exc.message).toContain("strict");
    expect(exc.message).toContain("balanced");
  });

  it("'No policies' phrase absent when available present", () => {
    const exc = new PolicyNotFoundError({ policyName: "x", available: ["strict"] });
    expect(exc.message).not.toContain("No policies");
  });

  it("not a BlockedByPolicyError", () => {
    expect(new PolicyNotFoundError({ policyName: "x" })).not.toBeInstanceOf(BlockedByPolicyError);
  });
});

describe("ProviderError", () => {
  it("is an LLMSecurityError", () => {
    expect(new ProviderError({ message: "x" })).toBeInstanceOf(LLMSecurityError);
  });

  it("providerName stored", () => {
    const exc = new ProviderError({ message: "API failed", providerName: "openai" });
    expect(exc.providerName).toBe("openai");
  });

  it("providerName default is unknown", () => {
    const exc = new ProviderError({ message: "failed" });
    expect(exc.providerName).toBe("unknown");
  });

  it("statusCode default is null", () => {
    const exc = new ProviderError({ message: "x", providerName: "openai" });
    expect(exc.statusCode).toBeNull();
  });

  it("statusCode stored", () => {
    const exc = new ProviderError({ message: "rate limited", providerName: "openai", statusCode: 429 });
    expect(exc.statusCode).toBe(429);
  });

  it("originalError default is undefined", () => {
    const exc = new ProviderError({ message: "x", providerName: "openai" });
    expect(exc.originalError).toBeUndefined();
  });

  it("originalError stored", () => {
    const original = new Error("network error");
    const exc = new ProviderError({ message: "wrapped", providerName: "x", originalError: original });
    expect(exc.originalError).toBe(original);
  });

  it("context stored", () => {
    const exc = new ProviderError({ message: "x", context: { attempt: 3 } });
    expect(exc.context).toEqual({ attempt: 3 });
  });

  it("message contains provider name", () => {
    const exc = new ProviderError({ message: "rate limited", providerName: "openai" });
    expect(exc.message).toContain("openai");
  });

  it("message contains status code when set", () => {
    const exc = new ProviderError({ message: "rate limited", providerName: "openai", statusCode: 429 });
    expect(exc.message).toContain("429");
  });

  it("message without status code has no HTTP noise", () => {
    const exc = new ProviderError({ message: "API failed", providerName: "anthropic" });
    expect(exc.message).not.toContain("HTTP");
  });

  it("toDict keys", () => {
    const exc = new ProviderError({ message: "error", providerName: "openai", statusCode: 500 });
    expect(new Set(Object.keys(exc.toDict()))).toEqual(
      new Set(["error", "provider_name", "status_code", "message"]),
    );
  });

  it("toDict error name", () => {
    const exc = new ProviderError({ message: "x", providerName: "openai" });
    expect(exc.toDict().error).toBe("ProviderError");
  });

  it("toDict provider_name", () => {
    const exc = new ProviderError({ message: "x", providerName: "anthropic" });
    expect(exc.toDict().provider_name).toBe("anthropic");
  });

  it("toDict status_code", () => {
    const exc = new ProviderError({ message: "x", providerName: "x", statusCode: 500 });
    expect(exc.toDict().status_code).toBe(500);
  });

  it("toDict status_code null when not set", () => {
    const exc = new ProviderError({ message: "x", providerName: "x" });
    expect(exc.toDict().status_code).toBeNull();
  });

  it("toDict message field", () => {
    const exc = new ProviderError({ message: "call failed", providerName: "openai" });
    expect(exc.toDict().message).toBeTruthy();
  });
});

describe("ProviderTimeoutError", () => {
  it("is a ProviderError", () => {
    expect(new ProviderTimeoutError()).toBeInstanceOf(ProviderError);
  });

  it("is an LLMSecurityError", () => {
    expect(new ProviderTimeoutError()).toBeInstanceOf(LLMSecurityError);
  });

  it("statusCode is 408", () => {
    expect(new ProviderTimeoutError().statusCode).toBe(408);
  });

  it.each(["openai", "anthropic", "ollama"])("statusCode is 408 regardless of provider: %s", (provider) => {
    expect(new ProviderTimeoutError({ providerName: provider }).statusCode).toBe(408);
  });

  it("timeoutSeconds default is null", () => {
    expect(new ProviderTimeoutError().timeoutSeconds).toBeNull();
  });

  it("timeoutSeconds stored", () => {
    const exc = new ProviderTimeoutError({ timeoutSeconds: 30.0 });
    expect(exc.timeoutSeconds).toBe(30.0);
  });

  it("timeoutSeconds integer stored", () => {
    const exc = new ProviderTimeoutError({ timeoutSeconds: 60 });
    expect(exc.timeoutSeconds).toBe(60);
  });

  it("providerName stored", () => {
    const exc = new ProviderTimeoutError({ providerName: "openai" });
    expect(exc.providerName).toBe("openai");
  });

  it("providerName default is unknown", () => {
    expect(new ProviderTimeoutError().providerName).toBe("unknown");
  });

  it("originalError stored", () => {
    const original = new Error("timed out");
    const exc = new ProviderTimeoutError({ originalError: original });
    expect(exc.originalError).toBe(original);
  });

  it("originalError default is undefined", () => {
    expect(new ProviderTimeoutError().originalError).toBeUndefined();
  });

  it("message contains timeoutSeconds when set", () => {
    const exc = new ProviderTimeoutError({ providerName: "openai", timeoutSeconds: 5.0 });
    expect(exc.message).toContain("5");
  });

  it("message contains provider name", () => {
    const exc = new ProviderTimeoutError({ providerName: "openai" });
    expect(exc.message).toContain("openai");
  });

  it("message without timeout does not crash", () => {
    // Must not raise even when timeoutSeconds is null
    const exc = new ProviderTimeoutError({ providerName: "openai" });
    expect(exc.message.length).toBeGreaterThan(0);
  });
});

describe("GuardError", () => {
  it("is an LLMSecurityError", () => {
    expect(new GuardError({ guardName: "x", message: "y" })).toBeInstanceOf(LLMSecurityError);
  });

  it("is not a BlockedByPolicyError", () => {
    expect(new GuardError({ guardName: "x", message: "y" })).not.toBeInstanceOf(BlockedByPolicyError);
  });

  it("guardName stored", () => {
    const exc = new GuardError({ guardName: "prompt_guard", message: "regex exploded" });
    expect(exc.guardName).toBe("prompt_guard");
  });

  it("originalError default is undefined", () => {
    const exc = new GuardError({ guardName: "x", message: "y" });
    expect(exc.originalError).toBeUndefined();
  });

  it("originalError stored", () => {
    const original = new Error("boom");
    const exc = new GuardError({ guardName: "x", message: "y", originalError: original });
    expect(exc.originalError).toBe(original);
  });

  it("context default is empty", () => {
    const exc = new GuardError({ guardName: "x", message: "y" });
    expect(exc.context).toEqual({});
  });

  it("context stored", () => {
    const exc = new GuardError({ guardName: "x", message: "y", context: { detail: "z" } });
    expect(exc.context).toEqual({ detail: "z" });
  });

  it("message contains guard name", () => {
    const exc = new GuardError({ guardName: "prompt_guard", message: "crashed" });
    expect(exc.message).toContain("prompt_guard");
  });

  it("message contains message text", () => {
    const exc = new GuardError({ guardName: "x", message: "regex exploded" });
    expect(exc.message).toContain("regex exploded");
  });

  it.each(["prompt_guard", "output_guard", "tool_guard", "custom"])(
    "all guard names accepted: %s",
    (name) => {
      const exc = new GuardError({ guardName: name, message: "fault" });
      expect(exc.message).toContain(name);
    },
  );
});

describe("Inheritance hierarchy", () => {
  const cases: Array<[string, () => LLMSecurityError]> = [
    ["BlockedByPolicyError", () => new BlockedByPolicyError({ reasons: ["x"] })],
    ["PromptBlockedError", () => new PromptBlockedError({ reasons: ["x"] })],
    ["OutputBlockedError", () => new OutputBlockedError({ reasons: ["x"] })],
    ["InvalidToolCallError", () => new InvalidToolCallError({ toolName: "x", reason: "y" })],
    ["PolicyNotFoundError", () => new PolicyNotFoundError({ policyName: "x" })],
    ["ProviderError", () => new ProviderError({ message: "x", providerName: "openai" })],
    ["ProviderTimeoutError", () => new ProviderTimeoutError({ providerName: "openai" })],
    ["GuardError", () => new GuardError({ guardName: "x", message: "y" })],
  ];

  it.each(cases)("%s is catchable as LLMSecurityError", (_name, factory) => {
    const exc = factory();
    let caught = false;
    try {
      throw exc;
    } catch (e) {
      if (e instanceof LLMSecurityError) caught = true;
    }
    expect(caught).toBe(true);
  });

  it("BlockedByPolicyError is not an InvalidToolCallError", () => {
    expect(new BlockedByPolicyError({ reasons: ["x"] })).not.toBeInstanceOf(InvalidToolCallError);
  });

  it("ProviderError is not a BlockedByPolicyError", () => {
    expect(new ProviderError({ message: "x" })).not.toBeInstanceOf(BlockedByPolicyError);
  });

  it("GuardError is not a ProviderError", () => {
    expect(new GuardError({ guardName: "x", message: "y" })).not.toBeInstanceOf(ProviderError);
  });

  it("PolicyNotFoundError is not a BlockedByPolicyError", () => {
    expect(new PolicyNotFoundError({ policyName: "x" })).not.toBeInstanceOf(BlockedByPolicyError);
  });
});

describe("Catchable as parent", () => {
  it("PromptBlockedError catchable as BlockedByPolicyError", () => {
    let caught = false;
    try {
      throw new PromptBlockedError({ reasons: ["injection"] });
    } catch (e) {
      if (e instanceof BlockedByPolicyError) caught = true;
    }
    expect(caught).toBe(true);
  });

  it("OutputBlockedError catchable as BlockedByPolicyError", () => {
    let caught = false;
    try {
      throw new OutputBlockedError({ reasons: ["credential"] });
    } catch (e) {
      if (e instanceof BlockedByPolicyError) caught = true;
    }
    expect(caught).toBe(true);
  });

  it("ProviderTimeoutError catchable as ProviderError", () => {
    let caught = false;
    try {
      throw new ProviderTimeoutError({ providerName: "openai" });
    } catch (e) {
      if (e instanceof ProviderError) caught = true;
    }
    expect(caught).toBe(true);
  });

  it("PromptBlockedError not caught as OutputBlockedError", () => {
    let caughtAsOutput = false;
    try {
      throw new PromptBlockedError({ reasons: ["x"] });
    } catch (e) {
      if (e instanceof OutputBlockedError) {
        caughtAsOutput = true;
      } else if (e instanceof BlockedByPolicyError) {
        // expected
      } else {
        throw e;
      }
    }
    expect(caughtAsOutput).toBe(false);
  });

  it("OutputBlockedError not caught as PromptBlockedError", () => {
    let caughtAsPrompt = false;
    try {
      throw new OutputBlockedError({ reasons: ["x"] });
    } catch (e) {
      if (e instanceof PromptBlockedError) {
        caughtAsPrompt = true;
      } else if (e instanceof BlockedByPolicyError) {
        // expected
      } else {
        throw e;
      }
    }
    expect(caughtAsPrompt).toBe(false);
  });

  it("broad catch order: prompt then blocked", () => {
    let caughtBy: string;
    try {
      throw new PromptBlockedError({ reasons: ["injection"] });
    } catch (e) {
      if (e instanceof PromptBlockedError) {
        caughtBy = "prompt";
      } else if (e instanceof BlockedByPolicyError) {
        caughtBy = "blocked";
      } else {
        throw e;
      }
    }
    expect(caughtBy).toBe("prompt");
  });

  it("broad catch order: output then blocked", () => {
    let caughtBy: string;
    try {
      throw new OutputBlockedError({ reasons: ["credential"] });
    } catch (e) {
      if (e instanceof OutputBlockedError) {
        caughtBy = "output";
      } else if (e instanceof BlockedByPolicyError) {
        caughtBy = "blocked";
      } else {
        throw e;
      }
    }
    expect(caughtBy).toBe("output");
  });

  it("broad catch order: timeout then provider", () => {
    let caughtBy: string;
    try {
      throw new ProviderTimeoutError({ providerName: "openai" });
    } catch (e) {
      if (e instanceof ProviderTimeoutError) {
        caughtBy = "timeout";
      } else if (e instanceof ProviderError) {
        caughtBy = "provider";
      } else {
        throw e;
      }
    }
    expect(caughtBy).toBe("timeout");
  });
});
