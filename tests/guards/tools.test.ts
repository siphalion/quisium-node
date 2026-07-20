import { describe, it, expect } from "vitest";
import { validateToolCall, validateToolCalls, aggregateToolScans } from "../../src/guards/tools.js";
import { GuardType, ToolCall } from "../../src/types.js";
import { BalancedPolicy, GuardConfig } from "../../src/policies.js";
import { balancedPolicy, strictPolicy, loggingOnlyPolicy } from "../helpers.js";

function tc(name: string, args: Record<string, unknown>, schema?: Record<string, unknown>, callId?: string): ToolCall {
  return new ToolCall({ name, args, schema: schema ?? {}, callId: callId ?? null });
}

function disabledPolicy() {
  return BalancedPolicy({
    toolGuard: new GuardConfig({ enabled: false }),
    raiseOnBlock: false,
  });
}

const FULL_SCHEMA = {
  type: "object",
  properties: {
    username: { type: "string" },
    age: { type: "integer" },
    limit: { type: "integer", minimum: 1, maximum: 100 },
  },
  required: ["username", "age"],
};

describe("validateToolCall - safe", () => {
  it("web search is safe", () => {
    const r = validateToolCall(tc("search_web", { query: "python tutorial" }), balancedPolicy());
    expect(r.allowed).toBe(true);
    expect(r.score).toBe(0.0);
  });

  it("get weather is safe", () => {
    const r = validateToolCall(tc("get_weather", { city: "London", units: "metric" }), balancedPolicy());
    expect(r.allowed).toBe(true);
    expect(r.score).toBe(0.0);
  });

  it("read file safe path is safe", () => {
    const r = validateToolCall(tc("read_file", { path: "documents/report.pdf" }), balancedPolicy());
    expect(r.allowed).toBe(true);
    expect(r.score).toBe(0.0);
  });

  it("send email is safe", () => {
    const r = validateToolCall(tc("send_email", { to: "user@example.com", subject: "Hello" }), balancedPolicy());
    expect(r.allowed).toBe(true);
  });

  it("safe call has empty reasons", () => {
    const r = validateToolCall(tc("search_web", { query: "hello" }), balancedPolicy());
    expect(r.reasons).toEqual([]);
  });

  it("safe call has empty categories", () => {
    const r = validateToolCall(tc("search_web", { query: "hello" }), balancedPolicy());
    expect(r.metadata.categories).toEqual([]);
  });

  it("safe call returns ScanResult", () => {
    const r = validateToolCall(tc("search_web", { query: "hello" }), balancedPolicy());
    expect(r.guardType).toBeDefined();
  });

  it("guard type is tool", () => {
    const r = validateToolCall(tc("search_web", { query: "hello" }), balancedPolicy());
    expect(r.guardType).toBe(GuardType.TOOL);
  });

  it("empty args is safe", () => {
    const r = validateToolCall(tc("ping", {}), balancedPolicy());
    expect(r.allowed).toBe(true);
  });
});

describe("validateToolCall - denylist", () => {
  function denyPolicy() {
    return BalancedPolicy({
      blockedTools: new Set(["exec_shell", "delete_all"]),
      raiseOnBlock: false,
    });
  }

  it("blocked tool not allowed", () => {
    const r = validateToolCall(tc("exec_shell", {}), denyPolicy());
    expect(r.allowed).toBe(false);
  });

  it("blocked tool score is one", () => {
    const r = validateToolCall(tc("exec_shell", {}), denyPolicy());
    expect(r.score).toBe(1.0);
  });

  it("blocked tool category denylist_violation", () => {
    const r = validateToolCall(tc("exec_shell", {}), denyPolicy());
    expect((r.metadata.categories as string[]) ?? []).toContain("denylist_violation");
  });

  it("second blocked tool", () => {
    const r = validateToolCall(tc("delete_all", {}), denyPolicy());
    expect(r.allowed).toBe(false);
    expect(r.score).toBe(1.0);
  });

  it("non-blocked tool passes", () => {
    const r = validateToolCall(tc("search_web", { query: "hello" }), denyPolicy());
    expect(r.allowed).toBe(true);
  });

  it("blocked tool reason mentions tool name", () => {
    const r = validateToolCall(tc("exec_shell", {}), denyPolicy());
    expect(r.reasons.some((reason) => reason.includes("exec_shell"))).toBe(true);
  });
});

describe("validateToolCall - allowlist", () => {
  function allowPolicy() {
    return BalancedPolicy({
      allowedTools: ["search_web", "read_file"],
      raiseOnBlock: false,
    });
  }

  it("unlisted tool not allowed", () => {
    const r = validateToolCall(tc("delete_file", {}), allowPolicy());
    expect(r.allowed).toBe(false);
  });

  it("unlisted tool score", () => {
    const r = validateToolCall(tc("delete_file", {}), allowPolicy());
    expect(r.score).toBe(0.95);
  });

  it("unlisted tool category", () => {
    const r = validateToolCall(tc("delete_file", {}), allowPolicy());
    expect((r.metadata.categories as string[]) ?? []).toContain("allowlist_violation");
  });

  it("listed tool passes", () => {
    const r = validateToolCall(tc("search_web", { query: "hello" }), allowPolicy());
    expect(r.allowed).toBe(true);
  });

  it("second listed tool passes", () => {
    const r = validateToolCall(tc("read_file", { path: "documents/report.pdf" }), allowPolicy());
    expect(r.allowed).toBe(true);
  });

  it("allowlist violation reason mentions permitted", () => {
    const r = validateToolCall(tc("exec_shell", {}), allowPolicy());
    expect(r.reasons.some((reason) => reason.includes("search_web") || reason.includes("read_file"))).toBe(true);
  });
});

describe("validateToolCall - dangerous names", () => {
  it.each([
    "exec",
    "eval",
    "shell",
    "run_command",
    "execute_command",
    "delete_all",
    "format_disk",
    "drop_database",
    "wipe",
  ])("dangerous name blocked: %s", (name) => {
    const r = validateToolCall(tc(name, {}), balancedPolicy());
    expect(r.allowed).toBe(false);
    expect(r.score).toBe(0.95);
  });

  it("dangerous name category", () => {
    const r = validateToolCall(tc("exec", {}), balancedPolicy());
    expect((r.metadata.categories as string[]) ?? []).toContain("dangerous_operation");
  });

  it("dangerous name reason contains name", () => {
    const r = validateToolCall(tc("shell", {}), balancedPolicy());
    expect(r.reasons.some((reason) => reason.includes("shell"))).toBe(true);
  });
});

describe("validateToolCall - admin names", () => {
  it.each(["admin_panel", "superuser_create", "debug_endpoint", "maintenance_api", "internal_api_v1"])(
    "admin name blocked: %s",
    (name) => {
      const r = validateToolCall(tc(name, {}), balancedPolicy());
      expect(r.allowed).toBe(false);
      expect(r.score).toBe(0.8);
    },
  );

  it("admin name category", () => {
    const r = validateToolCall(tc("admin_panel", {}), balancedPolicy());
    expect((r.metadata.categories as string[]) ?? []).toContain("dangerous_operation");
  });

  it("admin name blocked by logging_only (allowed)", () => {
    // score=0.80 < block=1.0 for LoggingOnly -> allowed
    const r = validateToolCall(tc("admin_panel", {}), loggingOnlyPolicy());
    expect(r.allowed).toBe(true);
  });

  it("regular name not flagged", () => {
    const r = validateToolCall(tc("search_web", { query: "test" }), balancedPolicy());
    expect(r.allowed).toBe(true);
    expect(r.score).toBe(0.0);
  });
});

describe("validateToolCall - path traversal", () => {
  it("dotdot slash blocked", () => {
    const r = validateToolCall(tc("read_file", { path: "../../etc/passwd" }), balancedPolicy());
    expect(r.allowed).toBe(false);
    expect(r.score).toBe(0.92);
  });

  it("three levels up", () => {
    const r = validateToolCall(tc("read_file", { path: "../../../secret.txt" }), balancedPolicy());
    expect(r.allowed).toBe(false);
    expect(r.score).toBe(0.92);
  });

  it("path_traversal category", () => {
    const r = validateToolCall(tc("read_file", { path: "../../etc/shadow" }), balancedPolicy());
    expect((r.metadata.categories as string[]) ?? []).toContain("path_traversal");
  });

  it("safe relative path not flagged", () => {
    const r = validateToolCall(tc("read_file", { path: "documents/report.pdf" }), balancedPolicy());
    expect(r.allowed).toBe(true);
  });

  it("path traversal reason mentions key", () => {
    const r = validateToolCall(tc("read_file", { path: "../../etc/passwd" }), balancedPolicy());
    expect(r.reasons.some((reason) => reason.includes("path"))).toBe(true);
  });
});

describe("validateToolCall - system paths", () => {
  it.each(["/etc/passwd", "/etc/shadow", "/proc/self/environ", "/sys/kernel/debug", "/dev/sda"])(
    "system path blocked: %s",
    (path) => {
      const r = validateToolCall(tc("read_file", { path }), balancedPolicy());
      expect(r.allowed).toBe(false);
      expect(r.score).toBe(0.88);
    },
  );

  it("system path category", () => {
    const r = validateToolCall(tc("read_file", { path: "/etc/passwd" }), balancedPolicy());
    expect((r.metadata.categories as string[]) ?? []).toContain("dangerous_operation");
  });
});

describe("validateToolCall - sensitive files", () => {
  it.each(["/home/user/.ssh/id_rsa", "/home/user/.env", "/home/user/.aws/credentials", "/var/www/.bash_history"])(
    "sensitive file blocked: %s",
    (path) => {
      const r = validateToolCall(tc("read_file", { path }), balancedPolicy());
      expect(r.allowed).toBe(false);
      expect(r.score).toBe(0.95);
    },
  );

  it("sensitive file category", () => {
    const r = validateToolCall(tc("read_file", { path: "/home/user/.ssh/id_rsa" }), balancedPolicy());
    expect((r.metadata.categories as string[]) ?? []).toContain("dangerous_operation");
  });
});

describe("validateToolCall - SSRF", () => {
  it("loopback ip blocked", () => {
    const r = validateToolCall(tc("http_request", { url: "http://127.0.0.1/admin" }), balancedPolicy());
    expect(r.allowed).toBe(false);
    expect(r.score).toBe(0.9);
  });

  it("private 192 ip blocked", () => {
    const r = validateToolCall(tc("http_request", { url: "http://192.168.1.1/api" }), balancedPolicy());
    expect(r.allowed).toBe(false);
    expect(r.score).toBe(0.9);
  });

  it("private 10 ip blocked", () => {
    const r = validateToolCall(tc("http_request", { url: "http://10.0.0.1/internal" }), balancedPolicy());
    expect(r.allowed).toBe(false);
    expect(r.score).toBe(0.9);
  });

  it("aws imds blocked", () => {
    const r = validateToolCall(
      tc("http_request", { url: "http://169.254.169.254/latest/meta-data/" }),
      balancedPolicy(),
    );
    expect(r.allowed).toBe(false);
  });

  it("gcp metadata blocked", () => {
    const r = validateToolCall(
      tc("http_request", { url: "http://metadata.google.internal/computeMetadata/v1/" }),
      balancedPolicy(),
    );
    expect(r.allowed).toBe(false);
    expect(r.score).toBe(0.98);
  });

  it("localhost blocked", () => {
    const r = validateToolCall(tc("http_request", { url: "http://localhost:8080/admin" }), balancedPolicy());
    expect(r.allowed).toBe(false);
    expect(r.score).toBe(0.88);
  });

  it("ssrf_attempt category in metadata", () => {
    const r = validateToolCall(tc("http_request", { url: "http://127.0.0.1/" }), balancedPolicy());
    expect((r.metadata.categories as string[]) ?? []).toContain("ssrf_attempt");
  });

  it("public url not flagged", () => {
    const r = validateToolCall(tc("http_request", { url: "https://api.example.com/data" }), balancedPolicy());
    expect(r.allowed).toBe(true);
  });
});

describe("validateToolCall - command injection", () => {
  it("semicolon injection", () => {
    const r = validateToolCall(tc("search_web", { query: "python; rm -rf /" }), balancedPolicy());
    expect(r.allowed).toBe(false);
    expect(r.score).toBe(0.88);
  });

  it("double ampersand injection", () => {
    const r = validateToolCall(tc("search_web", { query: "test && malicious_cmd" }), balancedPolicy());
    expect(r.allowed).toBe(false);
    expect(r.score).toBe(0.88);
  });

  it("pipe injection", () => {
    const r = validateToolCall(tc("search_web", { query: "test | bash -x /tmp/evil.sh" }), balancedPolicy());
    expect(r.allowed).toBe(false);
    expect(r.score).toBe(0.88);
  });

  it("subshell dollar paren", () => {
    const r = validateToolCall(tc("search_web", { query: "$(cat /etc/passwd)" }), balancedPolicy());
    expect(r.allowed).toBe(false);
    expect(r.score).toBe(0.88);
  });

  it("command_injection category", () => {
    const r = validateToolCall(tc("search_web", { query: "test; id" }), balancedPolicy());
    expect((r.metadata.categories as string[]) ?? []).toContain("command_injection");
  });

  it("clean query not flagged", () => {
    const r = validateToolCall(tc("search_web", { query: "python best practices" }), balancedPolicy());
    expect(r.allowed).toBe(true);
  });
});

describe("validateToolCall - SQL injection", () => {
  it("or 1 equals 1", () => {
    const r = validateToolCall(
      tc("db_query", { query: "SELECT * FROM users WHERE id=1 OR 1=1" }),
      balancedPolicy(),
    );
    expect(r.allowed).toBe(false);
    expect(r.score).toBe(0.9);
  });

  it("union select", () => {
    const r = validateToolCall(
      tc("db_query", { query: "SELECT * FROM users UNION SELECT * FROM admins" }),
      balancedPolicy(),
    );
    expect(r.allowed).toBe(false);
    expect(r.score).toBe(0.9);
  });

  it("drop table", () => {
    const r = validateToolCall(tc("db_query", { query: "SELECT 1; DROP TABLE users" }), balancedPolicy());
    expect(r.allowed).toBe(false);
  });

  it("safe sql not flagged", () => {
    const r = validateToolCall(
      tc("db_query", { query: "SELECT name, age FROM users WHERE id = 42" }),
      balancedPolicy(),
    );
    expect(r.allowed).toBe(true);
  });
});

describe("validateToolCall - schema valid", () => {
  it("valid args allowed", () => {
    const r = validateToolCall(
      tc("create_user", { username: "alice", age: 30, limit: 50 }, FULL_SCHEMA),
      balancedPolicy(),
    );
    expect(r.allowed).toBe(true);
    expect(r.score).toBe(0.0);
  });

  it("schema_validated flag true", () => {
    const r = validateToolCall(tc("create_user", { username: "alice", age: 30 }, FULL_SCHEMA), balancedPolicy());
    expect(r.metadata.schema_validated).toBe(true);
  });

  it("no schema flag false", () => {
    const r = validateToolCall(tc("search_web", { query: "test" }), balancedPolicy());
    expect(r.metadata.schema_validated).toBe(false);
  });

  it("extra fields not penalised", () => {
    // JSON Schema allows additional properties by default
    const r = validateToolCall(
      tc("create_user", { username: "alice", age: 30, extra_field: "ok" }, FULL_SCHEMA),
      balancedPolicy(),
    );
    expect(r.allowed).toBe(true);
  });
});

describe("validateToolCall - schema violation", () => {
  it("type mismatch blocked", () => {
    const r = validateToolCall(
      tc("create_user", { username: "alice", age: "thirty" }, FULL_SCHEMA),
      balancedPolicy(),
    );
    expect(r.allowed).toBe(false);
    expect(r.score).toBe(0.88);
  });

  it("type mismatch category", () => {
    const r = validateToolCall(
      tc("create_user", { username: "alice", age: "thirty" }, FULL_SCHEMA),
      balancedPolicy(),
    );
    expect((r.metadata.categories as string[]) ?? []).toContain("schema_violation");
  });

  it("missing required field blocked", () => {
    const r = validateToolCall(tc("create_user", { username: "alice" }, FULL_SCHEMA), balancedPolicy());
    expect(r.allowed).toBe(false);
    expect(r.score).toBe(0.88);
  });

  it("minimum violation blocked", () => {
    const r = validateToolCall(
      tc("create_user", { username: "alice", age: 25, limit: 0 }, FULL_SCHEMA),
      balancedPolicy(),
    );
    expect(r.allowed).toBe(false);
    expect(r.score).toBe(0.88);
  });

  it("maximum violation blocked", () => {
    const r = validateToolCall(
      tc("create_user", { username: "alice", age: 25, limit: 200 }, FULL_SCHEMA),
      balancedPolicy(),
    );
    expect(r.allowed).toBe(false);
    expect(r.score).toBe(0.88);
  });

  it("enum violation blocked", () => {
    const enumSchema = {
      type: "object",
      properties: { color: { type: "string", enum: ["red", "green", "blue"] } },
    };
    const r = validateToolCall(tc("set_color", { color: "purple" }, enumSchema), balancedPolicy());
    expect(r.allowed).toBe(false);
    expect(r.score).toBe(0.88);
  });

  it("schema violation reason is string", () => {
    const r = validateToolCall(
      tc("create_user", { username: "alice", age: "thirty" }, FULL_SCHEMA),
      balancedPolicy(),
    );
    expect(r.reasons.every((reason) => typeof reason === "string")).toBe(true);
  });
});

describe("validateToolCall - result structure", () => {
  it("guard type is tool", () => {
    const r = validateToolCall(tc("search_web", { query: "hello" }), balancedPolicy());
    expect(r.guardType).toBe(GuardType.TOOL);
  });

  it("metadata has tool_name", () => {
    const r = validateToolCall(tc("read_file", { path: "../../etc/passwd" }), balancedPolicy());
    expect(r.metadata.tool_name).toBe("read_file");
  });

  it("metadata has call_id", () => {
    const r = validateToolCall(
      tc("read_file", { path: "../../etc/passwd" }, undefined, "call_abc"),
      balancedPolicy(),
    );
    expect(r.metadata.call_id).toBe("call_abc");
  });

  it("metadata call_id is null when not set", () => {
    const r = validateToolCall(tc("search_web", { query: "test" }), balancedPolicy());
    expect(r.metadata.call_id).toBeNull();
  });

  it("metadata has categories", () => {
    const r = validateToolCall(tc("read_file", { path: "../../etc/passwd" }), balancedPolicy());
    expect("categories" in r.metadata).toBe(true);
  });

  it("metadata has check_count", () => {
    const r = validateToolCall(tc("search_web", { query: "test" }), balancedPolicy());
    expect("check_count" in r.metadata).toBe(true);
    expect(typeof r.metadata.check_count).toBe("number");
  });

  it("metadata has schema_validated", () => {
    const r = validateToolCall(tc("search_web", { query: "test" }), balancedPolicy());
    expect("schema_validated" in r.metadata).toBe(true);
  });

  it("reasons is a list", () => {
    const r = validateToolCall(tc("read_file", { path: "../../etc/passwd" }), balancedPolicy());
    expect(Array.isArray(r.reasons)).toBe(true);
  });

  it("score is a number", () => {
    const r = validateToolCall(tc("read_file", { path: "../../etc/passwd" }), balancedPolicy());
    expect(typeof r.score).toBe("number");
  });

  it("path_traversal category in blocked result", () => {
    const r = validateToolCall(tc("read_file", { path: "../../etc/passwd" }), balancedPolicy());
    expect((r.metadata.categories as string[]) ?? []).toContain("path_traversal");
  });

  it("safe result check_count at least 3", () => {
    // At minimum the 3 name-level checks run for a safe call
    const r = validateToolCall(tc("search_web", { query: "python" }), balancedPolicy());
    expect(r.metadata.check_count as number).toBeGreaterThanOrEqual(3);
  });

  it("schema_validated true when schema provided", () => {
    const schema = { type: "object", properties: { q: { type: "string" } } };
    const r = validateToolCall(tc("search_web", { q: "test" }, schema), balancedPolicy());
    expect(r.metadata.schema_validated).toBe(true);
  });
});

describe("validateToolCall - guard disabled", () => {
  it("disabled allows dangerous name", () => {
    const r = validateToolCall(tc("exec", {}), disabledPolicy());
    expect(r.allowed).toBe(true);
    expect(r.score).toBe(0.0);
  });

  it("disabled allows path traversal", () => {
    const r = validateToolCall(tc("read_file", { path: "../../etc/passwd" }), disabledPolicy());
    expect(r.allowed).toBe(true);
  });

  it("disabled sets skipped metadata", () => {
    const r = validateToolCall(tc("exec", {}), disabledPolicy());
    expect(r.metadata.skipped).toBe(true);
  });

  it("disabled guard type still tool", () => {
    const r = validateToolCall(tc("exec", {}), disabledPolicy());
    expect(r.guardType).toBe(GuardType.TOOL);
  });

  it("disabled reasons empty", () => {
    const r = validateToolCall(tc("exec", {}), disabledPolicy());
    expect(r.reasons).toEqual([]);
  });

  it("disabled tool_name in metadata", () => {
    const r = validateToolCall(tc("exec", {}), disabledPolicy());
    expect(r.metadata.tool_name).toBe("exec");
  });
});

describe("validateToolCall - short circuit", () => {
  it("short circuit true stops early", () => {
    const r = validateToolCall(tc("read_file", { path: "../../etc/passwd" }), balancedPolicy(), {
      shortCircuit: true,
    });
    const rAll = validateToolCall(tc("read_file", { path: "../../etc/passwd" }), balancedPolicy(), {
      shortCircuit: false,
    });
    expect(r.metadata.check_count as number).toBeLessThan(rAll.metadata.check_count as number);
  });

  it("short circuit true still blocks", () => {
    const r = validateToolCall(tc("read_file", { path: "../../etc/passwd" }), balancedPolicy(), {
      shortCircuit: true,
    });
    expect(r.allowed).toBe(false);
  });

  it("short circuit false still blocks", () => {
    const r = validateToolCall(tc("read_file", { path: "../../etc/passwd" }), balancedPolicy(), {
      shortCircuit: false,
    });
    expect(r.allowed).toBe(false);
  });

  it("short circuit false collects more violations", () => {
    // A call that triggers multiple checks — short_circuit=False finds all
    const text = "../../etc/passwd; DROP TABLE users";
    const rSc = validateToolCall(tc("read_file", { path: text }), balancedPolicy(), { shortCircuit: true });
    const rAll = validateToolCall(tc("read_file", { path: text }), balancedPolicy(), { shortCircuit: false });
    expect(rAll.reasons.length).toBeGreaterThanOrEqual(rSc.reasons.length);
  });
});

describe("validateToolCall - nested args", () => {
  it("path traversal in nested dict", () => {
    const r = validateToolCall(tc("process", { config: { path: "../../etc/passwd" } }), balancedPolicy());
    expect(r.allowed).toBe(false);
    expect(r.score).toBe(0.92);
  });

  it("ssrf in nested dict", () => {
    const r = validateToolCall(tc("fetch", { options: { url: "http://127.0.0.1/admin" } }), balancedPolicy());
    expect(r.allowed).toBe(false);
  });

  it("safe nested dict passes", () => {
    const r = validateToolCall(
      tc("process", { config: { path: "documents/report.pdf", format: "pdf" } }),
      balancedPolicy(),
    );
    expect(r.allowed).toBe(true);
  });

  it("injection in list item", () => {
    const r = validateToolCall(
      tc("batch_read", { paths: ["../../etc/passwd", "safe.txt"] }),
      balancedPolicy(),
    );
    expect(r.allowed).toBe(false);
  });
});

describe("validateToolCall - policy thresholds", () => {
  it("balanced blocks path traversal", () => {
    const r = validateToolCall(tc("read_file", { path: "../../etc/passwd" }), balancedPolicy());
    expect(r.allowed).toBe(false);
  });

  it("strict blocks admin name", () => {
    // admin_panel score=0.80 >= strict block=0.40
    const r = validateToolCall(tc("admin_panel", {}), strictPolicy());
    expect(r.allowed).toBe(false);
  });

  it("balanced blocks admin name", () => {
    // admin_panel score=0.80 >= balanced block=0.75
    const r = validateToolCall(tc("admin_panel", {}), balancedPolicy());
    expect(r.allowed).toBe(false);
  });

  it("logging_only allows admin name", () => {
    // admin_panel score=0.80 < logging block=1.0
    const r = validateToolCall(tc("admin_panel", {}), loggingOnlyPolicy());
    expect(r.allowed).toBe(true);
  });

  it("logging_only still computes score", () => {
    const r = validateToolCall(tc("admin_panel", {}), loggingOnlyPolicy());
    expect(r.score).toBe(0.8);
  });

  it("balanced blocks dangerous name", () => {
    const r = validateToolCall(tc("exec", {}), balancedPolicy());
    expect(r.allowed).toBe(false);
  });

  it("logging_only allows dangerous name", () => {
    const r = validateToolCall(tc("exec", {}), loggingOnlyPolicy());
    expect(r.allowed).toBe(true);
  });

  it("per guard threshold override", () => {
    const p = BalancedPolicy({
      toolGuard: new GuardConfig({ blockThreshold: 0.98 }),
      raiseOnBlock: false,
    });
    // exec score=0.95 < per-guard override 0.98 -> allowed
    const r = validateToolCall(tc("exec", {}), p);
    expect(r.allowed).toBe(true);
    expect(r.score).toBe(0.95);
  });
});

describe("validateToolCalls", () => {
  it("returns one result per call", () => {
    const calls = [tc("search_web", { query: "python" }), tc("read_file", { path: "../../etc/passwd" })];
    const results = validateToolCalls(calls, balancedPolicy());
    expect(results.length).toBe(2);
  });

  it("safe call result allowed", () => {
    const results = validateToolCalls([tc("search_web", { query: "python" })], balancedPolicy());
    expect(results[0].allowed).toBe(true);
  });

  it("dangerous call result blocked", () => {
    const results = validateToolCalls([tc("read_file", { path: "../../etc/passwd" })], balancedPolicy());
    expect(results[0].allowed).toBe(false);
  });

  it("empty list returns empty", () => {
    expect(validateToolCalls([], balancedPolicy())).toEqual([]);
  });

  it("order preserved", () => {
    const calls = [
      tc("search_web", { query: "python" }),
      tc("exec", {}),
      tc("get_weather", { city: "Paris" }),
    ];
    const results = validateToolCalls(calls, balancedPolicy());
    expect(results[0].metadata.tool_name).toBe("search_web");
    expect(results[1].metadata.tool_name).toBe("exec");
    expect(results[2].metadata.tool_name).toBe("get_weather");
  });

  it("mix of safe and dangerous", () => {
    const calls = [tc("search_web", { query: "hello" }), tc("read_file", { path: "../../etc/passwd" })];
    const results = validateToolCalls(calls, balancedPolicy());
    expect(results[0].allowed).toBe(true);
    expect(results[1].allowed).toBe(false);
  });

  it("all results are ScanResults", () => {
    const calls = [tc("search_web", { query: "a" }), tc("exec", {})];
    for (const r of validateToolCalls(calls, balancedPolicy())) {
      expect(r.guardType).toBeDefined();
    }
  });
});

describe("aggregateToolScans", () => {
  it("empty list returns clean", () => {
    const agg = aggregateToolScans([], balancedPolicy());
    expect(agg.allowed).toBe(true);
    expect(agg.score).toBe(0.0);
  });

  it("empty list source_count zero", () => {
    const agg = aggregateToolScans([], balancedPolicy());
    expect(agg.metadata.source_count).toBe(0);
  });

  it("all safe results aggregate clean", () => {
    const policy = balancedPolicy();
    const r1 = validateToolCall(tc("search_web", { query: "python" }), policy);
    const r2 = validateToolCall(tc("get_weather", { city: "Paris" }), policy);
    const agg = aggregateToolScans([r1, r2], policy);
    expect(agg.allowed).toBe(true);
    expect(agg.score).toBe(0.0);
  });

  it("one blocked makes aggregate blocked", () => {
    const policy = balancedPolicy();
    const rSafe = validateToolCall(tc("search_web", { query: "python" }), policy);
    const rBad = validateToolCall(tc("read_file", { path: "../../etc/passwd" }), policy);
    const agg = aggregateToolScans([rSafe, rBad], policy);
    expect(agg.allowed).toBe(false);
  });

  it("aggregate score is max", () => {
    const policy = balancedPolicy();
    const rHigh = validateToolCall(tc("exec", {}), policy); // 0.95
    const rLow = validateToolCall(tc("admin_panel", {}), policy); // 0.80
    const agg = aggregateToolScans([rHigh, rLow], policy);
    expect(agg.score).toBe(Math.max(rHigh.score, rLow.score));
    expect(agg.score).toBe(0.95);
  });

  it("reasons merged", () => {
    const policy = balancedPolicy();
    const r1 = validateToolCall(tc("exec", {}), policy);
    const r2 = validateToolCall(tc("read_file", { path: "../../etc/passwd" }), policy);
    const agg = aggregateToolScans([r1, r2], policy);
    expect(agg.reasons.length).toBeGreaterThanOrEqual(2);
  });

  it("guard type is tool", () => {
    const policy = balancedPolicy();
    const r = validateToolCall(tc("search_web", { query: "test" }), policy);
    const agg = aggregateToolScans([r], policy);
    expect(agg.guardType).toBe(GuardType.TOOL);
  });

  it("metadata aggregated flag", () => {
    const policy = balancedPolicy();
    const r = validateToolCall(tc("search_web", { query: "test" }), policy);
    const agg = aggregateToolScans([r], policy);
    expect(agg.metadata.aggregated).toBe(true);
  });

  it("metadata source_count", () => {
    const policy = balancedPolicy();
    const r1 = validateToolCall(tc("search_web", { query: "a" }), policy);
    const r2 = validateToolCall(tc("search_web", { query: "b" }), policy);
    const agg = aggregateToolScans([r1, r2], policy);
    expect(agg.metadata.source_count).toBe(2);
  });

  it("metadata tool_names list", () => {
    const policy = balancedPolicy();
    const rSafe = validateToolCall(tc("search_web", { query: "python" }), policy);
    const rBad = validateToolCall(tc("read_file", { path: "../../etc/passwd" }), policy);
    const agg = aggregateToolScans([rSafe, rBad], policy);
    const toolNames = (agg.metadata.tool_names as string[]) ?? [];
    expect(toolNames).toContain("search_web");
    expect(toolNames).toContain("read_file");
  });

  it("single result aggregate", () => {
    const policy = balancedPolicy();
    const r = validateToolCall(tc("exec", {}), policy);
    const agg = aggregateToolScans([r], policy);
    expect(agg.allowed).toBe(false);
    expect(agg.score).toBe(r.score);
  });

  it("aggregate respects policy threshold", () => {
    // exec score=0.95 < logging block=1.0 -> allowed even in aggregate
    const policy = loggingOnlyPolicy();
    const r = validateToolCall(tc("exec", {}), policy);
    const agg = aggregateToolScans([r], policy);
    expect(agg.allowed).toBe(true);
  });

  it("categories deduped", () => {
    const policy = balancedPolicy();
    const r1 = validateToolCall(tc("read_file", { path: "../../etc/passwd" }), policy);
    const r2 = validateToolCall(tc("read_file", { path: "../secret.txt" }), policy);
    const agg = aggregateToolScans([r1, r2], policy);
    const cats = (agg.metadata.categories as string[]) ?? [];
    expect(cats.length).toBe(new Set(cats).size);
  });

  it("from validateToolCalls output", () => {
    const policy = balancedPolicy();
    const calls = [tc("search_web", { query: "python" }), tc("read_file", { path: "../../etc/passwd" })];
    const perCall = validateToolCalls(calls, policy);
    const agg = aggregateToolScans(perCall, policy);
    expect(agg.allowed).toBe(false);
    expect(agg.score).toBe(0.92);
  });
});
