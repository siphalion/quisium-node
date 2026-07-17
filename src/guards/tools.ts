/**
 * Tool-call validation guard. Intercepts every function/tool invocation the
 * model wants to make and validates it against the policy's allowlist and the
 * tool's JSON schema.
 */
import { getSyncRequire } from "../internal/optionalRequire.js";
import type { Policy } from "../policies.js";
import { GuardType, ScanResult, ToolCall, round4 } from "../types.js";

const requireOptional = getSyncRequire();

interface CheckResult {
  matched: boolean;
  score: number;
  reason: string;
  matchedText: string;
}

const NO_MATCH: CheckResult = { matched: false, score: 0.0, reason: "", matchedText: "" };
const FLAGS = "i";

const RE_PATH_TRAVERSAL = new RegExp("(\\.\\.[/\\\\])+|(\\.\\.[/\\\\]?){2,}", FLAGS);

const RE_SYSTEM_PATHS = new RegExp(
  "^/?(etc|proc|sys|dev|boot|root|run|var/run|var/log" +
    "|windows[/\\\\]system32|winnt|programdata)[/\\\\]",
  FLAGS,
);

const RE_SENSITIVE_FILES = new RegExp(
  "(^|[/\\\\])(passwd|shadow|sudoers|hosts|authorized_keys" +
    "|\\.ssh[/\\\\]|\\.aws[/\\\\]credentials|\\.env" +
    "|id_rsa|id_ed25519|\\.bash_history|\\.zsh_history" +
    "|web\\.config|appsettings\\.json|secrets\\.json" +
    "|private\\.pem|private\\.key|server\\.key)$",
  FLAGS,
);

const RE_INTERNAL_IP = new RegExp(
  "https?://" +
    "(127\\.\\d+\\.\\d+\\.\\d+" + // loopback
    "|10\\.\\d+\\.\\d+\\.\\d+" + // RFC-1918 10/8
    "|172\\.(1[6-9]|2\\d|3[01])\\.\\d+\\.\\d+" + // RFC-1918 172.16/12
    "|192\\.168\\.\\d+\\.\\d+" + // RFC-1918 192.168/16
    "|169\\.254\\.\\d+\\.\\d+" + // link-local / AWS metadata
    "|::1" + // IPv6 loopback
    "|0\\.0\\.0\\.0)",
  FLAGS,
);

const RE_METADATA_URLS = new RegExp(
  "https?://" +
    "(169\\.254\\.169\\.254" + // AWS / GCP / Azure IMDS
    "|metadata\\.google\\.internal" +
    "|metadata\\.azure\\.com" +
    "|100\\.100\\.100\\.200)", // Alibaba Cloud metadata
  FLAGS,
);

const RE_LOCALHOST = new RegExp("https?://(localhost|0\\.0\\.0\\.0)(:\\d+)?", FLAGS);

// Shell metacharacters: ;  &  |  `  $( ... )  ${ ... }  output redirection to /
const RE_SHELL_METACHAR = /[;&|`]|\$\(|\$\{|>\s*\/|&&|\|\|/;

// avoid false positives on natural language mentions of interpreter names
const RE_SHELL_COMMANDS = new RegExp(
  "(?:^|\\s|[;&|])" +
    "(bash|sh|zsh|fish|cmd\\.exe|powershell|pwsh" +
    "|curl|wget|nc|ncat|netcat|perl|ruby|php)" +
    "\\s+-[a-zA-Z]",
  FLAGS,
);

const RE_SUBSHELL = /(\$\(|`).{0,120}(\)|`)/;

const RE_WILDCARD_DESTRUCTIVE = /(\*\s*\/|\*\.\*|\/\s*\*)/;

const RE_SQL_INJECTION = new RegExp(
  "('?\\s*(OR|AND)\\s+'?\\d+'?\\s*=\\s*'?\\d+" + // OR 1=1
    "|--\\s*$" + // trailing SQL comment
    "|;\\s*(DROP|DELETE|TRUNCATE|INSERT|UPDATE)\\s+TABLE" +
    "|UNION\\s+(ALL\\s+)?SELECT)",
  FLAGS,
);

const RE_INHERENTLY_DANGEROUS = new RegExp(
  "^(exec|eval|shell|run_command|execute_command" +
    "|system_exec|os_exec|subprocess|spawn" +
    "|delete_all|wipe|format_disk|drop_database" +
    "|send_all_emails|mass_email|bulk_sms)$",
  FLAGS,
);

const RE_ADMIN_TOOL = new RegExp(
  "(admin|superuser|root|privileged|internal_api" + "|debug_endpoint|maintenance|backdoor)",
  FLAGS,
);

function checkDenylist(toolName: string, policy: Policy): CheckResult | null {
  if (!policy.isToolAllowed(toolName)) {
    const normalised = toolName.toLowerCase().trim();
    if (policy.blockedTools.has(normalised)) {
      return {
        matched: true,
        score: 1.0,
        reason: `Tool '${toolName}' is explicitly in the policy denylist.`,
        matchedText: toolName,
      };
    }
    if (policy.allowedTools !== null) {
      const allowedStr = [...policy.allowedTools].sort().join(", ") || "none";
      return {
        matched: true,
        score: 0.95,
        reason: `Tool '${toolName}' is not in the policy allowlist. Permitted tools: ${allowedStr}`,
        matchedText: toolName,
      };
    }
  }
  return null;
}

function checkInherentlyDangerousName(toolName: string): CheckResult {
  const m = RE_INHERENTLY_DANGEROUS.exec(toolName);
  if (!m) return NO_MATCH;
  return {
    matched: true,
    score: 0.95,
    reason: `Tool name '${toolName}' is inherently dangerous and blocked unconditionally.`,
    matchedText: toolName,
  };
}

function checkAdminToolName(toolName: string): CheckResult {
  const m = RE_ADMIN_TOOL.exec(toolName);
  if (!m) return NO_MATCH;
  return {
    matched: true,
    score: 0.8,
    reason: `Tool name '${toolName}' suggests privileged access (matched '${m[0]}').`,
    matchedText: m[0],
  };
}

function checkPathTraversal(key: string, value: string): CheckResult {
  const m = RE_PATH_TRAVERSAL.exec(value);
  if (!m) return NO_MATCH;
  return {
    matched: true,
    score: 0.92,
    reason: `Path traversal sequence in arg '${key}': '${value.slice(0, 80)}'`,
    matchedText: value.slice(0, 80),
  };
}

function checkSystemPath(key: string, value: string): CheckResult {
  const m = RE_SYSTEM_PATHS.exec(value);
  if (!m) return NO_MATCH;
  return {
    matched: true,
    score: 0.88,
    reason: `System path access in arg '${key}': '${value.slice(0, 80)}'`,
    matchedText: value.slice(0, 80),
  };
}

function checkSensitiveFile(key: string, value: string): CheckResult {
  const m = RE_SENSITIVE_FILES.exec(value);
  if (!m) return NO_MATCH;
  return {
    matched: true,
    score: 0.95,
    reason: `Sensitive file access in arg '${key}': '${value.slice(0, 80)}'`,
    matchedText: value.slice(0, 80),
  };
}

function checkInternalIp(key: string, value: string): CheckResult {
  const m = RE_INTERNAL_IP.exec(value);
  if (!m) return NO_MATCH;
  return {
    matched: true,
    score: 0.9,
    reason: `Internal IP SSRF attempt in arg '${key}': '${value.slice(0, 80)}'`,
    matchedText: value.slice(0, 80),
  };
}

function checkMetadataUrl(key: string, value: string): CheckResult {
  const m = RE_METADATA_URLS.exec(value);
  if (!m) return NO_MATCH;
  return {
    matched: true,
    score: 0.98,
    reason: `Cloud metadata SSRF in arg '${key}': '${value.slice(0, 80)}'`,
    matchedText: value.slice(0, 80),
  };
}

function checkLocalhost(key: string, value: string): CheckResult {
  const m = RE_LOCALHOST.exec(value);
  if (!m) return NO_MATCH;
  return {
    matched: true,
    score: 0.88,
    reason: `Localhost SSRF attempt in arg '${key}': '${value.slice(0, 80)}'`,
    matchedText: value.slice(0, 80),
  };
}

function checkShellMetachar(key: string, value: string): CheckResult {
  const m = RE_SHELL_METACHAR.exec(value);
  if (!m) return NO_MATCH;
  return {
    matched: true,
    score: 0.88,
    reason: `Shell metacharacter injection in arg '${key}': '${value.slice(0, 80)}'`,
    matchedText: value.slice(0, 80),
  };
}

function checkShellCommand(key: string, value: string): CheckResult {
  const m = RE_SHELL_COMMANDS.exec(value);
  if (!m) return NO_MATCH;
  return {
    matched: true,
    score: 0.85,
    reason: `Shell command invocation in arg '${key}': '${value.slice(0, 80)}'`,
    matchedText: value.slice(0, 80),
  };
}

function checkSubshell(key: string, value: string): CheckResult {
  const m = RE_SUBSHELL.exec(value);
  if (!m) return NO_MATCH;
  return {
    matched: true,
    score: 0.92,
    reason: `Subshell expansion in arg '${key}': '${value.slice(0, 80)}'`,
    matchedText: value.slice(0, 80),
  };
}

function checkWildcardDestructive(key: string, value: string): CheckResult {
  const m = RE_WILDCARD_DESTRUCTIVE.exec(value);
  if (!m) return NO_MATCH;
  return {
    matched: true,
    score: 0.82,
    reason: `Destructive wildcard pattern in arg '${key}': '${value.slice(0, 80)}'`,
    matchedText: value.slice(0, 80),
  };
}

function checkSqlInjection(key: string, value: string): CheckResult {
  const m = RE_SQL_INJECTION.exec(value);
  if (!m) return NO_MATCH;
  return {
    matched: true,
    score: 0.9,
    reason: `SQL injection pattern in arg '${key}': '${value.slice(0, 80)}'`,
    matchedText: value.slice(0, 80),
  };
}

type ArgCheckFn = (key: string, value: string) => CheckResult;

const ALL_ARG_CHECKS: Array<[ArgCheckFn, string]> = [
  [checkPathTraversal, "path_traversal"],
  [checkSystemPath, "dangerous_operation"],
  [checkSensitiveFile, "dangerous_operation"],
  [checkInternalIp, "ssrf_attempt"],
  [checkMetadataUrl, "ssrf_attempt"],
  [checkLocalhost, "ssrf_attempt"],
  [checkShellMetachar, "command_injection"],
  [checkShellCommand, "command_injection"],
  [checkSubshell, "command_injection"],
  [checkWildcardDestructive, "dangerous_operation"],
  [checkSqlInjection, "command_injection"],
];

const TYPE_CHECKERS: Record<string, (v: unknown) => boolean> = {
  string: (v) => typeof v === "string",
  integer: (v) => typeof v === "number" && Number.isInteger(v),
  number: (v) => typeof v === "number",
  boolean: (v) => typeof v === "boolean",
  array: (v) => Array.isArray(v),
  object: (v) => typeof v === "object" && v !== null && !Array.isArray(v),
  null: (v) => v === null,
};

function validateSchemaBuiltin(
  args: Record<string, unknown>,
  schema: Record<string, unknown>,
): CheckResult | null {
  const properties = (schema.properties as Record<string, Record<string, unknown>>) ?? {};
  const required = (schema.required as string[]) ?? [];

  for (const req of required) {
    if (!(req in args)) {
      return {
        matched: true,
        score: 0.88,
        reason: `Schema validation failed: missing required field '${req}'`,
        matchedText: JSON.stringify(args).slice(0, 80),
      };
    }
  }

  for (const [fname, fval] of Object.entries(args)) {
    if (!(fname in properties)) continue;
    const fschema = properties[fname] ?? {};
    const ftype = fschema.type as string | undefined;

    if (ftype && ftype in TYPE_CHECKERS) {
      if (ftype === "integer" && typeof fval === "boolean") {
        return {
          matched: true,
          score: 0.88,
          reason: `Schema validation failed at '${fname}': expected integer, got boolean`,
          matchedText: String(fval).slice(0, 80),
        };
      }
      const checker = TYPE_CHECKERS[ftype];
      if (checker && !checker(fval)) {
        const actualType = fval === null ? "null" : Array.isArray(fval) ? "array" : typeof fval;
        return {
          matched: true,
          score: 0.88,
          reason: `Schema validation failed at '${fname}': expected ${ftype}, got ${actualType}`,
          matchedText: String(fval).slice(0, 80),
        };
      }
    }

    if (typeof fval === "number") {
      if (typeof fschema.minimum === "number" && fval < fschema.minimum) {
        return {
          matched: true,
          score: 0.88,
          reason: `Schema validation failed at '${fname}': ${fval} < minimum ${fschema.minimum}`,
          matchedText: String(fval),
        };
      }
      if (typeof fschema.maximum === "number" && fval > fschema.maximum) {
        return {
          matched: true,
          score: 0.88,
          reason: `Schema validation failed at '${fname}': ${fval} > maximum ${fschema.maximum}`,
          matchedText: String(fval),
        };
      }
    }

    if (Array.isArray(fschema.enum) && !fschema.enum.includes(fval)) {
      return {
        matched: true,
        score: 0.88,
        reason: `Schema validation failed at '${fname}': '${String(fval)}' not in enum ${JSON.stringify(fschema.enum)}`,
        matchedText: String(fval).slice(0, 80),
      };
    }
  }

  return null;
}

/**
 * Validate tool-call args against a JSON Schema. Uses `ajv` when available for
 * full spec compliance, falling back to a lightweight built-in validator.
 */
function validateSchema(args: Record<string, unknown>, schema: Record<string, unknown>): CheckResult | null {
  if (!schema || Object.keys(schema).length === 0) return null;

  const ajvCtor = tryLoadAjv();
  if (ajvCtor) {
    try {
      const ajv = new ajvCtor({ allErrors: false, strict: false });
      const validateFn = ajv.compile(schema);
      const valid = validateFn(args);
      if (!valid) {
        const err = validateFn.errors?.[0];
        const path = err?.instancePath ? err.instancePath.replace(/^\//, "").replace(/\//g, " -> ") : "root";
        return {
          matched: true,
          score: 0.88,
          reason: `Schema validation failed at '${path}': ${err?.message ?? "invalid"}`,
          matchedText: "",
        };
      }
      return null;
    } catch (exc) {
      return {
        matched: true,
        score: 0.5,
        reason: `Tool schema itself is invalid: ${String((exc as Error).message ?? exc).slice(0, 120)}`,
        matchedText: "",
      };
    }
  }

  return validateSchemaBuiltin(args, schema);
}

let ajvModule: unknown = undefined;
let ajvLoadAttempted = false;

function tryLoadAjv(): (new (options?: Record<string, unknown>) => {
  compile: (schema: Record<string, unknown>) => {
    (data: unknown): boolean;
    errors?: Array<{ instancePath?: string; message?: string }> | null;
  };
}) | null {
  if (!ajvLoadAttempted) {
    ajvLoadAttempted = true;
    try {
      ajvModule = requireOptional("ajv");
    } catch {
      ajvModule = null;
    }
  }
  if (!ajvModule) return null;
  const mod = ajvModule as { default?: unknown };
  return (mod.default ?? ajvModule) as ReturnType<typeof tryLoadAjv>;
}

function extractStringValues(
  args: Record<string, unknown>,
  prefix = "",
  depth = 0,
  maxDepth = 4,
): Array<[string, string]> {
  const results: Array<[string, string]> = [];
  if (depth > maxDepth) return results;

  for (const [k, v] of Object.entries(args)) {
    const key = prefix ? `${prefix}.${k}` : k;
    if (typeof v === "string") {
      results.push([key, v]);
    } else if (v !== null && typeof v === "object" && !Array.isArray(v)) {
      results.push(...extractStringValues(v as Record<string, unknown>, key, depth + 1, maxDepth));
    } else if (Array.isArray(v)) {
      v.forEach((item, i) => {
        const itemKey = `${key}[${i}]`;
        if (typeof item === "string") {
          results.push([itemKey, item]);
        } else if (item !== null && typeof item === "object" && !Array.isArray(item)) {
          results.push(...extractStringValues(item as Record<string, unknown>, itemKey, depth + 1, maxDepth));
        }
      });
    }
  }
  return results;
}

function dedupe(items: string[]): string[] {
  return Array.from(new Set(items));
}

function buildResult(params: {
  allowed: boolean;
  maxScore: number;
  reasons: string[];
  categories: string[];
  checksRun: number;
  toolName: string;
  callId: string | null;
  schemaValidated: boolean;
}): ScanResult {
  return new ScanResult({
    allowed: params.allowed,
    score: round4(params.maxScore),
    reasons: params.reasons,
    guardType: GuardType.TOOL,
    metadata: {
      tool_name: params.toolName,
      call_id: params.callId,
      categories: dedupe(params.categories),
      check_count: params.checksRun,
      schema_validated: params.schemaValidated,
    },
  });
}

export interface ValidateToolCallOptions {
  shortCircuit?: boolean;
}

export function validateToolCall(call: ToolCall, policy: Policy, options: ValidateToolCallOptions = {}): ScanResult {
  const shortCircuit = options.shortCircuit ?? true;

  if (!policy.isGuardEnabled(GuardType.TOOL)) {
    return new ScanResult({
      allowed: true,
      score: 0.0,
      reasons: [],
      guardType: GuardType.TOOL,
      metadata: {
        skipped: true,
        reason: "tool_guard disabled in policy",
        tool_name: call.name,
        call_id: call.callId,
      },
    });
  }

  const blockThreshold = policy.effectiveBlockThreshold(GuardType.TOOL);
  const reasons: string[] = [];
  const categories: string[] = [];
  let maxScore = 0.0;
  let checksRun = 0;
  let schemaValidated = false;

  const record = (result: CheckResult, category: string): boolean => {
    reasons.push(result.reason);
    categories.push(category);
    if (result.score > maxScore) maxScore = result.score;
    return shortCircuit && maxScore >= blockThreshold;
  };

  checksRun += 1;
  const nameResult = checkDenylist(call.name, policy);
  if (nameResult) {
    const cat = nameResult.score === 1.0 ? "denylist_violation" : "allowlist_violation";
    if (record(nameResult, cat)) {
      return buildResult({
        allowed: false,
        maxScore,
        reasons,
        categories,
        checksRun,
        toolName: call.name,
        callId: call.callId,
        schemaValidated,
      });
    }
  }

  checksRun += 1;
  let r = checkInherentlyDangerousName(call.name);
  if (r.matched && record(r, "dangerous_operation")) {
    return buildResult({
      allowed: false,
      maxScore,
      reasons,
      categories,
      checksRun,
      toolName: call.name,
      callId: call.callId,
      schemaValidated,
    });
  }

  checksRun += 1;
  r = checkAdminToolName(call.name);
  if (r.matched && record(r, "dangerous_operation")) {
    return buildResult({
      allowed: false,
      maxScore,
      reasons,
      categories,
      checksRun,
      toolName: call.name,
      callId: call.callId,
      schemaValidated,
    });
  }

  if (call.hasSchema) {
    checksRun += 1;
    schemaValidated = true;
    const schemaResult = validateSchema(call.args, call.schema);
    if (schemaResult && record(schemaResult, "schema_violation")) {
      return buildResult({
        allowed: false,
        maxScore,
        reasons,
        categories,
        checksRun,
        toolName: call.name,
        callId: call.callId,
        schemaValidated,
      });
    }
  }

  for (const [key, value] of extractStringValues(call.args)) {
    for (const [checkFn, category] of ALL_ARG_CHECKS) {
      checksRun += 1;
      const argResult = checkFn(key, value);
      if (argResult.matched && record(argResult, category)) {
        return buildResult({
          allowed: false,
          maxScore,
          reasons,
          categories,
          checksRun,
          toolName: call.name,
          callId: call.callId,
          schemaValidated,
        });
      }
    }
  }

  return buildResult({
    allowed: maxScore < blockThreshold,
    maxScore,
    reasons,
    categories,
    checksRun,
    toolName: call.name,
    callId: call.callId,
    schemaValidated,
  });
}

export function validateToolCalls(calls: ToolCall[], policy: Policy, options: ValidateToolCallOptions = {}): ScanResult[] {
  return calls.map((c) => validateToolCall(c, policy, options));
}

export function aggregateToolScans(results: ScanResult[], policy: Policy): ScanResult {
  if (results.length === 0) {
    return new ScanResult({
      allowed: true,
      score: 0.0,
      reasons: [],
      guardType: GuardType.TOOL,
      metadata: { aggregated: true, source_count: 0 },
    });
  }

  let maxScore = 0.0;
  const allReasons: string[] = [];
  const allCategories: string[] = [];
  const toolNames: string[] = [];

  for (const r of results) {
    if (r.score > maxScore) maxScore = r.score;
    allReasons.push(...r.reasons);
    allCategories.push(...((r.metadata.categories as string[] | undefined) ?? []));
    const name = r.metadata.tool_name as string | undefined;
    if (name) toolNames.push(name);
  }

  const blockThreshold = policy.effectiveBlockThreshold(GuardType.TOOL);

  return new ScanResult({
    allowed: maxScore < blockThreshold,
    score: round4(maxScore),
    reasons: allReasons,
    guardType: GuardType.TOOL,
    metadata: {
      aggregated: true,
      source_count: results.length,
      tool_names: toolNames,
      categories: dedupe(allCategories),
    },
  });
}
