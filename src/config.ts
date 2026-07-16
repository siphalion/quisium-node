/**
 * Config loading: env vars, YAML files, and plain objects, merged and validated
 * into a Policy. Also hosts the process-wide default-policy registry.
 */
import { BalancedPolicy, GuardConfig, Policy, loadPolicyFromDict } from "./policies.js";

export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = new.target.name;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export class ConfigValidationError extends ConfigError {
  readonly errors: string[];

  constructor(errors: string[]) {
    const bulletList = errors.join("\n  - ");
    super(`Config validation failed with ${errors.length} error(s):\n  - ${bulletList}`);
    this.errors = errors;
    this.name = "ConfigValidationError";
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export class ConfigSourceError extends ConfigError {
  constructor(message: string) {
    super(message);
    this.name = "ConfigSourceError";
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

function parseBool(value: string): boolean {
  const normalised = value.trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(normalised)) return true;
  if (["0", "false", "no", "off"].includes(normalised)) return false;
  throw new ConfigValidationError([
    `Cannot parse ${JSON.stringify(value)} as a boolean. Use one of: 1/0, true/false, yes/no, on/off`,
  ]);
}

function parseCsvList(value: string): string[] {
  return value
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

function parseFloat_(value: string): number {
  const n = Number(value);
  if (Number.isNaN(n)) {
    throw new ConfigValidationError([`Cannot parse ${JSON.stringify(value)} as a number.`]);
  }
  return n;
}

const ENV_PREFIX = "LLM_SECURITY_";

type EnvCoerce = (value: string) => unknown;

const ENV_FIELD_MAP: Record<string, [string, EnvCoerce]> = {
  NAME: ["name", (v) => v],
  BLOCK_THRESHOLD: ["block_threshold", parseFloat_],
  WARN_THRESHOLD: ["warn_threshold", parseFloat_],
  RAISE_ON_BLOCK: ["raise_on_block", parseBool],
  REDACT_ON_WARN: ["redact_on_warn", parseBool],
  LOG_CLEAN_REQUESTS: ["log_clean_requests", parseBool],
  ALLOWED_TOOLS: ["allowed_tools", parseCsvList],
  BLOCKED_TOOLS: ["blocked_tools", parseCsvList],
  PROMPT_GUARD_ENABLED: ["_prompt_guard_enabled", parseBool],
  OUTPUT_GUARD_ENABLED: ["_output_guard_enabled", parseBool],
  TOOL_GUARD_ENABLED: ["_tool_guard_enabled", parseBool],
};

const THRESHOLD_FIELDS = ["block_threshold", "warn_threshold"] as const;
const BOOL_FIELDS = ["raise_on_block", "redact_on_warn", "log_clean_requests"] as const;
const GUARD_KEYS = ["prompt_guard", "output_guard", "tool_guard"] as const;
const VALID_GUARD_FIELDS = new Set(["enabled", "block_threshold", "warn_threshold"]);

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function validateConfigDict(data: Record<string, unknown>): void {
  const errors: string[] = [];

  for (const fieldName of THRESHOLD_FIELDS) {
    if (fieldName in data) {
      const val = data[fieldName];
      if (typeof val !== "number") {
        errors.push(`${fieldName} must be a number, got ${typeof val}`);
      } else if (!(val >= 0.0 && val <= 1.0)) {
        errors.push(`${fieldName} must be in [0.0, 1.0], got ${val}`);
      }
    }
  }

  const block = typeof data.block_threshold === "number" ? data.block_threshold : 0.75;
  const warn = typeof data.warn_threshold === "number" ? data.warn_threshold : 0.4;
  if (warn >= block) {
    errors.push(`warn_threshold (${warn}) must be strictly less than block_threshold (${block})`);
  }

  for (const fieldName of BOOL_FIELDS) {
    if (fieldName in data && typeof data[fieldName] !== "boolean") {
      errors.push(`${fieldName} must be a boolean (true/false), got ${typeof data[fieldName]}`);
    }
  }

  if ("name" in data) {
    if (typeof data.name !== "string" || !data.name.trim()) {
      errors.push("name must be a non-empty string");
    }
  }

  if ("allowed_tools" in data && data.allowed_tools !== null && data.allowed_tools !== undefined) {
    const at = data.allowed_tools;
    if (!Array.isArray(at)) {
      errors.push(`allowed_tools must be a list of strings or null, got ${typeof at}`);
    } else if (!at.every((t) => typeof t === "string")) {
      errors.push("allowed_tools must contain only strings");
    }
  }

  if ("blocked_tools" in data) {
    const bt = data.blocked_tools;
    if (!(Array.isArray(bt) || bt instanceof Set)) {
      errors.push(`blocked_tools must be a list or set of strings, got ${typeof bt}`);
    } else {
      const items = Array.isArray(bt) ? bt : Array.from(bt);
      if (!items.every((t) => typeof t === "string")) {
        errors.push("blocked_tools must contain only strings");
      }
    }
  }

  for (const guardKey of GUARD_KEYS) {
    if (!(guardKey in data)) continue;
    const gval = data[guardKey];
    if (gval instanceof GuardConfig) continue;
    if (!isPlainObject(gval)) {
      errors.push(`${guardKey} must be a dict or GuardConfig, got ${typeof gval}`);
      continue;
    }
    const unknown = Object.keys(gval).filter((k) => !VALID_GUARD_FIELDS.has(k));
    for (const uk of unknown.sort()) {
      errors.push(`${guardKey}: unknown field ${JSON.stringify(uk)}`);
    }
    for (const subField of ["block_threshold", "warn_threshold"] as const) {
      if (subField in gval && gval[subField] !== null && gval[subField] !== undefined) {
        const sv = gval[subField];
        if (typeof sv !== "number") {
          errors.push(`${guardKey}.${subField} must be a number, got ${typeof sv}`);
        } else if (!(sv >= 0.0 && sv <= 1.0)) {
          errors.push(`${guardKey}.${subField} must be in [0.0, 1.0], got ${sv}`);
        }
      }
    }
    const gBlock = gval.block_threshold;
    const gWarn = gval.warn_threshold;
    if (
      gBlock !== null &&
      gBlock !== undefined &&
      gWarn !== null &&
      gWarn !== undefined &&
      typeof gBlock === "number" &&
      typeof gWarn === "number" &&
      gWarn >= gBlock
    ) {
      errors.push(
        `${guardKey}.warn_threshold (${gWarn}) must be strictly less than ${guardKey}.block_threshold (${gBlock})`,
      );
    }
  }

  if (errors.length > 0) {
    throw new ConfigValidationError(errors);
  }
}

function resolveEnvOverrides(): Record<string, unknown> {
  const overrides: Record<string, unknown> = {};
  const guardToggles: Record<string, boolean> = {};

  for (const [envSuffix, [fieldName, coerceFn]] of Object.entries(ENV_FIELD_MAP)) {
    const envKey = `${ENV_PREFIX}${envSuffix}`;
    const raw = process.env[envKey];
    if (raw === undefined) continue;

    let value: unknown;
    try {
      value = coerceFn(raw);
    } catch (exc) {
      throw new ConfigValidationError([
        `Environment variable ${envKey}=${JSON.stringify(raw)} is invalid: ${(exc as Error).message}`,
      ]);
    }

    if (fieldName.startsWith("_") && fieldName.endsWith("_enabled")) {
      const guardKey = fieldName.slice(1, -"_enabled".length);
      guardToggles[guardKey] = value as boolean;
    } else {
      overrides[fieldName] = value;
    }
  }

  for (const [guardField, enabled] of Object.entries(guardToggles)) {
    if (!(guardField in overrides)) overrides[guardField] = {};
    const g = overrides[guardField];
    if (isPlainObject(g)) g.enabled = enabled;
  }

  return overrides;
}

function deepMerge(
  base: Record<string, unknown>,
  override: Record<string, unknown>,
): Record<string, unknown> {
  const result: Record<string, unknown> = structuredCloneCompat(base);
  for (const [key, value] of Object.entries(override)) {
    if (isPlainObject(result[key]) && isPlainObject(value)) {
      result[key] = deepMerge(result[key], value);
    } else {
      result[key] = structuredCloneCompat(value);
    }
  }
  return result;
}

function structuredCloneCompat<T>(value: T): T {
  if (value instanceof Set) return new Set(value) as unknown as T;
  if (Array.isArray(value)) return [...value] as unknown as T;
  if (isPlainObject(value)) return { ...value } as unknown as T;
  return value;
}

export interface LoadConfigOptions {
  yamlPath?: string;
  data?: Record<string, unknown>;
  useEnv?: boolean;
  validate?: boolean;
  basePolicy?: Policy;
}

export async function loadConfig(options: LoadConfigOptions = {}): Promise<Policy> {
  const { yamlPath, data, useEnv = true, validate = true, basePolicy } = options;

  let merged: Record<string, unknown> = (basePolicy ?? BalancedPolicy()).toDict() as unknown as Record<
    string,
    unknown
  >;

  if (yamlPath !== undefined) {
    const fs = await import("node:fs");
    if (!fs.existsSync(yamlPath) || !fs.statSync(yamlPath).isFile()) {
      throw new ConfigSourceError(
        `Config YAML file not found: ${JSON.stringify(yamlPath)}. Check the path and ensure the file exists.`,
      );
    }
    let yaml: typeof import("js-yaml");
    try {
      yaml = await import("js-yaml");
    } catch {
      throw new ConfigSourceError(
        "js-yaml is required to load config from YAML. Install it with: npm install js-yaml",
      );
    }

    const raw = fs.readFileSync(yamlPath, "utf-8");
    const fileData = (yaml.load(raw) ?? {}) as unknown;
    if (!isPlainObject(fileData)) {
      throw new ConfigSourceError(
        `YAML file ${JSON.stringify(yamlPath)} must contain a mapping at the top level, got ${typeof fileData}`,
      );
    }
    merged = deepMerge(merged, fileData);
  }

  if (data !== undefined) {
    merged = deepMerge(merged, data);
  }

  if (useEnv) {
    const envOverrides = resolveEnvOverrides();
    if (Object.keys(envOverrides).length > 0) {
      merged = deepMerge(merged, envOverrides);
    }
  }

  if (validate) {
    validateConfigDict(merged);
  }

  return loadPolicyFromDict(merged);
}

let defaultPolicy: Policy | null = null;

export function getDefaultPolicy(): Policy {
  if (defaultPolicy === null) {
    defaultPolicy = BalancedPolicy();
  }
  return defaultPolicy;
}

export function setDefaultPolicy(policy: Policy): void {
  if (!(policy instanceof Policy)) {
    throw new TypeError(`setDefaultPolicy() expects a Policy instance, got ${typeof policy}`);
  }
  defaultPolicy = policy;
}

export function resetDefaultPolicy(): void {
  defaultPolicy = null;
}

export { loadPolicyFromDict, loadPolicyFromYaml } from "./policies.js";
