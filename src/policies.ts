/**
 * The Policy engine: GuardConfig, Policy, built-in presets, and dict/YAML loaders.
 *
 * A Policy is the single configuration object that controls the entire security
 * pipeline. Every guard, every provider, every middleware reads from it.
 */
import { GuardType, PolicyAction } from "./types.js";

export interface GuardConfigInit {
  enabled?: boolean;
  blockThreshold?: number | null;
  warnThreshold?: number | null;
}

export class GuardConfig {
  readonly enabled: boolean;
  readonly blockThreshold: number | null;
  readonly warnThreshold: number | null;

  constructor(init: GuardConfigInit = {}) {
    this.enabled = init.enabled ?? true;
    this.blockThreshold = init.blockThreshold ?? null;
    this.warnThreshold = init.warnThreshold ?? null;

    for (const [value, label] of [
      [this.blockThreshold, "blockThreshold"],
      [this.warnThreshold, "warnThreshold"],
    ] as const) {
      if (value !== null && !(value >= 0.0 && value <= 1.0)) {
        throw new RangeError(`GuardConfig.${label} must be in [0.0, 1.0], got ${value}`);
      }
    }
    if (
      this.blockThreshold !== null &&
      this.warnThreshold !== null &&
      this.warnThreshold >= this.blockThreshold
    ) {
      throw new RangeError(
        "GuardConfig.warnThreshold must be strictly less than blockThreshold. " +
          `Got warn=${this.warnThreshold}, block=${this.blockThreshold}`,
      );
    }
  }
}

export interface PolicyInit {
  name?: string;
  blockThreshold?: number;
  warnThreshold?: number;
  raiseOnBlock?: boolean;
  promptGuard?: GuardConfig;
  outputGuard?: GuardConfig;
  toolGuard?: GuardConfig;
  allowedTools?: string[] | null;
  blockedTools?: Set<string> | string[];
  redactOnWarn?: boolean;
  logCleanRequests?: boolean;
  metadata?: Record<string, unknown>;
}

export interface PolicyDict {
  name: string;
  block_threshold: number;
  warn_threshold: number;
  raise_on_block: boolean;
  prompt_guard: { enabled: boolean; block_threshold: number | null; warn_threshold: number | null };
  output_guard: { enabled: boolean; block_threshold: number | null; warn_threshold: number | null };
  tool_guard: { enabled: boolean; block_threshold: number | null; warn_threshold: number | null };
  allowed_tools: string[] | null;
  blocked_tools: string[];
  redact_on_warn: boolean;
  log_clean_requests: boolean;
  metadata: Record<string, unknown>;
}

const POLICY_FIELDS = [
  "name",
  "blockThreshold",
  "warnThreshold",
  "raiseOnBlock",
  "promptGuard",
  "outputGuard",
  "toolGuard",
  "allowedTools",
  "blockedTools",
  "redactOnWarn",
  "logCleanRequests",
  "metadata",
] as const;

/** The single configuration object that controls the entire security pipeline. */
export class Policy {
  readonly name: string;
  readonly blockThreshold: number;
  readonly warnThreshold: number;
  readonly raiseOnBlock: boolean;
  readonly promptGuard: GuardConfig;
  readonly outputGuard: GuardConfig;
  readonly toolGuard: GuardConfig;
  readonly allowedTools: string[] | null;
  readonly blockedTools: Set<string>;
  readonly redactOnWarn: boolean;
  readonly logCleanRequests: boolean;
  readonly metadata: Record<string, unknown>;

  constructor(init: PolicyInit = {}) {
    this.name = init.name ?? "default";
    this.blockThreshold = init.blockThreshold ?? 0.75;
    this.warnThreshold = init.warnThreshold ?? 0.4;
    this.raiseOnBlock = init.raiseOnBlock ?? true;
    this.promptGuard = init.promptGuard ?? new GuardConfig();
    this.outputGuard = init.outputGuard ?? new GuardConfig();
    this.toolGuard = init.toolGuard ?? new GuardConfig();
    this.redactOnWarn = init.redactOnWarn ?? true;
    this.logCleanRequests = init.logCleanRequests ?? false;
    this.metadata = init.metadata ?? {};

    if (!(this.blockThreshold >= 0.0 && this.blockThreshold <= 1.0)) {
      throw new RangeError(
        `Policy.blockThreshold must be in [0.0, 1.0], got ${this.blockThreshold}`,
      );
    }
    if (!(this.warnThreshold >= 0.0 && this.warnThreshold <= 1.0)) {
      throw new RangeError(`Policy.warnThreshold must be in [0.0, 1.0], got ${this.warnThreshold}`);
    }
    if (this.warnThreshold >= this.blockThreshold) {
      throw new RangeError(
        "Policy.warnThreshold must be strictly less than blockThreshold. " +
          `Got warn=${this.warnThreshold}, block=${this.blockThreshold}`,
      );
    }
    if (!this.name || !this.name.trim()) {
      throw new Error("Policy.name must be a non-empty string.");
    }

    this.allowedTools =
      init.allowedTools == null ? null : init.allowedTools.map((t) => t.toLowerCase().trim());

    const rawBlocked = init.blockedTools ?? new Set<string>();
    this.blockedTools = new Set(
      Array.from(rawBlocked, (t) => t.toLowerCase().trim()),
    );
  }

  effectiveBlockThreshold(guard: GuardType): number {
    const cfg = this.guardConfig(guard);
    return cfg.blockThreshold ?? this.blockThreshold;
  }

  effectiveWarnThreshold(guard: GuardType): number {
    const cfg = this.guardConfig(guard);
    return cfg.warnThreshold ?? this.warnThreshold;
  }

  isGuardEnabled(guard: GuardType): boolean {
    return this.guardConfig(guard).enabled;
  }

  private guardConfig(guard: GuardType): GuardConfig {
    switch (guard) {
      case GuardType.PROMPT:
        return this.promptGuard;
      case GuardType.OUTPUT:
        return this.outputGuard;
      case GuardType.TOOL:
        return this.toolGuard;
      default:
        throw new Error(`Unknown guard type: ${guard as string}`);
    }
  }

  isToolAllowed(toolName: string): boolean {
    const normalised = toolName.toLowerCase().trim();
    if (this.blockedTools.has(normalised)) return false;
    if (this.allowedTools === null) return true;
    return this.allowedTools.includes(normalised);
  }

  actionForScore(score: number, guard: GuardType): PolicyAction {
    if (score >= this.effectiveBlockThreshold(guard)) return PolicyAction.BLOCK;
    if (score >= this.effectiveWarnThreshold(guard)) return PolicyAction.WARN;
    return PolicyAction.LOG;
  }

  replace(overrides: Partial<PolicyInit>): Policy {
    const unknown = Object.keys(overrides).filter(
      (k) => !(POLICY_FIELDS as readonly string[]).includes(k),
    );
    if (unknown.length > 0) {
      throw new TypeError(`Policy.replace() got unknown field(s): ${unknown.sort().join(", ")}`);
    }
    const current: PolicyInit = {
      name: this.name,
      blockThreshold: this.blockThreshold,
      warnThreshold: this.warnThreshold,
      raiseOnBlock: this.raiseOnBlock,
      promptGuard: this.promptGuard,
      outputGuard: this.outputGuard,
      toolGuard: this.toolGuard,
      allowedTools: this.allowedTools,
      blockedTools: this.blockedTools,
      redactOnWarn: this.redactOnWarn,
      logCleanRequests: this.logCleanRequests,
      metadata: this.metadata,
    };
    return new Policy({ ...current, ...overrides });
  }

  withAllowedTools(tools: string[]): Policy {
    return this.replace({ allowedTools: tools });
  }

  withBlockedTools(tools: string[]): Policy {
    return this.replace({ blockedTools: new Set(tools) });
  }

  toDict(): PolicyDict {
    return {
      name: this.name,
      block_threshold: this.blockThreshold,
      warn_threshold: this.warnThreshold,
      raise_on_block: this.raiseOnBlock,
      prompt_guard: {
        enabled: this.promptGuard.enabled,
        block_threshold: this.promptGuard.blockThreshold,
        warn_threshold: this.promptGuard.warnThreshold,
      },
      output_guard: {
        enabled: this.outputGuard.enabled,
        block_threshold: this.outputGuard.blockThreshold,
        warn_threshold: this.outputGuard.warnThreshold,
      },
      tool_guard: {
        enabled: this.toolGuard.enabled,
        block_threshold: this.toolGuard.blockThreshold,
        warn_threshold: this.toolGuard.warnThreshold,
      },
      allowed_tools: this.allowedTools,
      blocked_tools: Array.from(this.blockedTools).sort(),
      redact_on_warn: this.redactOnWarn,
      log_clean_requests: this.logCleanRequests,
      metadata: this.metadata,
    };
  }

  toJSON(): PolicyDict {
    return this.toDict();
  }

  toString(): string {
    return (
      `Policy(name=${JSON.stringify(this.name)}, ` +
      `block=${this.blockThreshold}, warn=${this.warnThreshold}, ` +
      `raiseOnBlock=${this.raiseOnBlock})`
    );
  }
}

export function StrictPolicy(overrides: Partial<PolicyInit> = {}): Policy {
  return new Policy({
    name: "strict",
    blockThreshold: 0.4,
    warnThreshold: 0.15,
    raiseOnBlock: true,
    redactOnWarn: true,
    logCleanRequests: true,
    ...overrides,
  });
}

export function BalancedPolicy(overrides: Partial<PolicyInit> = {}): Policy {
  return new Policy({
    name: "balanced",
    blockThreshold: 0.75,
    warnThreshold: 0.4,
    raiseOnBlock: true,
    redactOnWarn: true,
    logCleanRequests: false,
    ...overrides,
  });
}

export function LoggingOnlyPolicy(overrides: Partial<PolicyInit> = {}): Policy {
  return new Policy({
    name: "logging-only",
    blockThreshold: 1.0,
    warnThreshold: 0.99,
    raiseOnBlock: false,
    redactOnWarn: false,
    logCleanRequests: true,
    ...overrides,
  });
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Build a Policy from a plain object using the wire format (snake_case keys,
 * matching Policy.toDict() / YAML policy files).
 */
export function loadPolicyFromDict(data: Record<string, unknown>): Policy {
  const init: PolicyInit = {};

  if (typeof data.name === "string") init.name = data.name;
  if (typeof data.block_threshold === "number") init.blockThreshold = data.block_threshold;
  if (typeof data.warn_threshold === "number") init.warnThreshold = data.warn_threshold;
  if (typeof data.raise_on_block === "boolean") init.raiseOnBlock = data.raise_on_block;
  if (typeof data.redact_on_warn === "boolean") init.redactOnWarn = data.redact_on_warn;
  if (typeof data.log_clean_requests === "boolean") init.logCleanRequests = data.log_clean_requests;

  if ("allowed_tools" in data) {
    const v = data.allowed_tools;
    init.allowedTools = v === null || v === undefined ? null : (v as string[]);
  }
  if ("blocked_tools" in data) {
    const v = data.blocked_tools;
    init.blockedTools = Array.isArray(v) ? new Set(v as string[]) : (v as Set<string>);
  }
  if (isPlainObject(data.metadata)) init.metadata = data.metadata;

  for (const [key, prop] of [
    ["prompt_guard", "promptGuard"],
    ["output_guard", "outputGuard"],
    ["tool_guard", "toolGuard"],
  ] as const) {
    const raw = data[key];
    if (raw instanceof GuardConfig) {
      init[prop] = raw;
    } else if (isPlainObject(raw)) {
      init[prop] = new GuardConfig({
        enabled: raw.enabled as boolean | undefined,
        blockThreshold: (raw.block_threshold ?? null) as number | null,
        warnThreshold: (raw.warn_threshold ?? null) as number | null,
      });
    }
  }

  return new Policy(init);
}

/** Build a Policy from a YAML file. Requires the optional `js-yaml` dependency. */
export async function loadPolicyFromYaml(path: string): Promise<Policy> {
  let yaml: typeof import("js-yaml");
  try {
    yaml = await import("js-yaml");
  } catch (exc) {
    throw new Error(
      "js-yaml is required to load policies from YAML files. Install it with: npm install js-yaml",
      { cause: exc },
    );
  }

  const fs = await import("node:fs");
  if (!fs.existsSync(path) || !fs.statSync(path).isFile()) {
    throw new Error(`Policy YAML file not found: ${JSON.stringify(path)}`);
  }

  const raw = fs.readFileSync(path, "utf-8");
  const data = (yaml.load(raw) ?? {}) as unknown;

  if (!isPlainObject(data)) {
    throw new Error(
      `Policy YAML file must contain a mapping at the top level. Got ${typeof data} in ${JSON.stringify(path)}`,
    );
  }

  return loadPolicyFromDict(data);
}
