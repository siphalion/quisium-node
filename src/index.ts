/**
 * Public API surface. Framework-specific middleware (Express) lives under the
 * `quisium/middleware/express` subpath instead of here, so importing this
 * entry point never pulls in `express` as a hard dependency.
 */

export {
  RiskLevel,
  riskLevelFromScore,
  GuardType,
  PolicyAction,
  round4,
  ScanResult,
  GuardDecision,
  ToolCall,
} from "./types.js";
export type {
  ScanResultInit,
  ScanResultDict,
  GuardDecisionInit,
  GuardDecisionDict,
  ToolCallInit,
  ToolCallDict,
} from "./types.js";

export { GuardConfig, Policy, StrictPolicy, BalancedPolicy, LoggingOnlyPolicy, loadPolicyFromDict, loadPolicyFromYaml } from "./policies.js";
export type { GuardConfigInit, PolicyInit, PolicyDict } from "./policies.js";

export {
  ConfigError,
  ConfigValidationError,
  ConfigSourceError,
  validateConfigDict,
  loadConfig,
  getDefaultPolicy,
  setDefaultPolicy,
  resetDefaultPolicy,
} from "./config.js";
export type { LoadConfigOptions } from "./config.js";

export {
  LLMSecurityError,
  BlockedByPolicyError,
  PromptBlockedError,
  OutputBlockedError,
  InvalidToolCallError,
  PolicyNotFoundError,
  ProviderError,
  ProviderTimeoutError,
  GuardError,
} from "./exceptions.js";
export type {
  BlockedByPolicyErrorInit,
  PromptBlockedErrorInit,
  OutputBlockedErrorInit,
  InvalidToolCallErrorInit,
  PolicyNotFoundErrorInit,
  ProviderErrorInit,
  ProviderTimeoutErrorInit,
  GuardErrorInit,
} from "./exceptions.js";

export {
  LogFormat,
  EventType,
  SecurityEvent,
  logDecision,
  logScanResult,
  logToolCall,
  addHandler,
  removeHandler,
  clearHandlers,
  SecurityEventLogger,
} from "./logging.js";
export type {
  SecurityLogger,
  SecurityEventHandler,
  SecurityEventInit,
  SecurityEventDict,
  SecurityEventLoggerInit,
  LogDecisionOptions,
  LogScanResultOptions,
  LogToolCallOptions,
} from "./logging.js";

export { scanPrompt, scanMessages, aggregatePromptScans } from "./guards/prompts.js";
export type { ChatMessageLike, ScanPromptOptions, ScanMessagesOptions } from "./guards/prompts.js";

export { scanOutput, scanAndRedact, redactOutput } from "./guards/outputs.js";
export type { ScanOutputOptions, ScanAndRedactOptions } from "./guards/outputs.js";

export { validateToolCall, validateToolCalls, aggregateToolScans } from "./guards/tools.js";
export type { ValidateToolCallOptions } from "./guards/tools.js";

export { BaseProvider, ProviderConfig } from "./providers/base.js";
export type { ChatMessage, ProviderConfigInit, ChatOptions } from "./providers/base.js";

export { GenericProvider } from "./providers/generic.js";
export type { CallFn, ExtractFn, ExtractToolsFn, GenericProviderInit } from "./providers/generic.js";

// OpenAIProvider is safe to re-export unconditionally: it only touches the
// optional `openai` package lazily inside its constructor, never at module
// load time, so importing this file never requires `openai` to be installed.
export { OpenAIProvider } from "./providers/openai.js";
export type { OpenAIProviderInit } from "./providers/openai.js";
