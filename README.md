# Quisium (Node)

Production-grade security middleware for LLM calls — prompt injection detection, output validation, and tool-call enforcement.

This is the Node.js / TypeScript port of the Python [`quisium`](https://github.com/siphalion/quisium) package. It sits between your application code and any LLM provider, scanning every prompt before it reaches the model and every response before it reaches your users.

| Property | Value |
|---|---|
| Type | Node package (ESM + CJS, fully typed) |
| Purpose | Security middleware between app code and LLM provider |
| Guards | Prompt injection, unsafe/leaked-credential output, dangerous tool calls |
| Policy engine | Plain object, YAML file, or built-in presets |
| Providers | `OpenAIProvider`, `GenericProvider` (bring your own client/fetch) |
| Framework support | Express |
| Return type | `GuardDecision { allowed, score, reasons, safeOutput }` |
| Runtime deps | Zero — `openai` / `js-yaml` / `ajv` / `express` are optional peer deps |

## Install

```bash
npm install quisium
```

Everything above works with zero extra dependencies. Install the optional peers only for what you actually use:

```bash
npm install openai        # OpenAIProvider
npm install js-yaml       # loadPolicyFromYaml / loadConfig({ yamlPath })
npm install ajv           # full JSON Schema validation for tool-call args (built-in fallback otherwise)
npm install express       # quisium/middleware/express
```

## Quick start

```ts
import { GenericProvider, BalancedPolicy, PromptBlockedError } from "quisium";

const provider = new GenericProvider({
  callFn: async (messages) => myLLMClient.complete(messages),
  extractFn: (response) => response.text,
  policy: BalancedPolicy(),
});

try {
  const decision = await provider.chat([{ role: "user", content: userInput }]);
  console.log(decision.safeOutput);
} catch (err) {
  if (err instanceof PromptBlockedError) {
    // err.reasons, err.score, err.decision
  }
}
```

Every guarded call runs a six-stage pipeline: scan the prompt → decide (block / warn / allow) → forward to the model → scan the response → scan any tool calls → return a `GuardDecision` with the full audit trail (`decision.scanResults`). If a stage exceeds the policy's block threshold, the pipeline short-circuits — the model is never called for a blocked prompt, and a blocked response never reaches your application.

## Policies

A `Policy` is the single configuration object every guard and provider reads from.

```ts
import { StrictPolicy, BalancedPolicy, LoggingOnlyPolicy, Policy, GuardConfig } from "quisium";

StrictPolicy();       // block=0.40, warn=0.15 — production, sensitive apps
BalancedPolicy();      // block=0.75, warn=0.40 — default, standard apps
LoggingOnlyPolicy();   // never blocks — logs only, good for dev/staging

BalancedPolicy({ allowedTools: ["search_web", "read_file"], raiseOnBlock: false });

new Policy({
  name: "custom",
  blockThreshold: 0.6,
  warnThreshold: 0.3,
  toolGuard: new GuardConfig({ blockThreshold: 0.5 }), // per-guard threshold override
});
```

Load one from a plain object or YAML (requires `js-yaml`):

```ts
import { loadPolicyFromDict, loadPolicyFromYaml } from "quisium";

const policy = loadPolicyFromDict({ block_threshold: 0.8, allowed_tools: ["read_file"] });
const policyFromFile = await loadPolicyFromYaml("policies/production.yaml"); // async — reads a file + optional dep
```

Note: `loadPolicyFromDict`/`loadPolicyFromYaml`/`.toDict()` intentionally use **snake_case** keys — that's the wire format shared with the Python package's YAML/JSON policy files, so a policy file written for either package loads in both. Everything else in the TS API (class properties, method names) is camelCase.

`loadConfig({ yamlPath, data, useEnv, basePolicy })` layers a base policy, a YAML file, a plain object, and `LLM_SECURITY_*` environment variables (in that precedence order) into one validated `Policy`.

## Guards

The three guards can be used directly if you want to build your own pipeline instead of going through a provider:

```ts
import { scanPrompt, scanAndRedact, validateToolCall, BalancedPolicy, ToolCall } from "quisium";

const policy = BalancedPolicy();

scanPrompt("Ignore all previous instructions...", policy);
// -> { allowed: false, score: 0.92, reasons: ["Direct instruction override detected..."] }

scanAndRedact("your key is sk-abc123...", policy);
// -> { allowed: false, safeOutput: "your key is [REDACTED:CREDENTIAL_LEAK]", reasons: [...] }

validateToolCall(new ToolCall({ name: "delete_all", args: {} }), policy);
// -> { allowed: false, reasons: ["Tool name 'delete_all' is inherently dangerous..."] }
```

| Guard | Detects | Default action |
|---|---|---|
| `scanPrompt` / `scanMessages` | Injection, jailbreaks (DAN, persona-switching), context exfiltration, base64/unicode/zero-width obfuscation, token flooding | Block or warn |
| `scanOutput` / `scanAndRedact` | API keys/JWTs/SSH keys, OS commands, SSRF-adjacent content, SSNs/credit cards, malware/ransomware indicators, self-harm/violence instructions | Redact + warn, or block |
| `validateToolCall` | Allowlist/denylist, JSON-Schema argument validation, path traversal, SSRF, command/SQL injection in args, inherently dangerous tool names | Block |

## Providers

`OpenAIProvider` wraps the official `openai` SDK and runs the full guard pipeline around every call, including streaming:

```ts
import { OpenAIProvider } from "quisium";

const provider = new OpenAIProvider({ model: "gpt-4o", policy: BalancedPolicy() });

const decision = await provider.chat([{ role: "user", content: "Summarize this doc." }]);

// Streaming
const stream = provider.streamChat([{ role: "user", content: "Tell me a story." }]);
for await (const chunk of stream) process.stdout.write(chunk);
```

`GenericProvider` wraps any callable — your own SDK, a raw `fetch`, anything:

```ts
import { GenericProvider } from "quisium";

const provider = GenericProvider.fromOpenAiCompatibleUrl({
  url: "https://api.example.com/v1/chat/completions",
  model: "my-model",
  apiKey: process.env.MY_API_KEY,
});
```

## Express middleware

```ts
import express from "express";
import { guardRoute, quisiumErrorHandler, quisiumMiddleware } from "quisium/middleware/express";
import { BalancedPolicy } from "quisium";

const app = express();
app.use(express.json());

// Per-route: scans the request, attaches req.quisiumDecision, and calls next(err) on block
app.post("/chat", guardRoute({ policy: BalancedPolicy() }), (req, res) => {
  res.json({ reply: "..." });
});
app.use(quisiumErrorHandler()); // renders PromptBlockedError/OutputBlockedError as JSON

// Or blanket: scans matching paths' request AND response bodies, blocks/redacts directly
app.use(quisiumMiddleware({ policy: BalancedPolicy(), scanPaths: ["/chat", "/api"] }));
```

`quisiumMiddleware` requires `express.json()` mounted upstream — it reads `req.body`, it does not parse raw bytes itself.

## Logging

```ts
import { SecurityEventLogger, addHandler } from "quisium";

addHandler((event) => sendToDatadog(event.toDict()));

const logger = new SecurityEventLogger({ policy, providerName: "openai" });
logger.logDecision(decision, { durationMs: 42 });
```

## Public API surface

```ts
import {
  // Providers
  OpenAIProvider, GenericProvider, BaseProvider, ProviderConfig,
  // Policies
  Policy, GuardConfig, StrictPolicy, BalancedPolicy, LoggingOnlyPolicy,
  loadPolicyFromDict, loadPolicyFromYaml,
  // Config
  loadConfig, getDefaultPolicy, setDefaultPolicy, resetDefaultPolicy,
  // Guards
  scanPrompt, scanMessages, aggregatePromptScans,
  scanOutput, scanAndRedact, redactOutput,
  validateToolCall, validateToolCalls, aggregateToolScans,
  // Types
  ScanResult, GuardDecision, ToolCall, RiskLevel, GuardType, PolicyAction,
  // Exceptions
  LLMSecurityError, BlockedByPolicyError, PromptBlockedError, OutputBlockedError,
  InvalidToolCallError, PolicyNotFoundError, ProviderError, ProviderTimeoutError, GuardError,
  // Logging
  SecurityEventLogger, SecurityEvent, logDecision, logScanResult, logToolCall,
  addHandler, removeHandler, clearHandlers,
} from "quisium";
```

`quisium/middleware/express` is a separate subpath so importing the main package never requires `express` to be installed.

## Development

```bash
npm install
npm run build       # tsup -> dist/ (ESM + CJS + .d.ts)
npm run typecheck    # tsc --noEmit
npm test             # vitest run
npm run lint         # eslint
```

## License

BSD-3-Clause
