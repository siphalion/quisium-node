# Changelog

## 0.1.0

Initial Node.js / TypeScript port of the Python [`quisium`](https://github.com/siphalion/quisium) package.

- Full port of the policy engine (`Policy`, `GuardConfig`, presets, dict/YAML/env config loading).
- Full port of the three guards: prompt-injection scanning, output scanning/redaction, tool-call validation.
- Full port of the provider layer: `BaseProvider`, `GenericProvider` (any callable/fetch-based client), `OpenAIProvider` (official `openai` SDK, including streaming).
- New: Express middleware (`quisium/middleware/express`) — `guardRoute`/`quisiumErrorHandler` for per-route guarding, `quisiumMiddleware` for blanket request+response scanning. Replaces the Python package's FastAPI/Flask integrations, which have no Node equivalent target in this port.
- Structured security-event logging with a pluggable handler registry.
- Published as dual ESM/CJS with full TypeScript types; `openai`, `js-yaml`, `ajv`, and `express` are optional peer dependencies — the core package has zero required runtime dependencies.
- 1,486 tests ported from the Python pytest suite to vitest.
