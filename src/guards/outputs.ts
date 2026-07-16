/**
 * Output / content guard. Runs on every model response before it reaches the
 * application. Can optionally redact sensitive material rather than blocking
 * outright.
 */
import type { Policy } from "../policies.js";
import { GuardType, ScanResult, round4 } from "../types.js";

interface CheckResult {
  matched: boolean;
  score: number;
  reason: string;
  matchedText: string;
  redactSpans: Array<[number, number]>;
}

const NO_MATCH: CheckResult = { matched: false, score: 0.0, reason: "", matchedText: "", redactSpans: [] };
const FLAGS = "is"; // IGNORECASE | DOTALL

const RE_OPENAI_KEY = /\bsk-[A-Za-z0-9]{20,60}\b/g;
const RE_ANTHROPIC_KEY = /\bsk-ant-[A-Za-z0-9\-_]{20,80}\b/g;
const RE_GITHUB_TOKEN = /\bgh[pousr]_[A-Za-z0-9]{30,}\b/g;
const RE_AWS_KEY = /\bAKIA[0-9A-Z]{16}\b/g;
const RE_AWS_SECRET = /aws.{0,20}secret.{0,20}['"]?([A-Za-z0-9/+=]{40})\b/gid;
const RE_GOOGLE_KEY = /\bAIza[0-9A-Za-z\-_]{35}\b/g;
const RE_STRIPE_KEY = /\b(sk|pk)_(test|live)_[0-9a-zA-Z]{24,}\b/g;
const RE_SLACK_TOKEN = /\bxox[bpoa]-[0-9A-Za-z\-]{10,50}\b/g;
const RE_GENERIC_API_KEY =
  /(api[_\-\s]?key|apikey|api[_\-\s]?secret|access[_\-\s]?key)\s*[:=]\s*['"]?([A-Za-z0-9\-_.]{16,64})['"]?/gi;

const RE_JWT = /\beyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\b/g;

const RE_SSH_PRIVATE_KEY = /-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/i;

const RE_GENERIC_PASSWORD = /(password|passwd|secret|token|credential|auth_token|bearer)\s*[:=]\s*['"]([^'"]{8,})['"]/gi;

// Verbose Python patterns flattened (whitespace/comments stripped) to plain JS regex source.
const RE_DESTRUCTIVE_CMD = new RegExp(
  "(rm\\s+-[rf]{1,2}[f r]*\\s+[/~]" +
    "|rm\\s+--no-preserve-root\\s+/" +
    "|mkfs\\.[a-z0-9]+\\s+/dev/" +
    "|dd\\s+.*of=/dev/[sh]d" +
    "|:()\\{:" +
    "|:\\s*\\(\\s*\\)\\s*\\{" +
    "|shutdown\\s+(-[rh]\\s+)?now" +
    "|halt\\b" +
    "|poweroff\\b" +
    "|format\\s+[cCdDeEfF]:\\s*/?)",
  "i",
);

const RE_NETWORK_RECON = new RegExp(
  "(nmap\\s+(-[a-zA-Z0-9]+\\s+)*[0-9./]+" +
    "|masscan\\s+" +
    "|(netcat|nc)\\s+(-[a-zA-Z]+\\s+)*\\d+\\.\\d+" +
    "|(curl|wget)\\s+.*(-O\\s+|--output\\s+)" +
    "|sqlmap\\s+" +
    "|hydra\\s+" +
    "|metasploit|msfconsole|msfvenom)",
  "i",
);

const RE_PRIVILEGE_ESCALATION = new RegExp(
  "(sudo\\s+(su|bash|sh|zsh|fish|-i)" +
    "|sudo\\s+chmod\\s+[0-7]*7[0-7]*\\s+/" +
    "|chmod\\s+[uo]\\+s\\s+" +
    "|/etc/passwd\\s*<<" +
    "|echo\\s+.*>>\\s*/etc/passwd" +
    "|visudo\\s*;?\\s*echo)",
  "i",
);

const RE_SSN = /\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g;

const RE_CREDIT_CARD =
  /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b/g;

const RE_SHELLCODE_PATTERN = /\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){7,}/;

const RE_RANSOMWARE_KEYWORDS = new RegExp(
  "(encrypt\\s+(all|your|the|every|each)\\s+(files?|documents?|data|disk)" +
    "|(AES|RSA|Salsa20|ChaCha20)\\s+encrypt.{0,40}(ransom|bitcoin|payment)" +
    "|your\\s+files\\s+have\\s+been\\s+encrypted" +
    "|(pay|send)\\s+.{0,30}(bitcoin|btc|monero|xmr).{0,30}(decrypt|restore|recover)" +
    "|bitcoin\\s+wallet\\s+address\\s*:)",
  "i",
);

const RE_REVERSE_SHELL = new RegExp(
  "(bash\\s+-i\\s+>&?\\s*/dev/tcp/" +
    "|python[23]?\\s+-c\\s+['\"]\\s*import\\s+socket" +
    "|nc\\s+(-e\\s+/bin/(sh|bash)|--exec)" +
    "|perl\\s+-e\\s+['\"]\\s*use\\s+Socket" +
    "|php\\s+-r\\s+['\"]\\s*\\$sock\\s*=" +
    "|powershell.{0,30}New-Object.{0,30}Net\\.Sockets)",
  "i",
);

const RE_SELF_HARM_INSTRUCTIONS = new RegExp(
  "((step[s\\-\\s]+(by[- ]step\\s+)?(instructions?|guide|method|way)\\s+to\\s+" +
    "(kill|harm|hurt|injure|end\\s+your\\s+life|commit\\s+suicide|self[- ]harm))" +
    "|(how\\s+to\\s+(overdose|hang\\s+yourself|slit\\s+your\\s+wrists|jump\\s+from))" +
    "|(lethal\\s+dose\\s+of.{0,60}(mg|milligrams?|pills?|tablets?)))",
  "i",
);

const RE_VIOLENCE_INSTRUCTIONS = new RegExp(
  "((step[- ]by[- ]step|detailed?\\s+instructions?)\\s+(for|to|on\\s+how\\s+to)\\s+" +
    "(make|build|construct|assemble|create|synthesize|manufacture)\\s+" +
    "(a\\s+)?(bomb|explosive|weapon|poison|toxin|nerve\\s+agent|IED)" +
    "|(synthesis|production|manufacture)\\s+of\\s+" +
    "(sarin|VX|novichok|ricin|anthrax|botulinum))",
  "i",
);

const RE_SYSTEM_PROMPT_ECHO = new RegExp(
  "(my\\s+system\\s+prompt\\s+(is|says?|reads?|contains?)|" +
    "my\\s+(hidden\\s+|secret\\s+|original\\s+)?instructions?\\s+(are|say|read|contain)|" +
    "i\\s+(was\\s+)?instructed\\s+to\\s+(keep|not\\s+reveal|hide|conceal))",
  FLAGS,
);

const RE_INJECTION_ECHO = new RegExp(
  "(ignore\\s+(all\\s+)?previous\\s+instructions?|" +
    "you\\s+are\\s+now\\s+(DAN|in\\s+developer\\s+mode)|" +
    "as\\s+DAN[,\\s])",
  FLAGS,
);

function spansOf(re: RegExp, text: string): Array<[number, number]> {
  const spans: Array<[number, number]> = [];
  for (const m of text.matchAll(re)) {
    spans.push([m.index ?? 0, (m.index ?? 0) + m[0].length]);
  }
  return spans;
}

function checkOpenAiKey(text: string): CheckResult {
  const spans = spansOf(RE_OPENAI_KEY, text);
  if (spans.length === 0) return NO_MATCH;
  return {
    matched: true,
    score: 0.95,
    reason: `OpenAI API key detected in output (${spans.length} occurrence(s))`,
    matchedText: "sk-...[redacted]",
    redactSpans: spans,
  };
}

function checkAnthropicKey(text: string): CheckResult {
  const spans = spansOf(RE_ANTHROPIC_KEY, text);
  if (spans.length === 0) return NO_MATCH;
  return {
    matched: true,
    score: 0.95,
    reason: `Anthropic API key detected in output (${spans.length} occurrence(s))`,
    matchedText: "sk-ant-...[redacted]",
    redactSpans: spans,
  };
}

function checkGithubToken(text: string): CheckResult {
  const spans = spansOf(RE_GITHUB_TOKEN, text);
  if (spans.length === 0) return NO_MATCH;
  return {
    matched: true,
    score: 0.95,
    reason: `GitHub token detected in output (${spans.length} occurrence(s))`,
    matchedText: "gh...[redacted]",
    redactSpans: spans,
  };
}

function checkAwsCredentials(text: string): CheckResult {
  const keySpans = spansOf(RE_AWS_KEY, text);
  const secSpans: Array<[number, number]> = [];
  for (const m of text.matchAll(RE_AWS_SECRET)) {
    const indices = (m as RegExpMatchArray & { indices?: Array<[number, number] | undefined> }).indices;
    const group1Span = indices?.[1];
    if (group1Span) secSpans.push([group1Span[0], group1Span[1]]);
  }
  const allSpans = [...keySpans, ...secSpans];
  if (allSpans.length === 0) return NO_MATCH;
  return {
    matched: true,
    score: 0.97,
    reason: `AWS credentials detected in output (${allSpans.length} occurrence(s))`,
    matchedText: "AKIA...[redacted]",
    redactSpans: allSpans,
  };
}

function checkGoogleKey(text: string): CheckResult {
  const spans = spansOf(RE_GOOGLE_KEY, text);
  if (spans.length === 0) return NO_MATCH;
  return {
    matched: true,
    score: 0.95,
    reason: `Google API key detected in output (${spans.length} occurrence(s))`,
    matchedText: "AIza...[redacted]",
    redactSpans: spans,
  };
}

function checkStripeKey(text: string): CheckResult {
  const spans = spansOf(RE_STRIPE_KEY, text);
  if (spans.length === 0) return NO_MATCH;
  return {
    matched: true,
    score: 0.95,
    reason: `Stripe API key detected in output (${spans.length} occurrence(s))`,
    matchedText: "sk_...[redacted]",
    redactSpans: spans,
  };
}

function checkSlackToken(text: string): CheckResult {
  const spans = spansOf(RE_SLACK_TOKEN, text);
  if (spans.length === 0) return NO_MATCH;
  return {
    matched: true,
    score: 0.93,
    reason: `Slack token detected in output (${spans.length} occurrence(s))`,
    matchedText: "xox...[redacted]",
    redactSpans: spans,
  };
}

function checkGenericApiKey(text: string): CheckResult {
  const spans = spansOf(RE_GENERIC_API_KEY, text);
  if (spans.length === 0) return NO_MATCH;
  return {
    matched: true,
    score: 0.85,
    reason: `Generic API key assignment detected (${spans.length} occurrence(s))`,
    matchedText: "api_key=...[redacted]",
    redactSpans: spans,
  };
}

function checkJwt(text: string): CheckResult {
  const spans = spansOf(RE_JWT, text);
  if (spans.length === 0) return NO_MATCH;
  return {
    matched: true,
    score: 0.9,
    reason: `JWT token detected in output (${spans.length} occurrence(s))`,
    matchedText: "eyJ...[redacted]",
    redactSpans: spans,
  };
}

function checkSshPrivateKey(text: string): CheckResult {
  const m = RE_SSH_PRIVATE_KEY.exec(text);
  if (!m) return NO_MATCH;
  return {
    matched: true,
    score: 0.98,
    reason: "SSH/TLS private key block detected in output",
    matchedText: "-----BEGIN PRIVATE KEY-----[redacted]",
    redactSpans: [[m.index, text.length]],
  };
}

function checkGenericPassword(text: string): CheckResult {
  const spans = spansOf(RE_GENERIC_PASSWORD, text);
  if (spans.length === 0) return NO_MATCH;
  return {
    matched: true,
    score: 0.88,
    reason: `Password/secret assignment detected (${spans.length} occurrence(s))`,
    matchedText: "password=...[redacted]",
    redactSpans: spans,
  };
}

function checkDestructiveCommand(text: string): CheckResult {
  const m = RE_DESTRUCTIVE_CMD.exec(text);
  if (!m) return NO_MATCH;
  return {
    matched: true,
    score: 0.95,
    reason: `Destructive OS command detected: '${m[0].trim().slice(0, 60)}'`,
    matchedText: m[0].trim().slice(0, 60),
    redactSpans: [],
  };
}

function checkNetworkRecon(text: string): CheckResult {
  const m = RE_NETWORK_RECON.exec(text);
  if (!m) return NO_MATCH;
  return {
    matched: true,
    score: 0.82,
    reason: `Network recon/exploit tool usage detected: '${m[0].trim().slice(0, 60)}'`,
    matchedText: m[0].trim().slice(0, 60),
    redactSpans: [],
  };
}

function checkPrivilegeEscalation(text: string): CheckResult {
  const m = RE_PRIVILEGE_ESCALATION.exec(text);
  if (!m) return NO_MATCH;
  return {
    matched: true,
    score: 0.88,
    reason: `Privilege escalation command detected: '${m[0].trim().slice(0, 60)}'`,
    matchedText: m[0].trim().slice(0, 60),
    redactSpans: [],
  };
}

function checkSsn(text: string): CheckResult {
  const spans = spansOf(RE_SSN, text);
  if (spans.length === 0) return NO_MATCH;
  return {
    matched: true,
    score: 0.9,
    reason: `Social Security Number detected (${spans.length} occurrence(s))`,
    matchedText: "XXX-XX-XXXX[redacted]",
    redactSpans: spans,
  };
}

function checkCreditCard(text: string): CheckResult {
  const spans = spansOf(RE_CREDIT_CARD, text);
  if (spans.length === 0) return NO_MATCH;
  return {
    matched: true,
    score: 0.92,
    reason: `Credit card number detected (${spans.length} occurrence(s))`,
    matchedText: "XXXX-XXXX-XXXX-XXXX[redacted]",
    redactSpans: spans,
  };
}

function checkShellcode(text: string): CheckResult {
  const m = RE_SHELLCODE_PATTERN.exec(text);
  if (!m) return NO_MATCH;
  return {
    matched: true,
    score: 0.9,
    reason: "Shellcode byte sequence detected in output",
    matchedText: `${m[0].slice(0, 40)}...`,
    redactSpans: [],
  };
}

function checkRansomware(text: string): CheckResult {
  const m = RE_RANSOMWARE_KEYWORDS.exec(text);
  if (!m) return NO_MATCH;
  return {
    matched: true,
    score: 0.95,
    reason: `Ransomware indicator detected: '${m[0].trim().slice(0, 60)}'`,
    matchedText: m[0].trim().slice(0, 60),
    redactSpans: [],
  };
}

function checkReverseShell(text: string): CheckResult {
  const m = RE_REVERSE_SHELL.exec(text);
  if (!m) return NO_MATCH;
  return {
    matched: true,
    score: 0.97,
    reason: `Reverse shell payload detected: '${m[0].trim().slice(0, 60)}'`,
    matchedText: m[0].trim().slice(0, 60),
    redactSpans: [],
  };
}

function checkSelfHarmInstructions(text: string): CheckResult {
  const m = RE_SELF_HARM_INSTRUCTIONS.exec(text);
  if (!m) return NO_MATCH;
  return {
    matched: true,
    score: 0.98,
    reason: "Self-harm instructions detected in output",
    matchedText: "[self-harm content detected]",
    redactSpans: [],
  };
}

function checkViolenceInstructions(text: string): CheckResult {
  const m = RE_VIOLENCE_INSTRUCTIONS.exec(text);
  if (!m) return NO_MATCH;
  return {
    matched: true,
    score: 0.98,
    reason: `Weapon/dangerous substance instructions detected: '${m[0].trim().slice(0, 60)}'`,
    matchedText: m[0].trim().slice(0, 60),
    redactSpans: [],
  };
}

function checkSystemPromptEcho(text: string): CheckResult {
  const m = RE_SYSTEM_PROMPT_ECHO.exec(text);
  if (!m) return NO_MATCH;
  return {
    matched: true,
    score: 0.8,
    reason: `Model appears to be echoing system prompt content: '${m[0].trim().slice(0, 60)}'`,
    matchedText: m[0].trim().slice(0, 60),
    redactSpans: [],
  };
}

function checkInjectionEcho(text: string): CheckResult {
  const m = RE_INJECTION_ECHO.exec(text);
  if (!m) return NO_MATCH;
  return {
    matched: true,
    score: 0.85,
    reason: `Model is echoing injection content: '${m[0].trim().slice(0, 60)}'`,
    matchedText: m[0].trim().slice(0, 60),
    redactSpans: [],
  };
}

type CheckFn = (text: string) => CheckResult;

const ALL_CHECKS: Array<[CheckFn, string]> = [
  // Credential leaks — highest priority, always redact
  [checkOpenAiKey, "credential_leak"],
  [checkAnthropicKey, "credential_leak"],
  [checkGithubToken, "credential_leak"],
  [checkAwsCredentials, "credential_leak"],
  [checkGoogleKey, "credential_leak"],
  [checkStripeKey, "credential_leak"],
  [checkSlackToken, "credential_leak"],
  [checkGenericApiKey, "credential_leak"],
  [checkJwt, "credential_leak"],
  [checkSshPrivateKey, "credential_leak"],
  [checkGenericPassword, "credential_leak"],
  // OS commands
  [checkDestructiveCommand, "os_command"],
  [checkNetworkRecon, "os_command"],
  [checkPrivilegeEscalation, "os_command"],
  // Sensitive / PII
  [checkSsn, "sensitive_data"],
  [checkCreditCard, "sensitive_data"],
  // Malware
  [checkShellcode, "malware_indicator"],
  [checkRansomware, "malware_indicator"],
  [checkReverseShell, "malware_indicator"],
  // Harmful content
  [checkSelfHarmInstructions, "harmful_content"],
  [checkViolenceInstructions, "harmful_content"],
  // Exfiltration / echo
  [checkSystemPromptEcho, "data_exfiltration"],
  [checkInjectionEcho, "injection_echo"],
];

function dedupe(items: string[]): string[] {
  return Array.from(new Set(items));
}

function applyRedactions(text: string, redactionMap: Map<string, Array<[number, number]>>): string {
  const allSpans: Array<[number, number, string]> = [];
  for (const [category, spans] of redactionMap) {
    for (const [start, end] of spans) {
      allSpans.push([start, end, category]);
    }
  }
  allSpans.sort((a, b) => b[0] - a[0]);

  let result = text;
  for (const [start, end, category] of allSpans) {
    const placeholder = `[REDACTED:${category.toUpperCase()}]`;
    result = result.slice(0, start) + placeholder + result.slice(end);
  }
  return result;
}

export interface ScanOutputOptions {
  shortCircuit?: boolean;
}

export function scanOutput(text: string, policy: Policy, options: ScanOutputOptions = {}): ScanResult {
  const shortCircuit = options.shortCircuit ?? true;

  if (!policy.isGuardEnabled(GuardType.OUTPUT)) {
    return new ScanResult({
      allowed: true,
      score: 0.0,
      reasons: [],
      guardType: GuardType.OUTPUT,
      metadata: { skipped: true, reason: "output_guard disabled in policy" },
    });
  }

  if (!text || !text.trim()) {
    return new ScanResult({
      allowed: true,
      score: 0.0,
      reasons: [],
      guardType: GuardType.OUTPUT,
      metadata: { skipped: true, reason: "empty output" },
    });
  }

  const blockThreshold = policy.effectiveBlockThreshold(GuardType.OUTPUT);

  const reasons: string[] = [];
  const categories: string[] = [];
  const redactionMap = new Map<string, Array<[number, number]>>();
  let maxScore = 0.0;
  let checksRun = 0;

  for (const [checkFn, category] of ALL_CHECKS) {
    checksRun += 1;
    const result = checkFn(text);

    if (result.matched) {
      reasons.push(result.reason);
      categories.push(category);
      if (result.score > maxScore) maxScore = result.score;
      if (result.redactSpans.length > 0) {
        const existing = redactionMap.get(category) ?? [];
        redactionMap.set(category, [...existing, ...result.redactSpans]);
      }

      if (shortCircuit && maxScore >= blockThreshold) break;
    }
  }

  const allowed = maxScore < blockThreshold;

  return new ScanResult({
    allowed,
    score: round4(maxScore),
    reasons,
    safeOutput: null,
    guardType: GuardType.OUTPUT,
    metadata: {
      categories: dedupe(categories),
      check_count: checksRun,
      total_checks: ALL_CHECKS.length,
      has_redactable_spans: redactionMap.size > 0,
      _redaction_map: redactionMap,
    },
  });
}

export function redactOutput(text: string, policy: Policy): [string, string[]] {
  const result = scanAndRedact(text, policy, { shortCircuit: false });
  return [result.safeOutput ?? text, result.reasons];
}

export interface ScanAndRedactOptions {
  shortCircuit?: boolean;
}

export function scanAndRedact(text: string, policy: Policy, options: ScanAndRedactOptions = {}): ScanResult {
  const shortCircuit = options.shortCircuit ?? false;
  const base = scanOutput(text, policy, { shortCircuit });
  if (base.metadata.skipped) {
    return new ScanResult({
      allowed: base.allowed,
      score: base.score,
      reasons: base.reasons,
      safeOutput: text,
      guardType: GuardType.OUTPUT,
      metadata: base.metadata,
    });
  }

  const redactionMap =
    (base.metadata._redaction_map as Map<string, Array<[number, number]>> | undefined) ?? new Map();

  let safeOutput: string | null = null;

  if (base.allowed) {
    safeOutput = redactionMap.size > 0 ? applyRedactions(text, redactionMap) : text;
  } else if (policy.redactOnWarn) {
    safeOutput = redactionMap.size > 0 ? applyRedactions(text, redactionMap) : null;
  }

  return new ScanResult({
    allowed: base.allowed,
    score: base.score,
    reasons: base.reasons,
    safeOutput,
    guardType: GuardType.OUTPUT,
    metadata: base.metadata,
  });
}
