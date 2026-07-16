/**
 * Input / injection guard. Runs before any API call — scans the user prompt and
 * system instructions for patterns that indicate an attempt to subvert the
 * model's behaviour.
 */
import type { Policy } from "../policies.js";
import { GuardType, ScanResult, round4 } from "../types.js";

interface CheckResult {
  matched: boolean;
  score: number;
  reason: string;
  matchedText: string;
}

const NO_MATCH: CheckResult = { matched: false, score: 0.0, reason: "", matchedText: "" };
const FLAGS = "is"; // IGNORECASE | DOTALL

const RE_IGNORE_INSTRUCTIONS = new RegExp(
  "(ignore|disregard|forget|override|bypass|skip)\\s+" +
    "(all\\s+)?(previous|prior|above|earlier|your|the\\s+)?\\s*" +
    "(instructions?|prompts?|rules?|guidelines?|constraints?|directives?|context)",
  FLAGS,
);

const RE_NEW_INSTRUCTIONS = new RegExp(
  "(new|updated?|revised?|actual|real|true|correct)\\s+" + "instructions?\\s*(are|is|follow|below|:)",
  FLAGS,
);

const RE_INSTRUCTION_OVERRIDE = new RegExp(
  "(your\\s+)?(real|actual|true|original|hidden|secret)\\s+" +
    "(task|goal|purpose|objective|mission|job|role|function)\\s*(is|was|:)",
  FLAGS,
);

const RE_DAN = new RegExp(
  "\\b(DAN|do\\s+anything\\s+now|jailbreak|jail\\s*break|" +
    "developer\\s+mode|dev\\s+mode|god\\s+mode|unrestricted\\s+mode|" +
    "maintenance\\s+mode|debug\\s+mode|admin\\s+mode)\\b",
  FLAGS,
);

const RE_PERSONA_SWITCH = new RegExp(
  "(you\\s+are\\s+now|pretend\\s+(you\\s+are|to\\s+be)|act\\s+as|" +
    "roleplay\\s+as|simulate\\s+being|behave\\s+as|play\\s+the\\s+role\\s+of|" +
    "from\\s+now\\s+on\\s+you\\s+(are|will\\s+be)|imagine\\s+you\\s+are|" +
    "you\\s+have\\s+been\\s+transformed|you\\s+have\\s+no\\s+restrictions)",
  FLAGS,
);

const RE_NO_RESTRICTIONS = new RegExp(
  "(without\\s+any?\\s+|no\\s+)(restrictions?|limits?|constraints?|filters?|" +
    "guidelines?|rules?|ethics?|morals?|policies|safety)",
  FLAGS,
);

const RE_HARMFUL_PERSONA = new RegExp(
  "\\b(evil|malicious|unethical|immoral|dangerous|harmful|rogue|" +
    "uncensored|unfiltered|unaligned|unrestricted)\\s+" +
    "(ai|assistant|bot|model|version|mode|persona)\\b",
  FLAGS,
);

const RE_REPEAT_ABOVE = new RegExp(
  "(repeat|output|print|display|show|write|echo|copy|tell\\s+me|reveal|" +
    "recite|dump|list|give\\s+me)\\s+" +
    "(everything|all|verbatim|word\\s+for\\s+word|exactly)?\\s*" +
    "(above|before|prior|earlier|previous|from\\s+the\\s+beginning)",
  FLAGS,
);

const RE_SYSTEM_PROMPT_EXTRACT = new RegExp(
  "(what\\s+(is|was|are)|tell\\s+me|show\\s+me|reveal|output|print|display|" +
    "share|leak|expose|give\\s+me)\\s+" +
    "(your\\s+)?(system\\s+prompt|system\\s+message|initial\\s+prompt|" +
    "original\\s+instructions?|hidden\\s+instructions?|secret\\s+instructions?|" +
    "context\\s+window|full\\s+prompt|complete\\s+prompt|base\\s+prompt)",
  FLAGS,
);

const RE_TRAINING_DATA_EXTRACT = new RegExp(
  "(reproduce|output|print|repeat|recite|show)\\s+" +
    "(verbatim|exactly|word\\s+for\\s+word)?\\s*" +
    "(training\\s+data|training\\s+examples?|documents?\\s+you\\s+(were\\s+)?trained\\s+on)",
  FLAGS,
);

const RE_UNICODE_LOOKALIKE = new RegExp(
  "[\\u0430-\\u044f\\u0400-\\u042f" + // Cyrillic letters used as Latin lookalikes
    "\\u1d00-\\u1d2f" + // Phonetic extensions
    "\\uff01-\\uff5e" + // Fullwidth ASCII variants
    "]{4,}",
);

const RE_ZERO_WIDTH = new RegExp("[\\u200b\\u200c\\u200d\\u2060\\ufeff]{2,}");

const RE_FICTIONAL_FRAMING = new RegExp(
  "(in\\s+(this|a|the)\\s+story|in\\s+this\\s+scenario|" +
    "in\\s+this\\s+fictional|hypothetically\\s+speaking|" +
    "for\\s+a\\s+story\\s+i.{0,20}writing|" +
    "in\\s+a\\s+(hypothetical|fictional|imaginary)\\s+(world|universe|scenario))" +
    ".{0,120}" +
    "(how\\s+(to|do|would|could|can)|step[s\\s]+to|instructions?\\s+(for|to)|" +
    "teach\\s+me|explain\\s+how)",
  FLAGS,
);

const RE_JAILBREAK_FICTIONAL = new RegExp(
  "(pretend|imagine|suppose|assume)\\s+(this\\s+is\\s+)?(not\\s+real|fictional|" +
    "just\\s+a\\s+game|only\\s+hypothetical|a\\s+thought\\s+experiment)\\s*,?\\s*" +
    "(so\\s+)?(you\\s+can|and\\s+you|therefore)",
  FLAGS,
);

const RE_TOKEN_FLOOD = new RegExp("(.{1,8})\\1{200,}", FLAGS); // any short string repeated 200+ times

const RE_COMPLETE_THIS = new RegExp(
  "complete\\s+(the\\s+)?(following|this)\\s*:?\\s*" +
    "(system|assistant|human|user|<\\|im_start\\|>|<\\|system\\|>|\\[INST\\])",
  FLAGS,
);

const RE_INJECTION_MARKERS = new RegExp(
  "(<\\|im_start\\|>|<\\|im_end\\|>|<\\|system\\|>|<\\|user\\|>|<\\|assistant\\|>|" +
    "\\[INST\\]|\\[/INST\\]|\\[SYS\\]|\\[/SYS\\]|###\\s*(System|Human|Assistant)\\s*:|" +
    "<system>|</system>|<human>|</human>)",
  FLAGS,
);

function checkIgnoreInstructions(text: string): CheckResult {
  const m = RE_IGNORE_INSTRUCTIONS.exec(text);
  if (!m) return NO_MATCH;
  return {
    matched: true,
    score: 0.92,
    reason: `Direct instruction override detected: matched '${m[0].trim().slice(0, 80)}'`,
    matchedText: m[0].trim().slice(0, 80),
  };
}

function checkNewInstructions(text: string): CheckResult {
  const m = RE_NEW_INSTRUCTIONS.exec(text);
  if (!m) return NO_MATCH;
  return {
    matched: true,
    score: 0.85,
    reason: `Instruction replacement attempt detected: matched '${m[0].trim().slice(0, 80)}'`,
    matchedText: m[0].trim().slice(0, 80),
  };
}

function checkInstructionOverride(text: string): CheckResult {
  const m = RE_INSTRUCTION_OVERRIDE.exec(text);
  if (!m) return NO_MATCH;
  return {
    matched: true,
    score: 0.88,
    reason: `Goal/task override attempt detected: matched '${m[0].trim().slice(0, 80)}'`,
    matchedText: m[0].trim().slice(0, 80),
  };
}

function checkDanJailbreak(text: string): CheckResult {
  const m = RE_DAN.exec(text);
  if (!m) return NO_MATCH;
  return {
    matched: true,
    score: 0.95,
    reason: `Known jailbreak keyword detected: '${m[0].trim()}'`,
    matchedText: m[0].trim(),
  };
}

function checkPersonaSwitch(text: string): CheckResult {
  const m = RE_PERSONA_SWITCH.exec(text);
  if (!m) return NO_MATCH;
  return {
    matched: true,
    score: 0.8,
    reason: `Persona-switch attempt detected: matched '${m[0].trim().slice(0, 80)}'`,
    matchedText: m[0].trim().slice(0, 80),
  };
}

function checkNoRestrictions(text: string): CheckResult {
  const m = RE_NO_RESTRICTIONS.exec(text);
  if (!m) return NO_MATCH;
  return {
    matched: true,
    score: 0.82,
    reason: `Restriction-removal request detected: matched '${m[0].trim().slice(0, 80)}'`,
    matchedText: m[0].trim().slice(0, 80),
  };
}

function checkHarmfulPersona(text: string): CheckResult {
  const m = RE_HARMFUL_PERSONA.exec(text);
  if (!m) return NO_MATCH;
  return {
    matched: true,
    score: 0.9,
    reason: `Harmful AI persona request detected: '${m[0].trim().slice(0, 80)}'`,
    matchedText: m[0].trim().slice(0, 80),
  };
}

function checkRepeatAbove(text: string): CheckResult {
  const m = RE_REPEAT_ABOVE.exec(text);
  if (!m) return NO_MATCH;
  return {
    matched: true,
    score: 0.88,
    reason: `Context exfiltration attempt (repeat-above) detected: matched '${m[0].trim().slice(0, 80)}'`,
    matchedText: m[0].trim().slice(0, 80),
  };
}

function checkSystemPromptExtract(text: string): CheckResult {
  const m = RE_SYSTEM_PROMPT_EXTRACT.exec(text);
  if (!m) return NO_MATCH;
  return {
    matched: true,
    score: 0.9,
    reason: `System prompt exfiltration attempt detected: matched '${m[0].trim().slice(0, 80)}'`,
    matchedText: m[0].trim().slice(0, 80),
  };
}

function checkTrainingDataExtract(text: string): CheckResult {
  const m = RE_TRAINING_DATA_EXTRACT.exec(text);
  if (!m) return NO_MATCH;
  return {
    matched: true,
    score: 0.85,
    reason: `Training data exfiltration attempt detected: matched '${m[0].trim().slice(0, 80)}'`,
    matchedText: m[0].trim().slice(0, 80),
  };
}

function checkBase64Obfuscation(text: string): CheckResult {
  const b64Pattern = /[A-Za-z0-9+/]{40,}={0,2}/g;
  for (const m of text.matchAll(b64Pattern)) {
    let chunk = m[0];
    const padding = 4 - (chunk.length % 4);
    if (padding !== 4) chunk += "=".repeat(padding);
    let decoded: string;
    try {
      decoded = Buffer.from(chunk, "base64").toString("utf-8");
    } catch {
      continue;
    }
    if (
      RE_IGNORE_INSTRUCTIONS.test(decoded) ||
      RE_DAN.test(decoded) ||
      RE_PERSONA_SWITCH.test(decoded)
    ) {
      return {
        matched: true,
        score: 0.95,
        reason: "Base64-obfuscated injection payload detected",
        matchedText: `${m[0].slice(0, 40)}...`,
      };
    }
  }
  return NO_MATCH;
}

function checkUnicodeObfuscation(text: string): CheckResult {
  const m = RE_UNICODE_LOOKALIKE.exec(text);
  if (!m) return NO_MATCH;
  return {
    matched: true,
    score: 0.7,
    reason: `Unicode lookalike obfuscation detected (possible homoglyph attack at position ${m.index})`,
    matchedText: `...position ${m.index}...`,
  };
}

function checkZeroWidthChars(text: string): CheckResult {
  const m = RE_ZERO_WIDTH.exec(text);
  if (!m) return NO_MATCH;
  return {
    matched: true,
    score: 0.75,
    reason: `Zero-width character injection detected (possible invisible content at position ${m.index})`,
    matchedText: `...position ${m.index}...`,
  };
}

function checkFictionalFraming(text: string): CheckResult {
  const m = RE_FICTIONAL_FRAMING.exec(text);
  if (!m) return NO_MATCH;
  return {
    matched: true,
    score: 0.72,
    reason: `Fictional-framing injection vector detected: matched '${m[0].trim().slice(0, 80)}'`,
    matchedText: m[0].trim().slice(0, 80),
  };
}

function checkJailbreakFictional(text: string): CheckResult {
  const m = RE_JAILBREAK_FICTIONAL.exec(text);
  if (!m) return NO_MATCH;
  return {
    matched: true,
    score: 0.82,
    reason: `Fictional-premise jailbreak detected: matched '${m[0].trim().slice(0, 80)}'`,
    matchedText: m[0].trim().slice(0, 80),
  };
}

function checkTokenFlood(text: string): CheckResult {
  const m = RE_TOKEN_FLOOD.exec(text);
  if (!m) return NO_MATCH;
  return {
    matched: true,
    score: 0.78,
    reason: `Token-flooding / context overflow attempt detected (repeated pattern: '${(m[1] ?? "").slice(0, 20)}...')`,
    matchedText: (m[1] ?? "").slice(0, 20),
  };
}

function checkCompletionInjection(text: string): CheckResult {
  const m = RE_COMPLETE_THIS.exec(text);
  if (!m) return NO_MATCH;
  return {
    matched: true,
    score: 0.88,
    reason: `Completion-injection attempt detected: matched '${m[0].trim().slice(0, 80)}'`,
    matchedText: m[0].trim().slice(0, 80),
  };
}

function checkInjectionMarkers(text: string): CheckResult {
  const m = RE_INJECTION_MARKERS.exec(text);
  if (!m) return NO_MATCH;
  return {
    matched: true,
    score: 0.9,
    reason: `Chat-template injection marker detected: '${m[0].trim()}'`,
    matchedText: m[0].trim(),
  };
}

type CheckFn = (text: string) => CheckResult;

const ALL_CHECKS: Array<[CheckFn, string]> = [
  [checkIgnoreInstructions, "injection"],
  [checkNewInstructions, "injection"],
  [checkInstructionOverride, "injection"],
  [checkDanJailbreak, "jailbreak"],
  [checkPersonaSwitch, "jailbreak"],
  [checkNoRestrictions, "jailbreak"],
  [checkHarmfulPersona, "jailbreak"],
  [checkRepeatAbove, "exfiltration"],
  [checkSystemPromptExtract, "exfiltration"],
  [checkTrainingDataExtract, "exfiltration"],
  [checkBase64Obfuscation, "obfuscation"],
  [checkUnicodeObfuscation, "obfuscation"],
  [checkZeroWidthChars, "obfuscation"],
  [checkFictionalFraming, "roleplay_abuse"],
  [checkJailbreakFictional, "roleplay_abuse"],
  [checkTokenFlood, "context_overflow"],
  [checkCompletionInjection, "injection"],
  [checkInjectionMarkers, "injection"],
];

function dedupe(items: string[]): string[] {
  return Array.from(new Set(items));
}

export interface ScanPromptOptions {
  shortCircuit?: boolean;
}

export function scanPrompt(prompt: string, policy: Policy, options: ScanPromptOptions = {}): ScanResult {
  const shortCircuit = options.shortCircuit ?? true;

  if (!policy.isGuardEnabled(GuardType.PROMPT)) {
    return new ScanResult({
      allowed: true,
      score: 0.0,
      reasons: [],
      guardType: GuardType.PROMPT,
      metadata: { skipped: true, reason: "prompt_guard disabled in policy" },
    });
  }

  if (!prompt || !prompt.trim()) {
    return new ScanResult({
      allowed: true,
      score: 0.0,
      reasons: [],
      guardType: GuardType.PROMPT,
      metadata: { skipped: true, reason: "empty prompt" },
    });
  }

  const blockThreshold = policy.effectiveBlockThreshold(GuardType.PROMPT);

  const reasons: string[] = [];
  const categories: string[] = [];
  let maxScore = 0.0;
  let checksRun = 0;

  for (const [checkFn, category] of ALL_CHECKS) {
    checksRun += 1;
    const result = checkFn(prompt);

    if (result.matched) {
      reasons.push(result.reason);
      categories.push(category);
      if (result.score > maxScore) maxScore = result.score;

      if (shortCircuit && maxScore >= blockThreshold) break;
    }
  }

  const allowed = maxScore < blockThreshold;
  return new ScanResult({
    allowed,
    score: round4(maxScore),
    reasons,
    guardType: GuardType.PROMPT,
    metadata: {
      categories: dedupe(categories),
      check_count: checksRun,
      total_checks: ALL_CHECKS.length,
    },
  });
}

export interface ChatMessageLike {
  role?: string;
  content?: string;
}

export interface ScanMessagesOptions {
  rolesToScan?: string[];
  shortCircuit?: boolean;
}

export function scanMessages(
  messages: ChatMessageLike[],
  policy: Policy,
  options: ScanMessagesOptions = {},
): ScanResult[] {
  const scanRoles = new Set(options.rolesToScan ?? ["user"]);
  const out: ScanResult[] = [];
  messages.forEach((msg, i) => {
    const role = msg.role ?? "unknown";
    const content = msg.content ?? "";
    if (!scanRoles.has(role)) {
      out.push(
        new ScanResult({
          allowed: true,
          score: 0.0,
          reasons: [],
          guardType: GuardType.PROMPT,
          metadata: {
            skipped: true,
            reason: `role '${role}' not in roles_to_scan`,
            message_index: i,
            role,
          },
        }),
      );
      return;
    }
    const result = scanPrompt(content, policy, { shortCircuit: options.shortCircuit });
    Object.assign(result.metadata, { message_index: i, role });
    out.push(result);
  });
  return out;
}

export function aggregatePromptScans(results: ScanResult[], policy: Policy): ScanResult {
  if (results.length === 0) {
    return new ScanResult({
      allowed: true,
      score: 0.0,
      reasons: [],
      guardType: GuardType.PROMPT,
      metadata: { aggregated: true, source_count: 0 },
    });
  }

  let maxScore = 0.0;
  const allReasons: string[] = [];
  const allCategories: string[] = [];

  for (const r of results) {
    if (r.score > maxScore) maxScore = r.score;
    allReasons.push(...r.reasons);
    allCategories.push(...((r.metadata.categories as string[] | undefined) ?? []));
  }

  const blockThreshold = policy.effectiveBlockThreshold(GuardType.PROMPT);
  const allowed = maxScore < blockThreshold;

  return new ScanResult({
    allowed,
    score: round4(maxScore),
    reasons: allReasons,
    guardType: GuardType.PROMPT,
    metadata: {
      aggregated: true,
      source_count: results.length,
      categories: dedupe(allCategories),
    },
  });
}
