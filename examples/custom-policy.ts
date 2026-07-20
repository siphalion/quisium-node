/**
 * Writing and loading a custom policy — run with `npx tsx examples/custom-policy.ts`.
 */
import { writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { GuardConfig, Policy, loadPolicyFromDict, loadPolicyFromYaml } from "../src/index.js";

// 1. Build a policy directly in code.
const inline = new Policy({
  name: "customer-support-bot",
  blockThreshold: 0.6,
  warnThreshold: 0.3,
  allowedTools: ["search_kb", "create_ticket"],
  toolGuard: new GuardConfig({ blockThreshold: 0.5 }), // stricter than the global default
});
console.log(inline.toDict());

// 2. Or from a plain object (e.g. parsed from your own config source).
const fromDict = loadPolicyFromDict({
  name: "from-dict",
  block_threshold: 0.8,
  allowed_tools: ["read_file", "search_web"],
});
console.log(fromDict.toDict());

// 3. Or from a YAML file (requires the optional `js-yaml` dependency).
async function yamlExample() {
  const dir = mkdtempSync(join(tmpdir(), "quisium-example-"));
  const path = join(dir, "policy.yaml");
  writeFileSync(
    path,
    [
      "name: production",
      "block_threshold: 0.75",
      "warn_threshold: 0.4",
      "allowed_tools:",
      "  - read_file",
      "  - search_web",
    ].join("\n"),
  );

  const fromYaml = await loadPolicyFromYaml(path);
  console.log(fromYaml.toDict());
}

yamlExample();
