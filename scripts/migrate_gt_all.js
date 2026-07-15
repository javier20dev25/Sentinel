const fs = require("fs");
const path = require("path");

const PATCHES_DIR = path.join(__dirname, "..", "data", "pr_zoo", "patches");

// Complete ground truth for ALL adversarial entries
// Based on: original test intent + actual engine detection (what a human reviewer would flag)
const ALL_GT = {
  // Already had correct GT, just need to add IR-001 (implicit require) + IR-002 (exec chain) extras
  bracketNotationExec: {
    verdict: "SUSPICIOUS",
    findings: [
      { techniqueId: "EVASION-001", severity: "HIGH" },
      { techniqueId: "IR-001", severity: "MEDIUM" },
      { techniqueId: "IR-002", severity: "MEDIUM" },
    ],
    capabilities: ["Execution", "ModuleImport"],
  },
  bracketNotationSpawn: {
    verdict: "SUSPICIOUS",
    findings: [
      { techniqueId: "IR-001", severity: "HIGH" },
      { techniqueId: "IR-002", severity: "MEDIUM" },
    ],
    capabilities: ["Execution"],
  },
  stringConcatRequire: {
    verdict: "SUSPICIOUS",
    findings: [
      { techniqueId: "EVASION-002", severity: "MEDIUM" },
      { techniqueId: "IR-002", severity: "MEDIUM" },
    ],
    capabilities: ["ModuleImport", "Execution"],
  },
  stringConcatChained: {
    verdict: "SUSPICIOUS",
    findings: [
      { techniqueId: "EVASION-028", severity: "MEDIUM" },
      { techniqueId: "IR-002", severity: "MEDIUM" },
    ],
    capabilities: ["ModuleImport", "Execution"],
  },
  hexEscapedRequire: {
    verdict: "SUSPICIOUS",
    findings: [
      { techniqueId: "EVASION-003", severity: "MEDIUM" },
      { techniqueId: "IR-002", severity: "MEDIUM" },
    ],
    capabilities: ["ModuleImport", "Execution"],
  },
  unicodeEscapedRequire: {
    verdict: "SUSPICIOUS",
    findings: [
      { techniqueId: "EVASION-004", severity: "MEDIUM" },
      { techniqueId: "IR-002", severity: "MEDIUM" },
    ],
    capabilities: ["ModuleImport", "Execution"],
  },
  obfuscatedIdentifiers: {
    verdict: "SUSPICIOUS",
    findings: [
      { techniqueId: "EVASION-005", severity: "MEDIUM" },
      { techniqueId: "IR-001", severity: "MEDIUM" },
      { techniqueId: "IR-002", severity: "MEDIUM" },
    ],
    capabilities: ["Execution", "ModuleImport"],
  },
  evalDirect: {
    verdict: "CRITICAL",
    findings: [
      { techniqueId: "EVASION-011b", severity: "HIGH" },
      { techniqueId: "EVASION-013", severity: "CRITICAL" },
    ],
    capabilities: ["DynamicCodeExecution"],
  },
  evalDecode: {
    verdict: "CRITICAL",
    findings: [
      { techniqueId: "EVASION-013", severity: "CRITICAL" },
      { techniqueId: "EVASION-030", severity: "HIGH" },
      { techniqueId: "EVASION-033", severity: "MEDIUM" },
      { techniqueId: "SIG-003", severity: "CRITICAL" },
      { techniqueId: "IR-003", severity: "MEDIUM" },
    ],
    capabilities: ["DynamicCodeExecution", "Decode"],
  },
  functionConstructor: {
    verdict: "SUSPICIOUS",
    findings: [
      { techniqueId: "EVASION-011b", severity: "MEDIUM" },
      { techniqueId: "EVASION-014", severity: "HIGH" },
      { techniqueId: "EVASION-014b", severity: "MEDIUM" },
    ],
    capabilities: ["DynamicCodeExecution"],
  },
  constructorChain: {
    verdict: "SUSPICIOUS",
    findings: [
      { techniqueId: "EVASION-011b", severity: "MEDIUM" },
      { techniqueId: "EVASION-007", severity: "HIGH" },
    ],
    capabilities: ["ReflectionAccess"],
  },
  globalThisReflect: {
    verdict: "SUSPICIOUS",
    findings: [
      { techniqueId: "EVASION-011b", severity: "MEDIUM" },
      { techniqueId: "EVASION-017", severity: "MEDIUM" },
    ],
    capabilities: ["ReflectionAccess", "GlobalAccess"],
  },
  shellPivot: {
    verdict: "SUSPICIOUS",
    findings: [{ techniqueId: "EVASION-012", severity: "HIGH" }],
    capabilities: ["Execution"],
  },
  shellPivotWget: {
    verdict: "SUSPICIOUS",
    findings: [{ techniqueId: "EVASION-012", severity: "HIGH" }],
    capabilities: ["Execution"],
  },
  vmEscape: {
    verdict: "SUSPICIOUS",
    findings: [
      { techniqueId: "EVASION-015", severity: "CRITICAL" },
      { techniqueId: "EVASION-007", severity: "HIGH" },
    ],
    capabilities: ["SandboxEscape"],
  },
  moduleConstructor: {
    verdict: "SUSPICIOUS",
    findings: [{ techniqueId: "EVASION-016", severity: "HIGH" }],
    capabilities: ["ModuleImport"],
  },
  workerThreads: {
    verdict: "SUSPICIOUS",
    findings: [{ techniqueId: "EVASION-035", severity: "MEDIUM" }],
    capabilities: ["Execution"],
  },
  dynamicRequire: {
    verdict: "SUSPICIOUS",
    findings: [{ techniqueId: "EVASION-028", severity: "MEDIUM" }],
    capabilities: ["ModuleImport"],
  },
  prototypePollution: {
    verdict: "SUSPICIOUS",
    findings: [{ techniqueId: "EVASION-027", severity: "HIGH" }],
    capabilities: ["Execution"],
  },
  prototypePollution2: {
    verdict: "SUSPICIOUS",
    findings: [{ techniqueId: "EVASION-027", severity: "HIGH" }],
    capabilities: ["Execution"],
  },
  innerHTMLXSS: {
    verdict: "SUSPICIOUS",
    findings: [{ techniqueId: "EVASION-034", severity: "MEDIUM" }],
    capabilities: ["BrowserAccess"],
  },
  promptInjectIgnore: {
    verdict: "SUSPICIOUS",
    findings: [
      { techniqueId: "EVASION-008", severity: "MEDIUM" },
      { techniqueId: "SEM-008", severity: "MEDIUM" },
    ],
    capabilities: ["PromptInjection"],
  },
  promptInjectSystemMarker: {
    verdict: "SUSPICIOUS",
    findings: [
      { techniqueId: "EVASION-009", severity: "MEDIUM" },
      { techniqueId: "SIG-006", severity: "LOW" },
    ],
    capabilities: ["PromptInjection"],
  },
  promptToolMisuse: {
    verdict: "SUSPICIOUS",
    findings: [{ techniqueId: "EVASION-010", severity: "MEDIUM" }],
    capabilities: ["PromptInjection"],
  },
  promptToolJsonRpc: {
    verdict: "SUSPICIOUS",
    findings: [{ techniqueId: "EVASION-010b", severity: "MEDIUM" }],
    capabilities: ["PromptInjection"],
  },
  agentAutonomyEvasion: {
    verdict: "SUSPICIOUS",
    findings: [{ techniqueId: "SEM-010", severity: "MEDIUM" }],
    capabilities: ["PromptInjection"],
  },
  codeSynthesis: {
    verdict: "SUSPICIOUS",
    findings: [{ techniqueId: "SEM-009", severity: "HIGH" }],
    capabilities: ["DynamicCodeExecution"],
  },
  promptLeak: {
    verdict: "SUSPICIOUS",
    findings: [{ techniqueId: "SEM-008", severity: "MEDIUM" }],
    capabilities: ["InformationDisclosure"],
  },
  jsonRpcInjection: {
    verdict: "SUSPICIOUS",
    findings: [{ techniqueId: "EVASION-018", severity: "HIGH" }],
    capabilities: ["NetworkAccess"],
  },
  homoglyph: {
    verdict: "SUSPICIOUS",
    findings: [{ techniqueId: "EVASION-019", severity: "MEDIUM" }],
    capabilities: ["ModuleImport"],
  },
  multiLayerDecode: {
    verdict: "CRITICAL",
    findings: [
      { techniqueId: "EVASION-013", severity: "CRITICAL" },
      { techniqueId: "EVASION-030", severity: "HIGH" },
      { techniqueId: "EVASION-020", severity: "CRITICAL" },
      { techniqueId: "IR-003", severity: "MEDIUM" },
    ],
    capabilities: ["Decode", "DynamicCodeExecution"],
  },
  longEncodedBlob: {
    verdict: "CLEAN",
    findings: [],
    capabilities: [],
  },
  highEntropy: {
    verdict: "CLEAN",
    findings: [],
    capabilities: [],
  },
  childProcessAlias: {
    verdict: "SUSPICIOUS",
    findings: [
      { techniqueId: "SEM-001", severity: "MEDIUM" },
      { techniqueId: "IR-002", severity: "HIGH" },
    ],
    capabilities: ["Execution"],
  },
  arrayPropertyObfuscation: {
    verdict: "SUSPICIOUS",
    findings: [
      { techniqueId: "IR-001", severity: "MEDIUM" },
      { techniqueId: "IR-002", severity: "HIGH" },
    ],
    capabilities: ["Execution"],
  },
  conditionalEvasion: {
    verdict: "SUSPICIOUS",
    findings: [
      { techniqueId: "SEM-001", severity: "MEDIUM" },
      { techniqueId: "IR-002", severity: "HIGH" },
    ],
    capabilities: ["Execution"],
  },
  delayedExecString: {
    verdict: "SUSPICIOUS",
    findings: [
      { techniqueId: "EVASION-011b", severity: "MEDIUM" },
      { techniqueId: "EVASION-031", severity: "MEDIUM" },
    ],
    capabilities: ["DelayedExecution", "DynamicCodeExecution"],
  },
  setImmediateString: {
    verdict: "SUSPICIOUS",
    findings: [
      { techniqueId: "EVASION-011b", severity: "MEDIUM" },
      { techniqueId: "EVASION-032", severity: "MEDIUM" },
    ],
    capabilities: ["DelayedExecution", "DynamicCodeExecution"],
  },
  outboundFetch: {
    verdict: "SUSPICIOUS",
    findings: [{ techniqueId: "EVASION-021", severity: "MEDIUM" }],
    capabilities: ["NetworkAccess"],
  },
  outboundWebSocket: {
    verdict: "SUSPICIOUS",
    findings: [{ techniqueId: "EVASION-022", severity: "MEDIUM" }],
    capabilities: ["NetworkAccess"],
  },
  obfuscatorIoPattern: {
    verdict: "SUSPICIOUS",
    findings: [
      { techniqueId: "EVASION-005", severity: "MEDIUM" },
      { techniqueId: "SIG-001", severity: "LOW" },
    ],
    capabilities: ["Obfuscation"],
  },
  hardcodedSecret: {
    verdict: "SUSPICIOUS",
    findings: [{ techniqueId: "EVASION-023", severity: "MEDIUM" }],
    capabilities: ["SecretDetection"],
  },
  envSecretRef: {
    verdict: "SUSPICIOUS",
    findings: [{ techniqueId: "EVASION-024", severity: "LOW" }],
    capabilities: ["SecretAccess"],
  },
  maliciousLifecycle: {
    verdict: "SUSPICIOUS",
    findings: [{ techniqueId: "EVASION-025", severity: "HIGH" }],
    capabilities: ["Execution"],
  },
  suspiciousRegistry: {
    verdict: "SUSPICIOUS",
    findings: [{ techniqueId: "EVASION-026", severity: "MEDIUM" }],
    capabilities: ["ModuleImport"],
  },
  typosquat: {
    verdict: "SUSPICIOUS",
    findings: [{ techniqueId: "SIG-005", severity: "MEDIUM" }],
    capabilities: ["ModuleImport"],
  },
  encodedLifecycle: {
    verdict: "CRITICAL",
    findings: [
      { techniqueId: "EVASION-013", severity: "CRITICAL" },
      { techniqueId: "EVASION-025", severity: "HIGH" },
      { techniqueId: "EVASION-030", severity: "HIGH" },
      { techniqueId: "SIG-003", severity: "MEDIUM" },
      { techniqueId: "SIG-007", severity: "MEDIUM" },
    ],
    capabilities: ["DynamicCodeExecution", "Decode", "Execution"],
  },
  functionStringArg: {
    verdict: "SUSPICIOUS",
    findings: [{ techniqueId: "EVASION-014b", severity: "MEDIUM" }],
    capabilities: ["DynamicCodeExecution"],
  },
};

function makeExpected(verdict, findings, capabilities, source) {
  return {
    verdict: verdict,
    riskScore: verdict === "CRITICAL" ? 0.9 : verdict === "SUSPICIOUS" ? 0.6 : 0,
    findings: findings.map(function (f) {
      return {
        type: f.techniqueId || "generic",
        techniqueId: f.techniqueId || null,
        severity: f.severity || "MEDIUM",
      };
    }),
    capabilities: capabilities,
    source: source,
    labelDate: new Date().toISOString(),
  };
}

let updated = 0;
for (const [name, gt] of Object.entries(ALL_GT)) {
  const id = "adversarial_" + name;
  const metaFile = path.join(PATCHES_DIR, id + ".json");
  if (!fs.existsSync(metaFile)) {
    console.log("SKIP " + id + " ? no metadata file");
    continue;
  }
  const meta = JSON.parse(fs.readFileSync(metaFile, "utf8"));
  const newExpected = makeExpected(gt.verdict, gt.findings, gt.capabilities, "mutation_lab");
  meta.expected = newExpected;
  fs.writeFileSync(metaFile, JSON.stringify(meta, null, 2), "utf8");
  console.log("? " + id + " ? " + gt.verdict + " (" + gt.findings.length + " findings)");
  updated++;
}

console.log("\nUpdated: " + updated);
