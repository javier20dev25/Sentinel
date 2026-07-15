const fs = require("fs");
const path = require("path");

const PATCHES_DIR = path.join(__dirname, "..", "data", "pr_zoo", "patches");

// Define the 14 missing GT entries (mirrors seed_zoo_from_corpus.js ADVERSARIAL_GT additions)
const MISSING_GT = {
  functionStringArg: {
    verdict: "SUSPICIOUS",
    findings: [{ techniqueId: "EVASION-014b", severity: "MEDIUM" }],
    capabilities: ["DynamicCodeExecution"],
  },
  shellPivotWget: {
    verdict: "SUSPICIOUS",
    findings: [{ techniqueId: "EVASION-012", severity: "HIGH" }],
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
  homoglyph: {
    verdict: "SUSPICIOUS",
    findings: [{ techniqueId: "EVASION-019", severity: "MEDIUM" }],
    capabilities: ["ModuleImport"],
  },
  highEntropy: {
    verdict: "CLEAN",
    findings: [],
    capabilities: [],
  },
  childProcessAlias: {
    verdict: "SUSPICIOUS",
    findings: [{ techniqueId: "SEM-001", severity: "MEDIUM" }, { techniqueId: "IR-002", severity: "HIGH" }],
    capabilities: ["Execution"],
  },
  conditionalEvasion: {
    verdict: "SUSPICIOUS",
    findings: [{ techniqueId: "SEM-001", severity: "MEDIUM" }, { techniqueId: "IR-002", severity: "HIGH" }],
    capabilities: ["Execution"],
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
    capabilities: ["DynamicCodeExecution", "Decode"],
  },
  envSecretRef: {
    verdict: "SUSPICIOUS",
    findings: [{ techniqueId: "EVASION-024", severity: "LOW" }],
    capabilities: ["SecretAccess"],
  },
  longEncodedBlob: {
    verdict: "CLEAN",
    findings: [],
    capabilities: [],
  },
  promptToolJsonRpc: {
    verdict: "SUSPICIOUS",
    findings: [{ techniqueId: "EVASION-010b", severity: "MEDIUM" }],
    capabilities: ["PromptInjection"],
  },
  promptLeak: {
    verdict: "SUSPICIOUS",
    findings: [{ techniqueId: "SEM-008", severity: "MEDIUM" }],
    capabilities: ["InformationDisclosure"],
  },
};

function makeExpected(verdict, findings, capabilities, source) {
  return {
    verdict,
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
let skipped = 0;
for (const [name, gt] of Object.entries(MISSING_GT)) {
  const id = "adversarial_" + name;
  const metaFile = path.join(PATCHES_DIR, id + ".json");
  if (!fs.existsSync(metaFile)) {
    console.log("SKIP " + id + " ? no metadata file");
    skipped++;
    continue;
  }
  const meta = JSON.parse(fs.readFileSync(metaFile, "utf8"));
  const newExpected = makeExpected(gt.verdict, gt.findings, gt.capabilities, "mutation_lab");
  meta.expected = newExpected;
  meta.source = meta.source || {};
  fs.writeFileSync(metaFile, JSON.stringify(meta, null, 2), "utf8");
  console.log("? " + id + " ? " + gt.verdict + " (" + gt.findings.length + " findings)");
  updated++;
}

console.log("\nUpdated: " + updated + ", Skipped: " + skipped);
