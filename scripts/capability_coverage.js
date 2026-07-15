const fs = require("fs");
const path = require("path");
const os = require("os");
const { execSync } = require("child_process");

const PATCHES_DIR = path.join(__dirname, "..", "data", "pr_zoo", "patches");
const KNOWLEDGE_DIR = path.join(os.homedir(), "sentinel-knowledge");

const SEVERITY_MAP = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };

// Normalize GT capability names to canonical taxonomy
const CAP_ALIASES = {
  // GT labels → canonical
  "Execution": "execution",
  "ModuleImport": "module_import",
  "DynamicCodeExecution": "dynamic_code",
  "Decode": "decode",
  "SecretAccess": "credential_access",
  "SecretDetection": "secret_detection",
  "NetworkAccess": "network",
  "DelayedExecution": "delayed_execution",
  "SandboxEscape": "sandbox_escape",
  "ReflectionAccess": "reflection",
  "GlobalAccess": "reflection",
  "PromptInjection": "prompt_injection",
  "BrowserAccess": "browser",
  "Obfuscation": "obfuscation",
  "InformationDisclosure": "information_disclosure",
  "SignatureMatch": "signature_match",
  "signature_match": "signature_match",
  // sentinel scan types → canonical
  "OS_CAPABILITY": "execution",
  "NETWORK_ACCESS": "network",
  "DYNAMIC_CODE": "dynamic_code",
  "FILE_SYSTEM": "filesystem",
  "PERSISTENCE": "persistence",
  "OBFUSCATION": "obfuscation",
  "CREDENTIAL_ACCESS": "credential_access",
  "PROMPT_INJECTION": "prompt_injection",
  "INFORMATION_DISCLOSURE": "information_disclosure",
  "REFLECTION": "reflection",
  "SANDBOX_ESCAPE": "sandbox_escape",
  "TYPOSQUAT": "typosquat",
  "SUPPLY_CHAIN": "supply_chain",
};

function normalizeCap(cap) {
  return (CAP_ALIASES[cap] || cap).toLowerCase();
}

function getExpectedCapabilities(meta) {
  const caps = new Set();
  const exp = meta.expected;
  if (!exp) return [];
  for (const cap of (exp.capabilities || [])) caps.add(normalizeCap(cap));
  return [...caps];
}

function extractSentinelCapabilities(scanJSON) {
  const caps = new Set();
  try {
    const data = JSON.parse(scanJSON);
    if (!data.findings) return [];
    for (const f of data.findings) {
      const canonical = normalizeCap(f.type || "");
      if (canonical) caps.add(canonical);
      // Also scan description for known patterns
      const desc = (f.description || "").toLowerCase();
      if (desc.includes("exec") || desc.includes("spawn") || desc.includes("process")) caps.add("execution");
      if (desc.includes("network") || desc.includes("fetch") || desc.includes("websocket")) caps.add("network");
      if (desc.includes("eval") || desc.includes("dynamic") || desc.includes("function(")) caps.add("dynamic_code");
      if (desc.includes("persistence") || desc.includes("lifecycle") || desc.includes("install")) caps.add("persistence");
      if (desc.includes("obfuscat") || desc.includes("encode") || desc.includes("base64")) caps.add("obfuscation");
      if (desc.includes("credential") || desc.includes("secret") || desc.includes("env")) caps.add("credential_access");
      if (desc.includes("prompt") || desc.includes("inject")) caps.add("prompt_injection");
      if (desc.includes("reflection") || desc.includes("prototype")) caps.add("reflection");
      if (desc.includes("sandbox") || desc.includes("vm.")) caps.add("sandbox_escape");
      if (desc.includes("typosquat") || desc.includes("typocap")) caps.add("typosquat");
      if (desc.includes("supply") || desc.includes("dependency")) caps.add("supply_chain");
      if (desc.includes("filesystem") || desc.includes("file write") || desc.includes("fs.")) caps.add("filesystem");
    }
  } catch (e) {
    // scan output wasn't valid JSON
  }
  return [...caps];
}

async function main() {
  console.log("=".repeat(70));
  console.log("  CAPABILITY COVERAGE REPORT — Sentinel Knowledge Lake");
  console.log("=".repeat(70));
  console.log();

  const files = fs.readdirSync(PATCHES_DIR).filter(f => f.endsWith(".json"));
  let total = 0, fullCoverage = 0, partialCoverage = 0, noCaps = 0;
  const results = [];
  const matrix = {};
  const gapsByCap = {};

  for (const file of files) {
    const metaFile = path.join(PATCHES_DIR, file);
    const patchFile = metaFile.replace(".json", ".patch");
    if (!fs.existsSync(patchFile)) continue;

    const meta = JSON.parse(fs.readFileSync(metaFile, "utf8"));
    const expectedCaps = getExpectedCapabilities(meta);
    if (expectedCaps.length === 0 && !meta.expected) continue;

    total++;
    const code = fs.readFileSync(patchFile, "utf8");
    const id = file.replace(".json", "");

    // Write to temp file and scan with sentinel
    const tmpFile = path.join(os.tmpdir(), `sentinel_scan_${id.replace(/[^a-zA-Z0-9]/g, "_")}.js`);
    fs.writeFileSync(tmpFile, code, "utf8");
    let scanOutput = "";
    try {
      scanOutput = execSync(`sentinel scan "${tmpFile}" --json 2>&1`, { encoding: "utf8", timeout: 10000 });
      // Extract JSON from output (sentinel may prepend host check text)
      const jsonStart = scanOutput.indexOf("{");
      if (jsonStart >= 0) scanOutput = scanOutput.slice(jsonStart);
      const jsonEnd = scanOutput.lastIndexOf("}");
      if (jsonEnd >= 0) scanOutput = scanOutput.slice(0, jsonEnd + 1);
    } catch (e) {
      scanOutput = e.stdout || "";
      const jsonStart = scanOutput.indexOf("{");
      if (jsonStart >= 0) scanOutput = scanOutput.slice(jsonStart);
      const jsonEnd = scanOutput.lastIndexOf("}");
      if (jsonEnd >= 0) scanOutput = scanOutput.slice(0, jsonEnd + 1);
    } finally {
      try { fs.unlinkSync(tmpFile); } catch(e) {}
    }

    const detectedCaps = extractSentinelCapabilities(scanOutput);

    const matched = expectedCaps.filter(c => detectedCaps.includes(c));
    const missing = expectedCaps.filter(c => !detectedCaps.includes(c));
    const unexpected = detectedCaps.filter(c => !expectedCaps.includes(c));

    // Confusion matrix per capability
    const allCaps = new Set([...expectedCaps, ...detectedCaps]);
    for (const cap of allCaps) {
      if (!matrix[cap]) matrix[cap] = { TP: 0, FP: 0, FN: 0, TN: 0, samples: 0 };
      const isExpected = expectedCaps.includes(cap);
      const isDetected = detectedCaps.includes(cap);
      matrix[cap].samples++;
      if (isExpected && isDetected) matrix[cap].TP++;
      else if (!isExpected && isDetected) matrix[cap].FP++;
      else if (isExpected && !isDetected) matrix[cap].FN++;
      else matrix[cap].TN++;
    }

    // Track gaps
    for (const cap of missing) {
      if (!gapsByCap[cap]) gapsByCap[cap] = [];
      gapsByCap[cap].push(id);
    }

    if (missing.length === 0 && unexpected.length === 0) fullCoverage++;
    else if (missing.length < expectedCaps.length) partialCoverage++;
    else noCaps++;

    results.push({ id, expectedCaps, detectedCaps, matched, missing, unexpected });
  }

  // ── Print per-entry detail (only gaps) ──
  const gapEntries = results.filter(r => r.missing.length > 0 || r.unexpected.length > 0);
  for (const r of gapEntries) {
    const flags = [];
    if (r.missing.length > 0) flags.push(`missing=[${r.missing.join(", ")}]`);
    if (r.unexpected.length > 0) flags.push(`unexpected=[${r.unexpected.join(", ")}]`);
    console.log(`  ${r.id.padEnd(40)} ${flags.join(" ")}`);
  }
  console.log();

  // ── Summary ──
  console.log("=".repeat(70));
  console.log("  COVERAGE SUMMARY");
  console.log("=".repeat(70));
  console.log(`  Samples:          ${total}`);
  console.log(`  Full coverage:    ${fullCoverage} (${(fullCoverage/total*100).toFixed(1)}%)`);
  console.log(`  Partial coverage: ${partialCoverage} (${(partialCoverage/total*100).toFixed(1)}%)`);
  console.log(`  No caps covered:  ${noCaps} (${(noCaps/total*100).toFixed(1)}%)`);
  console.log();

  // ── Confusion matrix ──
  console.log("=".repeat(70));
  console.log("  CONFUSION MATRIX BY CAPABILITY");
  console.log("=".repeat(70));
  console.log(`  ${"Capability".padEnd(24)} ${"TP".padStart(3)} ${"FP".padStart(3)} ${"FN".padStart(3)} ${"TN".padStart(3)}  ${"Prec".padStart(6)} ${"Rec".padStart(6)} ${"F1".padStart(6)} ${"Samples".padStart(6)}`);
  console.log("  " + "-".repeat(70));
  const filteredEntries = Object.entries(matrix).filter(([k, v]) => !["sentinel_detected","module_import","credential_access","dynamic_code"].includes(k) || v.FP > 0 || v.TP > 0).sort((a, b) => (b[1].TP + b[1].FN) - (a[1].TP + a[1].FN));
  for (const [cap, m] of filteredEntries) {
    const precision = m.TP + m.FP > 0 ? m.TP / (m.TP + m.FP) : 1;
    const recall = m.TP + m.FN > 0 ? m.TP / (m.TP + m.FN) : 1;
    const f1 = precision + recall > 0 ? 2 * precision * recall / (precision + recall) : 1;
    const pct = (s) => (s * 100 / total).toFixed(0) + "%";
    console.log(`  ${cap.padEnd(24)} ${String(m.TP).padStart(3)} ${String(m.FP).padStart(3)} ${String(m.FN).padStart(3)} ${String(m.TN).padStart(3)}  ${precision.toFixed(3).padStart(6)} ${recall.toFixed(3).padStart(6)} ${f1.toFixed(3).padStart(6)} ${pct(m.samples).padStart(6)}`);
  }
  console.log();

  // ── Coverage gaps ──
  if (Object.keys(gapsByCap).length > 0) {
    console.log("=".repeat(70));
    console.log("  COVERAGE GAPS — capabilities Sentinel never detected");
    console.log("=".repeat(70));
    for (const [cap, samples] of Object.entries(gapsByCap).sort((a, b) => b[1].length - a[1].length)) {
      console.log(`  ${cap.padEnd(24)} ${samples.length} missed — e.g. ${samples.slice(0, 3).join(", ")}`);
    }
    console.log();
  }

  // ── Save report ──
  const reportDir = path.join(KNOWLEDGE_DIR, "reports");
  if (!fs.existsSync(reportDir)) fs.mkdirSync(reportDir, { recursive: true });
  const reportPath = path.join(reportDir, `capability_coverage_${Date.now()}.json`);
  fs.writeFileSync(reportPath, JSON.stringify({
    timestamp: new Date().toISOString(),
    samples: total,
    fullCoverage,
    partialCoverage,
    noCaps,
    fullCoveragePct: (fullCoverage/total*100).toFixed(1),
    partialCoveragePct: (partialCoverage/total*100).toFixed(1),
    matrix,
    gapsByCap,
    results,
  }, null, 2));
  console.log(`  Report saved: ${reportPath}`);
  console.log(`  Knowledge Lake: ${KNOWLEDGE_DIR}`);
}

main().catch(console.error);
