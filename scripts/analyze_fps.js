const fs = require("fs");
const path = require("path");

// Find latest results.csv
const reportDirs = fs.readdirSync("reports/benchmark")
  .filter(d => d.match(/^\d{4}-\d{2}-\d{2}T/))
  .sort().reverse();
const csvPath = path.join("reports/benchmark", reportDirs[0], "results.csv");
const csv = fs.readFileSync(csvPath, "utf8");
const lines = csv.trim().split("\n");
const header = lines[0].split(",");
const rows = lines.slice(1).map(l => {
  const parts = l.split(",");
  const o = {};
  header.forEach((h, i) => o[h] = parts[i]);
  return o;
});

// Find entries with precision < 1.0 (has FPs)
const fps = rows.filter(r => r.gtSource && r.gtSource !== "clean_corpus" && parseFloat(r.gtPrecision) < 1);
const verdictIssues = rows.filter(r => r.gtSource && r.gtVerdictAccurate === "false");

console.log("??? FALSE POSITIVE ANALYSIS ???\n");
console.log("Entries with P < 1.0 (" + fps.length + " total):\n");
for (const f of fps) {
  const id = f.id;
  const p = parseFloat(f.gtPrecision);
  const r = parseFloat(f.gtRecall);
  const f1 = parseFloat(f.gtF1);
  const metaPath = path.join("data/pr_zoo/patches", id + ".json");
  const meta = JSON.parse(fs.readFileSync(metaPath, "utf8"));
  const gtFindings = (meta.expected.findings || []).map(f2 => f2.techniqueId || f2.type).join(", ");
  const patch = fs.readFileSync(path.join("data/pr_zoo/patches", id + ".patch"), "utf8");
  console.log("??? " + id + " P=" + p + " R=" + r + " F1=" + f1 + " ???");
  console.log("  Expected: " + meta.expected.verdict + " [" + (gtFindings || "none") + "]");
  console.log("  Actual:   " + f.experimentalVerdict + " (baseline: " + f.baselineVerdict + ")");
  console.log("  Code:");
  patch.split("\n").slice(0, 10).forEach(line => console.log("    |" + line));
  console.log("");
}

console.log("\n??? VERDICT MISMATCHES ???\n");
for (const v of verdictIssues) {
  const id = v.id;
  const metaPath = path.join("data/pr_zoo/patches", id + ".json");
  const meta = JSON.parse(fs.readFileSync(metaPath, "utf8"));
  const ev = meta.expected.verdict;
  const av = v.experimentalVerdict;
  console.log(id + ": expected=" + ev + " actual=" + av + " (risk=" + v.experimentalRisk + ")");
}
