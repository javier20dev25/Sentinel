const fs = require("fs");
const path = require("path");

// Find latest report
const reportDirs = fs.readdirSync("reports/benchmark")
  .filter(d => d.match(/^\d{4}-\d{2}-\d{2}T/))
  .sort().reverse();

const latest = path.join("reports/benchmark", reportDirs[0]);
const report = JSON.parse(fs.readFileSync(path.join(latest, "report.json"), "utf8"));

// Build report lines
const lines = [];
lines.push("# Sentinel Evaluation Lab ? Summary Report");
lines.push("");
lines.push("Generated: " + new Date().toISOString());
lines.push("Dataset: " + (report.stats?.time?.count || report.groundTruth?.samplesWithGT || "?") + " samples from PR Zoo");
lines.push("Report: " + latest);
lines.push("");

// GT summary
const gt = report.groundTruth;
if (gt) {
  lines.push("## Ground Truth Evaluation (" + gt.samplesWithGT + " samples)");
  lines.push("");
  lines.push("| Metric | Baseline | Experimental |");
  lines.push("|--------|----------|--------------|");
  const fmt = (v) => typeof v === "number" ? v.toFixed(3) : v;
  const fmtPct = (v) => (v * 100).toFixed(1) + "%";
  if (gt.baseline) {
    lines.push("| Precision | " + fmt(gt.baseline.avgPrecision) + " | " + fmt(gt.experimental.avgPrecision) + " |");
    lines.push("| Recall    | " + fmt(gt.baseline.avgRecall) + " | " + fmt(gt.experimental.avgRecall) + " |");
    lines.push("| F1        | " + fmt(gt.baseline.avgF1) + " | " + fmt(gt.experimental.avgF1) + " |");
    lines.push("| VAcc      | " + fmtPct(gt.baseline.verdictAccuracy) + " | " + fmtPct(gt.experimental.verdictAccuracy) + " |");
  }
  lines.push("");

  // By source
  if (gt.bySource) {
    lines.push("### By Source");
    lines.push("");
    lines.push("| Source | Count | Baseline F1 | Experimental F1 |");
    lines.push("|--------|-------|-------------|-----------------|");
    for (const [src, data] of Object.entries(gt.bySource)) {
      lines.push("| " + src + " | " + data.count + " | " + fmt(data.baselineAvgF1 || 0) + " | " + fmt(data.experimentalAvgF1 || 0) + " |");
    }
    lines.push("");
  }
}

// Performance
lines.push("## Performance");
lines.push("");
  lines.push("- Samples: " + (report.stats?.time?.count || "?"));
lines.push("- Average time: " + report.stats.time.avg.toFixed(1) + "ms");
lines.push("- P50: " + report.stats.time.p50.toFixed(1) + "ms");
lines.push("- P95: " + report.stats.time.p95.toFixed(1) + "ms");
lines.push("- Memory: " + report.stats.memory.avg + "MB average");
lines.push("");

// Divergences
const div = report.divergences;
if (div) {
  lines.push("## Divergences (" + div.total + " total)");
  lines.push("");
  lines.push("- Escalated: " + (div.escalated || div.escallated || 0) + " (baseline PASS ? experimental REVIEW/BLOCK)");
  lines.push("- De-escalated: " + (div.deescalated || 0) + " (baseline REVIEW/BLOCK ? experimental PASS)");
  lines.push("");
}

// File counts
lines.push("## Repository Structure");
lines.push("");
const counts = {};
const files = fs.readdirSync("data/pr_zoo/patches").filter(f => f.endsWith(".json"));
for (const f of files) {
  const meta = JSON.parse(fs.readFileSync(path.join("data/pr_zoo/patches", f), "utf8"));
  const src = meta.expected ? meta.expected.source : (meta.source ? meta.source.repo || "unknown" : "unknown");
  counts[src] = (counts[src] || 0) + 1;
}
lines.push("| Source | Count |");
lines.push("|--------|-------|");
for (const [src, count] of Object.entries(counts).sort((a, b) => b[1] - a[1])) {
  lines.push("| " + src + " | " + count + " |");
}
lines.push("");

// Remaining issues
lines.push("## Remaining Issues (Experimental)");
lines.push("");
const csvPath = path.join(latest, "results.csv");
if (fs.existsSync(csvPath)) {
  const csv = fs.readFileSync(csvPath, "utf8");
  const rows = csv.trim().split("\n").slice(1);
  const issues = rows.filter(r => {
    const cols = r.split(",");
    const p = parseFloat(cols[20]);
    const vak = cols[22];
    return cols[18] && (p < 1 || vak === "false");
  });
  lines.push("| ID | Precision | Verdict Correct |");
  lines.push("|----|-----------|-----------------|");
  for (const row of issues) {
    const cols = row.split(",");
    const id = cols[0];
    const p = parseFloat(cols[20]);
    const vak = cols[22];
    if (isNaN(p)) continue;
    lines.push("| " + id + " | " + (p < 1 ? p.toFixed(3) : "1.000") + " | " + vak + " |");
  }
  lines.push("");
}

// Key files
lines.push("## Key Files");
lines.push("");
lines.push("- `data/pr_zoo/manifest.json` ? PR Zoo manifest (" + files.length + " entries)");
lines.push("- `scripts/seed_zoo_from_corpus.js` ? Corpus seeding + ground truth definitions");
lines.push("- `scripts/benchmark_runner.js` ? Benchmark runner with GT evaluation");
lines.push("- `packages/sentinel-core/adapters/comparator.js` ? GT comparator");
lines.push("- `packages/sentinel-core/adapters/experimental_adapter.js` ? Experimental engine adapter (confidence, dead code strip)");
lines.push("- `packages/sentinel-core/scanner/evasion/normalizer.js` ? Dead code elimination");
lines.push("- `scripts/migrate_gt_all.js` ? Ground truth migration");
lines.push("- `scripts/gen_mutationlab.js` ? FP mutation generation");
lines.push("- `reports/benchmark/` ? Benchmark reports (latest: " + reportDirs[0] + ")");

const reportContent = lines.join("\n");
const reportPath = path.join(latest, "SUMMARY.md");
fs.writeFileSync(reportPath, reportContent);
console.log("Report written to " + reportPath);
console.log(reportContent);
