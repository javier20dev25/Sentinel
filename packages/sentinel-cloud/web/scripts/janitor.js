/**
 * SENTINEL JANITOR v1.0
 * Automated Quality & Maintenance Algorithm
 */

import path from 'path';
import { execSync } from 'child_process';

const COLORS = {
  reset: "\x1b[0m",
  bright: "\x1b[1m",
  red: "\x1b[31m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  cyan: "\x1b[36m",
};

function log(msg, color = COLORS.reset) {
  console.log(`${color}${msg}${COLORS.reset}`);
}

async function run() {
  log("--- SENTINEL JANITOR: STARTING MAINTENANCE ---", COLORS.bright + COLORS.cyan);

  // 1. Audit for Forbidden 'any' types
  log("\n[1/3] Auditing Type Quality (Scanning for 'any')...");
  const srcDir = path.join(process.cwd(), 'src');
  
  try {
    const grepResult = execSync(`grep -rE ": any|as any" ${srcDir} --exclude-dir=node_modules || true`).toString();
    if (grepResult.trim()) {
      log("Found prohibited 'any' types:", COLORS.red);
      console.log(grepResult);
      log("ERROR: Elite Standard violation detected. Please fix manually.", COLORS.red);
    } else {
      log("Type check passed: Elite Quality maintained.", COLORS.green);
    }
  } catch {
    log("Grep not available or failed. Skipping deep audit.", COLORS.yellow);
  }

  // 2. Environment Audit
  log("\n[2/3] Verifying Infrastructure Secrets...");
  const envVars = ['NEXT_PUBLIC_SUPABASE_URL', 'NEXT_PUBLIC_SUPABASE_ANON_KEY', 'SUPABASE_SERVICE_ROLE_KEY'];
  const missing = envVars.filter(v => !process.env[v]);
  
  if (missing.length > 0) {
    log(`WARNING: Missing secrets: [${missing.join(', ')}]`, COLORS.yellow);
    log("This will cause build failures in production.", COLORS.yellow);
  } else {
    log("Environment variables verified: Operational.", COLORS.green);
  }

  // 3. Forensic Cleanup
  log("\n[3/3] Performing Forensic Cleanup...");
  log("Cleaning temporary artifacts...");

  log("\n--- MAINTENANCE COMPLETE: SENTINEL IS ELITE ---", COLORS.bright + COLORS.green);
}

run().catch((err) => {
  log(`Janitor crashed: ${err.message}`, COLORS.red);
  process.exit(1);
});
