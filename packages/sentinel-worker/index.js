import express from "express";
import cors from "cors";
import { createClient } from "@supabase/supabase-js";
import { exec } from "child_process";
import { promisify } from "util";
import { createRequire } from "module";
import fs from "fs";

const require = createRequire(import.meta.url);
const execAsync = promisify(exec);

// Inicializar Supabase con Service Role Key
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!supabaseUrl || !supabaseKey) {
  console.error("FATAL: Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY");
  process.exit(1);
}

const supabase = createClient(supabaseUrl, supabaseKey);

const app = express();
app.use(cors());
app.use(express.json());

// Health check para Railway
app.get("/", (req, res) => {
  res.send("Sentinel Engine: ONLINE & LISTENING 🚀");
});

// Función principal de procesamiento (simula AST / Malware scan)
async function processJob(job) {
  const startTime = Date.now();
  console.log(`[JOB ${job.id}] Started processing repo: ${job.repo_full_name}`);

  try {
    // 1. Bloqueo Atómico (Atomic Lock) - Evita doble ejecución
    const { data: lockedJob, error: lockError } = await supabase
      .from('scan_jobs')
      .update({ status: 'PROCESSING', updated_at: new Date().toISOString() })
      .eq('id', job.id)
      .eq('status', 'PENDING')
      .select()
      .single();

    if (lockError || !lockedJob) {
      console.log(`[JOB ${job.id}] Failed to acquire lock (probably taken by another worker). Skipping.`);
      return;
    }

    // 2. Clone the repository
    const tmpDir = `/tmp/repo_${job.id}`;
    console.log(`[JOB ${job.id}] Cloning repository ${job.repo_full_name}...`);
    
    // Fallback if /tmp does not exist (e.g. Windows local testing)
    const cloneDir = fs.existsSync('/tmp') ? tmpDir : `./tmp_repo_${job.id}`;
    
    try {
      if (job.pr_number) {
        // PR scan: clone then fetch the PR head ref to scan the actual PR code
        await execAsync(`git clone --depth 50 https://github.com/${job.repo_full_name} ${cloneDir}`);
        await execAsync(`git fetch origin pull/${job.pr_number}/head:pr-branch && git checkout pr-branch`, { cwd: cloneDir });
        console.log(`[JOB ${job.id}] Checked out PR #${job.pr_number} branch`);
        
        // Collect Diff Stats
        const { stdout: diffStat } = await execAsync(`git diff --shortstat origin/main...head`, { cwd: cloneDir }).catch(() => ({ stdout: '' }));
        job.metadata.diff_stats = diffStat.trim();
        
        // Scan for "Massive Lines" (>35KB)
        const { stdout: largeLines } = await execAsync(`git diff origin/main...head | grep "^+" | awk 'length > 35000' | wc -l`, { cwd: cloneDir }).catch(() => ({ stdout: '0' }));
        job.metadata.large_lines_detected = parseInt(largeLines.trim()) || 0;
      } else {
        // Full repo scan: just clone default branch
        await execAsync(`git clone --depth 1 https://github.com/${job.repo_full_name} ${cloneDir}`);
      }
    } catch (cloneErr) {
      console.error(`[JOB ${job.id}] Clone failed:`, cloneErr.message);
      throw new Error(`Failed to clone repository: ${cloneErr.message}`);
    }

    // 2.5 Fetch Author Metadata from GitHub
    let authorInfo = null;
    const token = job.metadata?.provider_token;
    if (job.pr_number && token) {
      try {
        const prRes = await fetch(`https://api.github.com/repos/${job.repo_full_name}/pulls/${job.pr_number}`, {
          headers: { 'Authorization': `Bearer ${token}` }
        });
        if (prRes.ok) {
          const prData = await prRes.json();
          const userUrl = prData.user.url;
          const userRes = await fetch(userUrl, { headers: { 'Authorization': `Bearer ${token}` } });
          if (userRes.ok) {
            const userData = await userRes.json();
            authorInfo = {
              login: userData.login,
              avatar_url: userData.avatar_url,
              html_url: userData.html_url,
              created_at: userData.created_at,
              public_repos: userData.public_repos,
              followers: userData.followers
            };
          }
        }
      } catch (e) {
        console.error(`[JOB ${job.id}] Failed to fetch author info:`, e);
      }
    }

    // 3. Run the core engine via CJS bridge
    const scanType = job.scan_type || (job.metadata?.action === 'BASELINE_RADIOGRAPHY' ? 'BASELINE' : 'PR');
    console.log(`[JOB ${job.id}] Starting ${scanType} scan on ${cloneDir}...`);
    
    const bridge = require('./scan-bridge.cjs');
    const scanResults = await bridge.scanDirectory(cloneDir, job.repo_hash, 5, { 
      mode: 'cloud', 
      profile: 'DEFAULT',
      scanType: scanType
    });

    const vulnerabilitiesFound = scanResults.threats || 0;
    const riskScore = scanResults.riskScore || 0;
    const topAlerts = scanResults.rawAlerts ? scanResults.rawAlerts.slice(0, 50) : [];

    // 4. Cleanup cloned directory
    console.log(`[JOB ${job.id}] Cleaning up ${cloneDir}...`);
    try {
       fs.rmSync(cloneDir, { recursive: true, force: true });
    } catch(e) {
       console.error(`[JOB ${job.id}] Warning: Could not delete temp dir:`, e);
    }

    // 5. Escribir resultados finales en la tabla de telemetría (intelligence_events)
    // Usamos event_hash como hash criptográfico
    const eventHash = `evt_${Date.now()}_${Math.random().toString(36).substring(7)}`;
    const { error: insertError } = await supabase
      .from('intelligence_events')
      .insert({
        user_id: job.user_id,
        repo_hash: job.repo_hash || 'unknown',
        event_hash: eventHash,
        category: 'FORENSIC_SCAN',
        pattern: 'core_ast_scan',
        risk_score: riskScore,
        confidence: 0.98,
        is_baseline: scanType === 'BASELINE',
        origin: scanType,
        metadata: {
           filesScanned: scanResults.filesScanned,
           verdict: scanResults.verdict,
           topAlerts: topAlerts,
           author: authorInfo,
           diff_stats: job.metadata.diff_stats,
           large_lines: job.metadata.large_lines_detected,
           github_repo_url: `https://github.com/${job.repo_full_name}`
        }
      });

    if (insertError) {
      console.error(`[JOB ${job.id}] Failed to insert telemetry:`, insertError);
      throw insertError; 
    }

    // 5.5 If it's a BASELINE scan, update the repositories table
    if (scanType === 'BASELINE') {
      console.log(`[JOB ${job.id}] Finalizing BASELINE. Updating repository risk level...`);
      await supabase
        .from('repositories')
        .update({
          baseline_risk: riskScore,
          baseline_breakdown: {
            verdict: scanResults.verdict,
            files_scanned: scanResults.filesScanned,
            findings: vulnerabilitiesFound,
            scanned_at: new Date().toISOString()
          }
        })
        .eq('id', job.repo_hash);
    }

    // 6. Marcar el job como COMPLETED
    const executionTime = Date.now() - startTime;
    await supabase
      .from('scan_jobs')
      .update({ 
        status: 'COMPLETED', 
        updated_at: new Date().toISOString(),
        metadata: {
          ...job.metadata,
          vulnerabilities: vulnerabilitiesFound,
          execution_time_ms: executionTime,
          risk_score: riskScore,
          verdict: scanResults.verdict
        }
      })
      .eq('id', job.id);

    console.log(`[JOB ${job.id}] Completed successfully in ${executionTime}ms. Vulns: ${vulnerabilitiesFound}, Score: ${riskScore}`);

  } catch (error) {
    console.error(`[JOB ${job.id}] FAILED:`, error);
    
    // Marcar como FAILED en caso de crash
    await supabase
      .from('scan_jobs')
      .update({ 
        status: 'FAILED', 
        error_message: error.message || 'Unknown error during execution',
        updated_at: new Date().toISOString()
      })
      .eq('id', job.id);
  }
}

// Configurar Listener de Supabase Realtime para capturar nuevos Jobs
const channel = supabase.channel('worker_job_listener')
  .on(
    'postgres_changes',
    {
      event: 'INSERT',
      schema: 'public',
      table: 'scan_jobs',
      filter: "status=eq.PENDING"
    },
    (payload) => {
      const newJob = payload.new;
      console.log(`[EVENT] Received new PENDING job: ${newJob.id}`);
      // Disparar procesamiento asíncrono sin bloquear el event loop
      processJob(newJob);
    }
  )
  .subscribe((status) => {
    if (status === 'SUBSCRIBED') {
      console.log('Realtime connected! Listening for PENDING scan_jobs...');
    }
  });

const port = process.env.PORT || 8080;
app.listen(port, async () => {
  console.log(`Sentinel Worker HTTP listening on port ${port}`);
  
  // Procesar jobs que quedaron pendientes mientras el worker estaba offline
  console.log("Checking for existing PENDING jobs...");
  const { data: existingJobs } = await supabase
    .from('scan_jobs')
    .select('*')
    .eq('status', 'PENDING');
  
  if (existingJobs && existingJobs.length > 0) {
    console.log(`Found ${existingJobs.length} existing PENDING jobs. Processing...`);
    for (const job of existingJobs) {
      await processJob(job);
    }
  }
});
