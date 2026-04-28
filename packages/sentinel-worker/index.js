import express from "express";
import cors from "cors";
import { createClient } from "@supabase/supabase-js";

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

    // 2. Simulación de Motor de Análisis Pesado (Acá iría el Sentinel Core real)
    // Simulamos un análisis que tarda entre 2 y 5 segundos
    const scanDuration = Math.floor(Math.random() * 3000) + 2000;
    await new Promise(resolve => setTimeout(resolve, scanDuration));

    const vulnerabilitiesFound = Math.floor(Math.random() * 500) + 1;
    const riskScore = Math.random(); // 0.0 to 1.0

    // 3. Escribir resultados finales en la tabla de telemetría (intelligence_events)
    // Esto es el historial persistente.
    const eventHash = `evt_${Date.now()}_${Math.random().toString(36).substring(7)}`;
    const { error: insertError } = await supabase
      .from('intelligence_events')
      .insert({
        user_id: job.user_id,
        repo_hash: job.repo_hash,
        event_hash: eventHash,
        category: 'FORENSIC_SCAN',
        pattern: 'heuristic_scan',
        risk_score: riskScore,
        confidence: 0.95
      });

    if (insertError) {
      console.error(`[JOB ${job.id}] Failed to insert telemetry:`, insertError);
      throw insertError; // Pass to catch block
    }

    // 4. Marcar el job como COMPLETED
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
          risk_score: riskScore
        }
      })
      .eq('id', job.id);

    console.log(`[JOB ${job.id}] Completed successfully in ${executionTime}ms. Vulns: ${vulnerabilitiesFound}`);

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
app.listen(port, () => {
  console.log(`Sentinel Worker HTTP listening on port ${port}`);
});
