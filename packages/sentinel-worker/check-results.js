import { createClient } from '@supabase/supabase-js';

const s = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);

// Get the latest telemetry event
const { data: events } = await s
  .from('intelligence_events')
  .select('*')
  .order('created_at', { ascending: false })
  .limit(1);

if (events && events[0]) {
  const e = events[0];
  console.log('=== LATEST SCAN RESULT ===');
  console.log('Score:', e.risk_score);
  console.log('Verdict:', e.metadata?.verdict);
  console.log('Files Scanned:', e.metadata?.filesScanned);
  console.log('Unique Findings:', e.metadata?.topAlerts?.length);
  console.log('\n--- FINDINGS ---');
  e.metadata?.topAlerts?.forEach((a, i) => {
    console.log(`[${i+1}] ${a.type} -> ${a._file} (line ${a.line_number})`);
    console.log(`    ${a.description}`);
  });
} else {
  console.log('No events found');
}

process.exit(0);
