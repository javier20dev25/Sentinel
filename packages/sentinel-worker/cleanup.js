/**
 * Quick DB cleanup script — marks ancient PENDING jobs as FAILED
 * Run once to clear the backlog, then delete this file.
 */
import { createClient } from '@supabase/supabase-js';

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

const { data, error } = await supabase
  .from('scan_jobs')
  .update({ 
    status: 'FAILED', 
    error_message: 'Cleared by system: stale job from pre-fix deployment',
    updated_at: new Date().toISOString()
  })
  .in('status', ['PENDING', 'PROCESSING']);

console.log('Cleanup result:', { data, error });
process.exit(0);
