import { createClient } from '@supabase/supabase-js';

const s = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);

// Get a real user
const { data: users } = await s.auth.admin.listUsers();
const userId = users?.users?.[0]?.id;
console.log('Using user:', userId);

if (!userId) { console.log('No users found'); process.exit(1); }

// Get the repo_hash (repoId) for repos this user has
const { data: repos } = await s.from('repositories').select('*').limit(5);
console.log('Repos:', repos?.map(r => ({ id: r.id, name: r.github_full_name })));

const repoHash = repos?.[0]?.id;
if (!repoHash) { console.log('No repos found'); process.exit(1); }

// Insert a test job
const { data, error } = await s
  .from('scan_jobs')
  .insert({
    user_id: userId,
    repo_full_name: repos[0].github_full_name,
    repo_hash: repoHash,
    pr_number: 2,
    status: 'PENDING',
    metadata: { action: 'FORENSIC_SCAN' }
  })
  .select()
  .single();

console.log('Job result:', data?.id || 'FAILED', error?.message || 'OK');

// Wait a bit for the worker to pick it up, then check status
await new Promise(r => setTimeout(r, 15000));

const { data: job } = await s.from('scan_jobs').select('*').eq('id', data.id).single();
console.log('Job status after 15s:', job?.status, JSON.stringify(job?.metadata));

// Check intelligence_events
const { data: events } = await s.from('intelligence_events').select('*').eq('repo_hash', repoHash).limit(5);
console.log('Telemetry events:', events?.length || 0);
if (events?.length > 0) {
  console.log('Latest event:', JSON.stringify(events[0], null, 2));
}

process.exit(0);
