/**
 * Sentinel: Webhook Handler (GitHub → Sentinel Cloud)
 */

import { NextRequest, NextResponse } from 'next/server';
import { createClient } from '@supabase/supabase-js';
import { encrypt } from '@/lib/crypto';
import crypto from 'crypto';
import { GitHubPR } from '@/types';

// Helper to get Supabase Admin client only when needed (avoids build-time errors)
function getSupabaseAdmin() {
  const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
  
  if (!supabaseUrl || !supabaseServiceKey) {
    throw new Error('Supabase environment variables are missing');
  }
  
  return createClient(supabaseUrl, supabaseServiceKey);
}

// Verify the webhook signature from GitHub
function verifySignature(payload: string, signature: string | null, secret: string): boolean {
  if (!signature) return false;
  
  const hmac = crypto.createHmac('sha256', secret);
  const digest = 'sha256=' + hmac.update(payload).digest('hex');
  
  try {
    return crypto.timingSafeEqual(
      Buffer.from(digest),
      Buffer.from(signature)
    );
  } catch {
    return false;
  }
}

export async function POST(request: NextRequest) {
  const body = await request.text();
  const signature = request.headers.get('x-hub-signature-256');
  const event = request.headers.get('x-github-event');
  
  const webhookSecret = process.env.GITHUB_WEBHOOK_SECRET;
  if (webhookSecret && !verifySignature(body, signature, webhookSecret)) {
    return NextResponse.json({ error: 'Invalid signature' }, { status: 401 });
  }
  
  const payload = JSON.parse(body);
  const supabaseAdmin = getSupabaseAdmin();
  
  switch (event) {
    case 'push':
      return handlePush(payload, supabaseAdmin);
    case 'pull_request':
      return handlePR(payload, supabaseAdmin);
    case 'workflow_run':
      return handleWorkflowComplete(payload, supabaseAdmin);
    default:
      return NextResponse.json({ received: true, event });
  }
}

interface PushPayload {
  repository?: { full_name: string };
  ref?: string;
  commits?: Array<{
    id: string;
    message: string;
    author?: { username: string };
    added: string[];
    modified: string[];
    removed: string[];
  }>;
  pusher?: { name: string };
}

async function handlePush(payload: PushPayload, supabaseAdmin: import('@supabase/supabase-js').SupabaseClient) {
  const repoFullName = payload.repository?.full_name;
  const branch = payload.ref?.replace('refs/heads/', '');
  const commits = payload.commits || [];
  
  const { data: repo } = await supabaseAdmin
    .from('repositories')
    .select('id, user_id')
    .eq('github_full_name', repoFullName)
    .single();
  
  if (!repo) {
    return NextResponse.json({ skipped: true, reason: 'Repo not tracked' });
  }
  
  const encryptedCommits = encrypt({
    commits: commits.map((c) => ({
      sha: c.id,
      message: c.message,
      author: c.author?.username,
      added: c.added,
      modified: c.modified,
      removed: c.removed,
    })),
    branch,
    pusher: payload.pusher?.name,
  });
  
  await supabaseAdmin.from('scan_logs').insert({
    repo_id: repo.id,
    event_type: 'PUSH_INTERCEPTED',
    risk_level: 1,
    description: `Push to ${branch}: ${commits.length} commit(s) by ${payload.pusher?.name}`,
    evidence_metadata: JSON.stringify({ encrypted: encryptedCommits }),
  });
  
  const sensitivePatterns = [
    'package.json', 'package-lock.json', '.npmrc',
    '.github/workflows', '.env', 'Dockerfile',
  ];
  
  const hasSensitiveChanges = commits.some((c) => {
    const allFiles = [...(c.added || []), ...(c.modified || [])];
    return allFiles.some((f: string) => 
      sensitivePatterns.some(p => f.includes(p))
    );
  });
  
  if (hasSensitiveChanges) {
    await supabaseAdmin.from('scan_logs').insert({
      repo_id: repo.id,
      event_type: 'SANDBOX_DISPATCH_QUEUED',
      risk_level: 5,
      description: `Sensitive files modified in push to ${branch}. GitHub Sandbox analysis queued.`,
      evidence_metadata: JSON.stringify({ 
        encrypted: encrypt({ sensitiveFiles: commits.flatMap((c) => [...(c.added || []), ...(c.modified || [])]).filter((f: string) => sensitivePatterns.some(p => f.includes(p))) })
      }),
    });
  }
  
  return NextResponse.json({ processed: true, escalated: hasSensitiveChanges });
}

interface PRPayload {
  action: string;
  pull_request: GitHubPR;
  repository?: { full_name: string };
}

async function handlePR(payload: PRPayload, supabaseAdmin: import('@supabase/supabase-js').SupabaseClient) {
  const action = payload.action;
  const pr = payload.pull_request;
  const repoFullName = payload.repository?.full_name;
  
  if (!['opened', 'synchronize'].includes(action)) {
    return NextResponse.json({ skipped: true, reason: `PR action ${action} ignored` });
  }
  
  const { data: repo } = await supabaseAdmin
    .from('repositories')
    .select('id')
    .eq('github_full_name', repoFullName)
    .single();
  
  if (!repo) {
    return NextResponse.json({ skipped: true, reason: 'Repo not tracked' });
  }
  
  const encryptedPR = encrypt({
    number: pr.number,
    title: pr.title,
    author: pr.user?.login,
    baseBranch: pr.base?.ref,
    headBranch: pr.head?.ref,
    changedFiles: pr.changed_files,
    additions: pr.additions,
    deletions: pr.deletions,
  });
  
  let riskLevel = 2;
  if (pr.author_association === 'FIRST_TIME_CONTRIBUTOR') riskLevel += 3;
  if (pr.changed_files > 50) riskLevel += 2;
  if (pr.title?.toLowerCase().includes('ci') || pr.title?.toLowerCase().includes('workflow')) riskLevel += 1;
  
  riskLevel = Math.min(riskLevel, 10);
  
  await supabaseAdmin.from('scan_logs').insert({
    repo_id: repo.id,
    event_type: 'PR_OPENED',
    risk_level: riskLevel,
    description: `PR #${pr.number}: "${pr.title}" by ${pr.user?.login} (${pr.author_association})`,
    evidence_metadata: JSON.stringify({ encrypted: encryptedPR }),
  });
  
  return NextResponse.json({ processed: true, riskLevel });
}

interface WorkflowPayload {
  workflow_run?: {
    name: string;
    conclusion: string;
    id: number;
    updated_at: string;
    run_started_at?: string;
  };
  repository?: { full_name: string };
}

async function handleWorkflowComplete(payload: WorkflowPayload, supabaseAdmin: import('@supabase/supabase-js').SupabaseClient) {
  const run = payload.workflow_run;
  const repoFullName = payload.repository?.full_name;
  
  if (run?.name !== '🛡️ Sentinel Sandbox Analysis') {
    return NextResponse.json({ skipped: true, reason: 'Not a Sentinel workflow' });
  }
  
  if (run.conclusion !== 'success') {
    return NextResponse.json({ skipped: true, reason: `Workflow ${run.conclusion}` });
  }
  
  const { data: repo } = await supabaseAdmin
    .from('repositories')
    .select('id')
    .eq('github_full_name', repoFullName)
    .single();
  
  if (!repo) return NextResponse.json({ skipped: true });
  
  await supabaseAdmin.from('scan_logs').insert({
    repo_id: repo.id,
    event_type: 'SANDBOX_COMPLETE',
    risk_level: 3,
    description: `Sentinel Sandbox completed for ${repoFullName}. Telemetry artifact ready for download.`,
    evidence_metadata: JSON.stringify({
      encrypted: encrypt({
        runId: run.id,
        conclusion: run.conclusion,
        duration: run.run_started_at ? 
          (new Date(run.updated_at).getTime() - new Date(run.run_started_at).getTime()) / 1000 
          : null,
      })
    }),
  });
  
  return NextResponse.json({ processed: true, runId: run.id });
}
