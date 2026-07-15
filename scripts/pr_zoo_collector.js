/**
 * PR Zoo Collector (v1.0)
 *
 * Fetches real PR diffs from public repos, caches them locally
 * as .patch files, and builds a reproducible benchmark dataset.
 *
 * Usage:
 *   node scripts/pr_zoo_collector.js --count=100
 *   node scripts/pr_zoo_collector.js --repos=facebook/react,nodejs/node --count=20
 *
 * The zoo lives in data/pr_zoo/ and never changes once collected.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const https = require('https');
const crypto = require('crypto');
const { produce: baselineProduce } = require('../packages/sentinel-core/adapters/baseline_adapter');

const ZOO_DIR = path.join(__dirname, '..', 'data', 'pr_zoo');
const PATCHES_DIR = path.join(ZOO_DIR, 'patches');
const MANIFEST_PATH = path.join(ZOO_DIR, 'manifest.json');
const GITHUB_TOKEN = process.env.GITHUB_TOKEN || '';

const DEFAULT_REPOS = [
  { owner: 'facebook', repo: 'react', profile: 'frontend' },
  { owner: 'vercel', repo: 'next.js', profile: 'frontend' },
  { owner: 'expressjs', repo: 'express', profile: 'infrastructure' },
  { owner: 'microsoft', repo: 'TypeScript', profile: 'language' },
  { owner: 'nodejs', repo: 'node', profile: 'infrastructure' },
  { owner: 'lodash', repo: 'lodash', profile: 'libraries' },
  { owner: 'vitejs', repo: 'vite', profile: 'frontend' },
  { owner: 'supabase', repo: 'supabase', profile: 'backend' },
  { owner: 'nextauthjs', repo: 'next-auth', profile: 'infrastructure' },
  { owner: 'npm', repo: 'cli', profile: 'cli' },
];

const args = process.argv.slice(2);
const targetCount = parseInt(args.find(a => a.startsWith('--count='))?.split('=')[1] || 50);
const customReposArg = args.find(a => a.startsWith('--repos='));
const repos = customReposArg
  ? customReposArg.split('=')[1].split(',').map(r => {
      const [owner, repo] = r.split('/');
      return { owner, repo, profile: 'custom' };
    })
  : DEFAULT_REPOS;

const freshOnly = args.includes('--fresh'); // skip if already cached

// Init directories
if (!fs.existsSync(PATCHES_DIR)) fs.mkdirSync(PATCHES_DIR, { recursive: true });

// Load existing manifest
let manifest = { version: 1, generated: null, entries: [], stats: {} };
if (fs.existsSync(MANIFEST_PATH)) {
  try { manifest = JSON.parse(fs.readFileSync(MANIFEST_PATH, 'utf8')); } catch (e) {}
}

const existingIds = new Set(manifest.entries.map(e => e.id));

// ── Helpers ──

function fetchGitHub(endpoint) {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: 'api.github.com',
      path: endpoint,
      headers: {
        'User-Agent': 'Sentinel-PR-Zoo-Collector-v1',
        Accept: 'application/vnd.github.v3+json',
        ...(GITHUB_TOKEN ? { Authorization: `token ${GITHUB_TOKEN}` } : {}),
      },
    };
    https.get(options, (res) => {
      if (res.statusCode === 403) return reject(new Error('GitHub API Rate Limit'));
      if (res.statusCode === 404) return reject(new Error('Not found'));
      let data = '';
      res.on('data', (c) => (data += c));
      res.on('end', () => {
        try { resolve(JSON.parse(data)); } catch (e) { reject(e); }
      });
    }).on('error', reject);
  });
}

function safeId(owner, repo, pr) {
  return `${owner}_${repo.replace(/[^a-zA-Z0-9]/g, '_')}_${pr}`;
}

function patchPath(id) {
  return path.join(PATCHES_DIR, `${id}.patch`);
}
function metaPath(id) {
  return path.join(PATCHES_DIR, `${id}.json`);
}

async function collectRepo(owner, repo, profile, limit) {
  console.log(`\n[FETCH] ${owner}/${repo} — fetching up to ${limit} PRs...`);

  const prs = await fetchGitHub(`/repos/${owner}/${repo}/pulls?state=open&per_page=${limit}&sort=created&direction=desc`);
  if (!Array.isArray(prs)) return 0;

  let collected = 0;

  for (const pr of prs) {
    const id = safeId(owner, repo, pr.number);

    if (freshOnly && existingIds.has(id)) {
      continue;
    }

    const patchFile = patchPath(id);
    const metaFile = metaPath(id);

    try {
      // Fetch file diffs
      const files = await fetchGitHub(`/repos/${owner}/${repo}/pulls/${pr.number}/files`);
      if (!Array.isArray(files) || files.length === 0) continue;

      // Build patch content
      const patchLines = [];
      for (const f of files) {
        if (f.patch) {
          patchLines.push(`--- a/${f.filename}`);
          patchLines.push(`+++ b/${f.filename}`);
          patchLines.push(f.patch);
          patchLines.push('');
        }
      }

      if (patchLines.length === 0) continue;
      const patchContent = patchLines.join('\n');
      const patchHash = crypto.createHash('sha256').update(patchContent).digest('hex');

      // Save patch
      fs.writeFileSync(patchFile, patchContent, 'utf8');

      // Build source metadata (for baseline adapter)
      const source = {
        id,
        repo: `${owner}/${repo}`,
        pr: pr.number,
        url: pr.html_url || `https://github.com/${owner}/${repo}/pull/${pr.number}`,
        profile,
        description: (pr.title || '').substring(0, 200),
        state: pr.state,
        created_at: pr.created_at,
        updated_at: pr.updated_at,
        sha: pr.head?.sha || '',
        user: pr.user?.login || '',
        labels: (pr.labels || []).map((l) => l.name),
        files_changed: files.length,
        additions: pr.additions || files.reduce((s, f) => s + (f.additions || 0), 0),
        deletions: pr.deletions || files.reduce((s, f) => s + (f.deletions || 0), 0),
        patchSize: patchContent.length,
        patchHash,
        language: 'unknown',
      };

      // Run baseline analysis
      let baselineResult = null;
      try {
        baselineResult = baselineProduce(source, { isAudit: true });
      } catch (e) {
        baselineResult = { error: e.message };
      }

      // Save metadata + baseline result
      const meta = {
        source,
        baseline: baselineResult
          ? {
              verdict: baselineResult.verdict,
              riskScore: baselineResult.riskScore,
              findings: baselineResult.statistics.totalFindings,
              capabilities: baselineResult.capabilities,
            }
          : null,
        collected_at: new Date().toISOString(),
      };
      fs.writeFileSync(metaFile, JSON.stringify(meta, null, 2), 'utf8');

      // Add to manifest entry (lightweight)
      manifest.entries.push({
        id,
        repo: `${owner}/${repo}`,
        pr: pr.number,
        profile,
        title: (pr.title || '').substring(0, 120),
        user: pr.user?.login || '',
        files_changed: files.length,
        patchSize: patchContent.length,
        patchHash,
        baselineVerdict: baselineResult?.verdict || 'ERROR',
        baselineRiskScore: baselineResult?.riskScore || 0,
        collected_at: meta.collected_at,
      });

      collected++;
      existingIds.add(id);
      console.log(`  ✓ #${pr.number} — ${pr.title || 'untitled'} (${files.length} files, ${patchContent.length}b)`);
    } catch (e) {
      console.error(`  ✗ #${pr.number} — ${e.message}`);
    }
  }

  return collected;
}

async function start() {
  console.log('═'.repeat(50));
  console.log('PR ZOO COLLECTOR v1.0');
  console.log(`Target: ${targetCount} PRs across ${repos.length} repos`);
  console.log(`Cache: ${PATCHES_DIR}`);
  console.log(`Existing entries: ${manifest.entries.length}`);
  console.log(`Fresh only: ${freshOnly}`);
  console.log('═'.repeat(50));

  const base = Math.floor(targetCount / repos.length);
  const remainder = targetCount % repos.length;
  let totalCollected = 0;

  for (let i = 0; i < repos.length; i++) {
    const r = repos[i];
    const limit = base + (i < remainder ? 1 : 0);
    if (limit <= 0) continue;
    try {
      const count = await collectRepo(r.owner, r.repo, r.profile, limit);
      totalCollected += count;
    } catch (e) {
      console.error(`[ERROR] ${r.owner}/${r.repo}: ${e.message}`);
    }
  }

  // Finalize manifest
  manifest.generated = new Date().toISOString();
  manifest.stats = {
    totalEntries: manifest.entries.length,
    totalCollectedThisRun: totalCollected,
    reposUsed: repos.length,
    reposList: repos.map((r) => `${r.owner}/${r.repo}`),
    totalPatchBytes: manifest.entries.reduce((s, e) => s + (e.patchSize || 0), 0),
    uniqueRepos: new Set(manifest.entries.map((e) => e.repo)).size,
  };

  fs.writeFileSync(MANIFEST_PATH, JSON.stringify(manifest, null, 2), 'utf8');

  console.log('\n' + '═'.repeat(50));
  console.log(`COLLECTION COMPLETE`);
  console.log(`New this run: ${totalCollected}`);
  console.log(`Total in zoo: ${manifest.entries.length}`);
  console.log(`Patches saved: ${manifest.stats.totalPatchBytes} bytes`);
  console.log(`Manifest: ${MANIFEST_PATH}`);
  console.log('═'.repeat(50));
}

start().catch(console.error);
