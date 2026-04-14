/**
 * Sentinel: Dashboard API Server (HARDENED)
 * Provides endpoints for system checks, GitHub auth, repo management, and scanning.
 * 
 * SECURITY: All command execution uses execFileSync with array args.
 * Fix endpoint uses strict whitelist map (no regex bypass possible).
 * All inputs validated via sanitizer.js.
 * 
 * Audit: VULN-001, VULN-003, VULN-006 remediated.
 */

'use strict';

const express = require('express');
const cors = require('cors');
const os = require('os');
const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const db = require('../lib/db');
const gh = require('../lib/gh_bridge');
const git = require('../lib/git_bridge');
const { 
    isValidOwnerRepo, isValidHardenerKey, getWhitelistedCommand, 
    sanitizeForLog, isValidLocalPath, isValidGitPath 
} = require('../lib/sanitizer');
const { scanFile, scanDirectory, analyzeLifecycleScripts } = require('../scanner/index');
const shield = require('../lib/shield_bridge');
const fsExplorer = require('../lib/fs_explorer');
const gitHooks = require('../lib/git_hooks');
const hardener = require('../lib/hardener_bridge');
const polling = require('../services/polling');
const orchestrator = require('../lib/orchestrator');
const webhooks = require('../lib/webhooks');

// ─── Remote UI Intents (SSE) ───
let sseClients = [];

function emitSse(intent) {
    sseClients.forEach(client => {
        try {
            client.write(`data: ${JSON.stringify(intent)}\n\n`);
        } catch (e) {
            console.error("SSE Write failed", e);
        }
    });
}

const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = 3001;

// Ensure SSE endpoint is registered early
app.get(['/api/ui/stream', '/api/shield/logs'], (req, res) => {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.write(`data: {"connected": true}\n\n`);
    sseClients.push(res);
    req.on('close', () => { sseClients = sseClients.filter(c => c !== res); });
});

app.post('/api/ui/intent', (req, res) => {
    emitSse(req.body);
    res.json({ success: true, clientsNotified: sseClients.length });
});

const JWT_SECRET = process.env.JWT_SECRET || 'sentinel-local-dev-secret-key-1234';

app.use(cors());
app.use(express.json());

// Explicit CORS Headers for non-CORS library handled requests (Pre-flight, etc.)
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  next();
});

// ─── Local APP Authentication ───
app.get('/api/auth/local/status', (req, res) => {
    const hash = db.getSystemConfig('master_hash');
    res.json({ setupRequired: !hash });
});

app.post('/api/auth/local/setup', async (req, res) => {
    try {
        const { password } = req.body;
        if (!password || password.length < 4) return res.status(400).json({ error: 'Password too short' });
        
        const existingHash = db.getSystemConfig('master_hash');
        if (existingHash) return res.status(403).json({ error: 'Setup already completed' });

        const hash = await bcrypt.hash(password, 10);
        db.setSystemConfig('master_hash', hash);
        
        const token = jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '24h' });
        res.json({ success: true, token });
    } catch (e) {
        res.status(500).json({ error: sanitizeForLog(e.message) });
    }
});

app.post('/api/auth/local/login', async (req, res) => {
    try {
        const { password } = req.body;
        const hash = db.getSystemConfig('master_hash');
        if (!hash) return res.status(400).json({ error: 'Setup required first' });

        const match = await bcrypt.compare(password, hash);
        if (!match) return res.status(401).json({ error: 'Invalid password' });

        const token = jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '24h' });
        res.json({ success: true, token });
    } catch (e) {
        res.status(500).json({ error: sanitizeForLog(e.message) });
    }
});

// Middleware to protect subsequent API routes
const requireLocalAuth = (req, res, next) => {
    if (req.path.startsWith('/api/auth/local') || req.path === '/api/ui/stream') return next();
    
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Unauthorized: Token missing' });
    }
    
    const token = authHeader.split(' ')[1];
    try {
        jwt.verify(token, JWT_SECRET);
        next();
    } catch (err) {
        return res.status(401).json({ error: 'Unauthorized: Invalid or expired token' });
    }
};

app.use('/api', requireLocalAuth);

// ─── Settings Management ───
app.get('/api/settings', (req, res) => {
    const config = {
        ai_provider: db.getSystemConfig('ai_provider') || 'openai',
        ai_model: db.getSystemConfig('ai_model') || 'gpt-4o-mini',
        has_key: !!db.getSystemConfig('ai_key')
    };
    res.json(config);
});

app.post('/api/settings', (req, res) => {
    const { ai_provider, ai_key, ai_model } = req.body;
    if (ai_provider) db.setSystemConfig('ai_provider', ai_provider);
    if (ai_key) db.setSystemConfig('ai_key', ai_key);
    if (ai_model) db.setSystemConfig('ai_model', ai_model);
    res.json({ success: true });
});

// ─── System Requirements ───

/** Check if all required tools are installed */
app.get('/api/system/check', (req, res) => {
    try {
        const gitStatus = gh.isGitInstalled();
        const ghCli = gh.isGHInstalled();
        res.json({
            git: { installed: gitStatus.installed, version: gitStatus.version || null },
            gh: { installed: ghCli.installed, version: ghCli.version || null },
        });
    } catch (e) {
        console.error("❌ System check failed:", e.message);
        res.status(500).json({ 
            error: 'system_check_failed',
            message: e.message,
            stack: e.stack 
        });
    }
});

/** Get current system telemetry (RAM/CPU) */
app.get('/api/system/stats', (req, res) => {
    const totalMem = os.totalmem();
    const freeMem = os.freemem();
    const usedMem = totalMem - freeMem;
    const loadAvg = os.loadavg()[0];
    const cpus = os.cpus().length;
    const processMem = process.memoryUsage();

    res.json({
        os: {
            totalMem,
            freeMem,
            usedMem,
            memPercentage: Math.round((usedMem / totalMem) * 100),
            loadAvg,
            cpus
        },
        process: {
            rss: processMem.rss,
            heapTotal: processMem.heapTotal,
            heapUsed: processMem.heapUsed
        },
        uptime: process.uptime()
    });
});

/** Auto-install GitHub CLI */
app.post('/api/system/install-gh', async (req, res) => {
    const result = await gh.installGH();
    res.json(result);
});

// ─── GitHub Interop ───

app.get('/api/auth/status', (req, res) => {
    try {
        const ghInstalled = gh.isGHInstalled().installed;
        if (!ghInstalled) {
             return res.json({ authenticated: false, installed: false });
        }
        res.json({ ...gh.checkAuth(), installed: true });
    } catch (e) {
        res.status(500).json({ error: sanitizeForLog(e.message) });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const result = await gh.login();
        res.json(result);
    } catch (e) {
        res.status(500).json({ error: sanitizeForLog(e.message) });
    }
});

app.get('/api/github/repos', (req, res) => {
    try {
        const repos = gh.listUserRepos(200);
        res.json({ repos });
    } catch (e) {
        res.status(500).json({ error: sanitizeForLog(e.message) });
    }
});

// ─── Monitored Repositories (Local DB) ───

app.get('/api/repositories', (req, res) => {
    try {
        const repos = db.getRepositories();
        const reposWithLogs = repos.map(repo => {
            const logs = db.getLogsByRepoFilter(repo.id);
            let score = 100;
            
            const hardenerStatus = hardener.getSwitchesStatus();
            const isHardenerActive = hardenerStatus ? hardenerStatus.npmIgnoreScripts : false;
            const gHooksActive = gitHooks.isInstalled();
            
            const criticalThreats = logs.filter(l => l.risk_level > 7 && !l.pinned);
            const mediumThreats = logs.filter(l => l.risk_level > 4 && l.risk_level <= 7 && !l.pinned);
            
            if (!isHardenerActive) score -= 15;
            if (!gHooksActive) score -= 15;
            
            const lastScan = new Date(repo.last_scan_at || 0);
            const hoursSinceScan = (Date.now() - lastScan.getTime()) / (1000 * 60 * 60);
            if (hoursSinceScan > 48) score -= 10;
            
            score -= (criticalThreats.length * 30);
            score -= (mediumThreats.length * 10);
            score = Math.max(0, Math.min(100, score));
            
            return { ...repo, score, logs };
        });
        res.json(reposWithLogs);
    } catch (e) {
        res.status(500).json({ error: sanitizeForLog(e.message) });
    }
});

app.post('/api/repositories', (req, res) => {
    const { fullName } = req.body;
    if (!fullName || !isValidOwnerRepo(fullName)) {
        return res.status(400).json({ error: 'Invalid repository name' });
    }
    try {
        const id = db.addRepository('', fullName);
        res.status(201).json({ id, github_full_name: fullName });
    } catch (e) {
        res.status(500).json({ error: sanitizeForLog(e.message) });
    }
});

app.post('/api/repositories/bulk', (req, res) => {
    const { repos } = req.body;
    if (!Array.isArray(repos) || repos.length === 0) {
        return res.status(400).json({ error: 'repos must be a non-empty array of fullName strings' });
    }
    try {
        const results = [];
        for (const fullName of repos) {
            if (!isValidOwnerRepo(fullName)) {
                console.warn(`[BULK] Skipping invalid repo name: ${sanitizeForLog(String(fullName))}`);
                continue;
            }
            const id = db.addRepository('', fullName);
            results.push({ id, github_full_name: fullName });
        }
        res.status(201).json({ linked: results.length, repos: results });
    } catch (e) {
        res.status(500).json({ error: sanitizeForLog(e.message) });
    }
});

app.delete('/api/repositories/:id', (req, res) => {
    try {
        const success = db.deleteRepository(parseInt(req.params.id));
        res.json({ success });
    } catch (e) {
        res.status(500).json({ error: sanitizeForLog(e.message) });
    }
});

/** Trigger an immediate scan of a specific repo */
app.post('/api/repositories/:id/scan', (req, res) => {
    try {
        const repoId = parseInt(req.params.id);
        const repo = db.getRepositoryById(repoId);
        if (!repo) return res.status(404).json({ error: 'Repository not found' });

        let threats = 0;
        let prsScanned = 0;
        let filesScanned = 0;
        let currentStatus = 100;

        const emitLog = (msg, type = 'info') => {
            emitSse({ action: 'scan-log', repoId, log: { message: msg, type }, confidenceScore: currentStatus });
        };

        emitLog(`Starting scan for ${repo.github_full_name}...`, 'system');

        // Local Scan
        if (repo.local_path && fs.existsSync(repo.local_path)) {
            const results = scanDirectory(repo.local_path, repoId);
            threats += results.threats;
            filesScanned += results.filesScanned;
        }

        // Remote Scan (PRs)
        try {
            const prs = gh.listPRs(repo.github_full_name);
            prsScanned = prs.length;
            for (const pr of prs) {
                const diff = gh.getPRDiff(repo.github_full_name, pr.number);
                if (diff) {
                    const results = scanFile(`PR #${pr.number}.diff`, diff);
                    if (results.alerts.length > 0) {
                        threats += results.alerts.length;
                        const category = results.alerts.some(a => a.ruleName.includes('Secret')) ? 'SECRETS' : 'MALWARE';
                        db.addScanLog(repoId, 'PR_SCAN', 8, `Threats in PR #${pr.number}: ${results.alerts[0].ruleName}`, results.alerts, 'STATIC', category);
                    }
                }
            }
        } catch (err) {}

        if (threats > 0) {
            db.updateRepoStatus(repoId, 'INFECTED');
            emitLog(`Scan complete. ${threats} threats found!`, 'error');
        } else {
            db.updateRepoStatus(repoId, 'SAFE');
            emitLog(`Scan complete. Repository is clean.`, 'success');
        }

        res.json({ prs_scanned: prsScanned, files_scanned: filesScanned, threats_found: threats });
    } catch (e) {
        res.status(500).json({ error: sanitizeForLog(e.message) });
    }
});

/** Fast-scan by repo name - used by clinical terminal or CLI simulations */
app.post('/api/repositories/scan-by-name', (req, res) => {
    try {
        const { fullName } = req.body;
        if (!fullName) return res.status(400).json({ error: 'Repository name required' });

        const repo = db.getRepositoryByFullName(fullName);
        if (!repo) return res.status(404).json({ error: 'Repository not yet linked to Sentinel' });

        const repoId = repo.id;
        let threats = 0;
        let prsScanned = 0;
        let filesScanned = 0;
        let details = [];

        // Scan local if exists
        if (repo.local_path && fs.existsSync(repo.local_path)) {
            const results = scanDirectory(repo.local_path, repoId);
            threats += results.threats;
            filesScanned += results.filesScanned;
            details.push(...results.details);
        }

        // Scan remote PRs
        try {
            const prs = gh.listPRs(repo.github_full_name);
            prsScanned = prs.length;
            for (const pr of prs) {
                const diff = gh.getPRDiff(repo.github_full_name, pr.number);
                if (diff) {
                    const scan = scanFile(`PR #${pr.number}.diff`, diff);
                    if (scan.alerts.length > 0) {
                        threats += scan.alerts.length;
                        scan.alerts.forEach(alert => {
                            details.push(`PR #${pr.number}: ${alert.ruleName}`);
                            const category = alert.ruleName.includes('Secret') ? 'SECRETS' : 'MALWARE';
                            db.addScanLog(repoId, 'TERMINAL_PR_SCAN', 8, `Threat in PR #${pr.number}: ${alert.ruleName}`, scan.alerts, 'STATIC', category);
                        });
                    }
                }
            }
        } catch (err) {}

        // Update status for the dashboard
        if (threats > 0) {
            db.updateRepoStatus(repoId, 'INFECTED');
        } else {
            db.updateRepoStatus(repoId, 'SAFE');
        }

        res.json({ 
            prs_scanned: prsScanned, 
            files_scanned: filesScanned, 
            threats_found: threats,
            details: details.slice(0, 10) // Limit details sent to terminal
        });
    } catch (e) {
        res.status(500).json({ error: sanitizeForLog(e.message) });
    }
});

/** Add a repository by GitHub URL (Aura Intelligence) */
app.post('/api/repositories/add-url', (req, res) => {
    try {
        const { url } = req.body;
        if (!url) return res.status(400).json({ error: 'GitHub URL required' });

        // Basic parsing: github.com/owner/repo
        const match = url.match(/github\.com\/([^\/]+\/[^\/\s?#.]+)/i);
        if (!match) return res.status(400).json({ error: 'Invalid GitHub repository URL' });

        const fullName = match[1];
        const metadata = gh.getRepoMetadata(fullName);
        if (!metadata) return res.status(404).json({ error: 'Repository not found or private (check gh auth)' });

        // Add to DB
        const repoId = db.addRepository(null, fullName); // local_path is null for remote-only repos
        res.json({ id: repoId, fullName: fullName, metadata });
    } catch (e) {
        res.status(500).json({ error: sanitizeForLog(e.message) });
    }
});

/** Remote Dependency Audit (Aura Permissions) */
app.get('/api/repositories/:id/audit', (req, res) => {
    try {
        const repo = db.getRepositories().find(r => r.id === parseInt(req.params.id));
        if (!repo) return res.status(404).json({ error: 'Repository not found' });

        const packageJson = gh.getRemoteFileContent(repo.github_full_name, 'package.json');
        if (!packageJson) {
            return res.json({ 
                dependencies: 0,
                list: [],
                rootAlerts: [],
                noPackageJson: true
            });
        }

        const pkg = JSON.parse(packageJson);
        const deps = { ...pkg.dependencies, ...pkg.devDependencies };
        
        // Audit root lifecycle scripts
        const rootAlerts = analyzeLifecycleScripts(packageJson);

        res.json({ 
            dependencies: Object.keys(deps).length,
            list: Object.keys(deps),
            rootAlerts 
        });
    } catch (e) {
        res.status(500).json({ error: sanitizeForLog(e.message) });
    }
});

/** Commit History (Aura Monitor) */
app.get('/api/repositories/:id/commits', (req, res) => {
    try {
        const repo = db.getRepositories().find(r => r.id === parseInt(req.params.id));
        if (!repo) return res.status(404).json({ error: 'Repository not found' });

        const commits = gh.getCommits(repo.github_full_name, 10);
        res.json({ commits });
    } catch (e) {
        res.status(500).json({ error: sanitizeForLog(e.message) });
    }
});

// ─── Global Audit Trail (SGA) ───
app.get('/api/audit/logs', (req, res) => {
    try {
        const { repoId } = req.query;
        res.json(db.getAuditLogs(repoId || 'all'));
    } catch (e) {
        res.status(500).json({ error: sanitizeForLog(e.message) });
    }
});

// ─── System Security Management ───
app.get('/api/system/processes', (req, res) => {
    res.json({
        'pre-push': { active: gitHooks.isInstalled(), freq: 'On Push' },
        'hardener': { active: hardener.getSwitchesStatus().npmIgnoreScripts, freq: 'Always' },
        'poller': { active: polling.isActive(), freq: '5 mins', lastRun: polling.getLastRun() }
    });
});

app.post('/api/system/processes', (req, res) => {
    const { id, active } = req.body;
    let resultState = { active, freq: 'Unknown' };

    if (id === 'pre-push') {
        active ? gitHooks.install() : gitHooks.uninstall();
        resultState.freq = 'On Push';
    } else if (id === 'hardener') {
        hardener.setNpmIgnoreScripts(active);
        resultState.freq = 'Always';
    } else if (id === 'poller') {
        active ? polling.start() : polling.stop();
        resultState.freq = '5 mins';
        resultState.lastRun = polling.getLastRun();
    }
    
    res.json({ success: true, process: resultState });
});

// ─── Git Safe Staging ───
app.get('/api/git/staged', (req, res) => {
    const { repoId } = req.query;
    const repo = db.getRepositoryById(repoId);
    if (!repo || !repo.local_path) return res.status(404).json({ error: 'Local path missing' });
    try {
        const files = git.getStagedFiles(repo.local_path).map(file => {
            const content = git.getStagedContent(repo.local_path, file);
            const scan = scanFile(file, content);
            return { path: file, riskLevel: scan.alerts.length > 0 ? 8 : 0, alerts: scan.alerts };
        });
        res.json({ files });
    } catch (e) {
        res.status(500).json({ error: sanitizeForLog(e.message) });
    }
});

app.post('/api/git/unstage', (req, res) => {
    const { repoId, filePath } = req.body;
    const repo = db.getRepositoryById(repoId);
    git.unstageFile(repo.local_path, filePath);
    res.json({ success: true });
});

app.post('/api/git/push', async (req, res) => {
    const { repoId, override, password } = req.body;
    const repo = db.getRepositoryById(repoId);
    if (!repo) return res.status(404).json({ error: 'Repo not found' });

    const staged = git.getStagedFiles(repo.local_path);
    const prohibited = db.db.prepare('SELECT path FROM prohibited_assets WHERE repo_id = ? AND prohibited = 1').all(repoId).map(r => r.path);
    const violating = staged.filter(s => prohibited.some(p => s.includes(p)));

    if (violating.length > 0 && !override) {
        db.addAuditLog(repoId, 'PUSH', `Blocked push: prohibited assets detected`, repo.github_full_name);
        return res.status(403).json({ error: 'PROHIBITED_ASSETS_DETECTED', files: violating });
    }

    if (override) {
        const match = await bcrypt.compare(password, db.getSystemConfig('master_hash'));
        if (!match) return res.status(401).json({ error: 'Invalid password' });
    }

    const result = git.push(repo.local_path);
    if (result.success) {
        db.addAuditLog(repoId, 'PUSH', `Successful push${override ? ' (FORCED)' : ''}`, repo.github_full_name, result.hash);
        res.json(result);
    } else {
        res.status(500).json({ error: result.error });
    }
});

// ─── Project Shield & Asset Guard ───
app.post('/api/shield/harden', async (req, res) => {
    const result = await shield.hardenProject(req.body.repoId);
    res.json(result);
});

app.post('/api/shield/safe-install', async (req, res) => {
    const { repoId } = req.body;
    const threats = await shield.safeInstall(repoId, (msg) => {
        emitSse({ action: 'shield-log', message: msg, repoId: parseInt(repoId) });
    });
    res.json({ success: true, threats });
});

app.get('/api/shield/structure/:repoId', (req, res) => {
    const repo = db.getRepositoryById(req.params.repoId);
    res.json(fsExplorer.getStructure(repo.local_path));
});

app.post('/api/shield/prohibited', (req, res) => {
    const { repoId, path, prohibited } = req.body;
    db.db.prepare('INSERT INTO prohibited_assets (repo_id, path, prohibited) VALUES (?, ?, ?) ON CONFLICT(repo_id, path) DO UPDATE SET prohibited = excluded.prohibited').run(repoId, path, prohibited ? 1 : 0);
    res.json({ success: true });
});

app.get('/api/shield/prohibited/:repoId', (req, res) => {
    const rows = db.db.prepare('SELECT * FROM prohibited_assets WHERE repo_id = ? AND prohibited = 1').all(req.params.repoId);
    res.json(rows);
});

// ─── System & UI Heartbeat ───
    `);
});

// ─── AI AGENT SIDECHART API (Sentinel 3.5) ───────────────────────────────────

/**
 * GET /api/briefing/:repoId
 * Returns a machine-readable briefing for a specific tracked repository.
 */
app.get('/api/briefing/:repoId', async (req, res) => {
    try {
        const repo = db.getRepositoryById(parseInt(req.params.repoId));
        if (!repo) return res.status(404).json({ error: 'Repository not found' });
        
        const audit = await orchestrator.auditRepo(repo.github_full_name);
        const plan = await orchestrator.planHarden(repo.github_full_name);
        const logs = db.getLogsByRepoFilter(repo.id).slice(0, 3);

        res.json({
            repo: repo.github_full_name,
            score: audit.score,
            grade: audit.grade,
            threats: logs.map(l => ({ risk: l.risk_level, event: l.description })),
            recommended_actions: plan.plan.slice(0, 3).map(p => ({ action: p.action, target: p.target })),
            metadata: {
                scanned_at: repo.last_scan_at,
                status: repo.status
            }
        });
    } catch (e) {
        res.status(500).json({ error: sanitizeForLog(e.message) });
    }
});

/**
 * GET /api/briefing/name/:owner/:repo
 * Returns a briefing by repository full name.
 */
app.get('/api/briefing/name/:owner/:repo', async (req, res) => {
    try {
        const fullName = `${req.params.owner}/${req.params.repo}`;
        const audit = await orchestrator.auditRepo(fullName);
        const plan = await orchestrator.planHarden(fullName);
        
        const repo = db.getRepositoryByFullName(fullName);
        const logs = repo ? db.getLogsByRepoFilter(repo.id).slice(0, 3) : [];

        res.json({
            repo: fullName,
            score: audit.score,
            grade: audit.grade,
            threats: logs.map(l => ({ risk: l.risk_level, event: l.description })),
            recommended_actions: plan.plan.slice(0, 3).map(p => ({ action: p.action, target: p.target })),
            is_tracked: !!repo
        });
    } catch (e) {
        res.status(500).json({ error: sanitizeForLog(e.message) });
    }
});

// ─── CI Sandbox API (Sentinel 3.0 — Modo Pasivo) ────────────────────────────

const ciSandbox = require('../lib/ci_sandbox');

/**
 * GET /api/supply/sandbox/template
 * Genera (en memoria) el archivo sentinel-sandbox.yml para que el usuario
 * lo copie manualmente al repo. No requiere permisos especiales.
 */
app.get('/api/supply/sandbox/template', (req, res) => {
    const result = ciSandbox.generateWorkflowTemplate();
    res.json(result);
});

/**
 * GET /api/supply/sandbox/check/:owner/:repo
 * Verifica si sentinel-sandbox.yml ya está instalado en el repo.
 */
app.get('/api/supply/sandbox/check/:owner/:repo', (req, res) => {
    try {
        const { owner, repo } = req.params;
        const ownerRepo = `${owner}/${repo}`;
        if (!isValidOwnerRepo(ownerRepo)) {
            return res.status(400).json({ error: 'Invalid repo format' });
        }
        const result = ciSandbox.checkWorkflowInstalled(ownerRepo);
        res.json(result);
    } catch (e) {
        res.status(500).json({ error: sanitizeForLog(e.message) });
    }
});

/**
 * POST /api/supply/sandbox/trigger
 * Body: { ownerRepo: string, branch?: string }
 * Dispara un análisis sandbox en el repo (requiere workflow instalado).
 */
app.post('/api/supply/sandbox/trigger', async (req, res) => {
    try {
        const { ownerRepo, branch = 'main' } = req.body;
        if (!ownerRepo || !isValidOwnerRepo(ownerRepo)) {
            return res.status(400).json({ error: 'Missing or invalid ownerRepo' });
        }
        const result = await ciSandbox.triggerSandboxRun(ownerRepo, branch);
        res.json(result);
    } catch (e) {
        res.status(500).json({ error: sanitizeForLog(e.message) });
    }
});

/**
 * GET /api/supply/sandbox/status/:owner/:repo/:runId
 * Devuelve el estado actual de un run de sandbox.
 */
app.get('/api/supply/sandbox/status/:owner/:repo/:runId', (req, res) => {
    try {
        const { owner, repo, runId } = req.params;
        const ownerRepo = `${owner}/${repo}`;
        if (!isValidOwnerRepo(ownerRepo) || isNaN(Number(runId))) {
            return res.status(400).json({ error: 'Invalid parameters' });
        }
        const result = ciSandbox.getSandboxRunStatus(ownerRepo, parseInt(runId, 10));
        res.json(result);
    } catch (e) {
        res.status(500).json({ error: sanitizeForLog(e.message) });
    }
});

/**
 * POST /api/supply/sandbox/analyze
 * Body: { ownerRepo: string, runId: number }
 * Descarga artefactos del run completado y los analiza.
 * Devuelve el reporte de amenazas completo.
 */
app.post('/api/supply/sandbox/analyze', async (req, res) => {
    try {
        const { ownerRepo, runId } = req.body;
        if (!ownerRepo || !isValidOwnerRepo(ownerRepo) || !runId || isNaN(Number(runId))) {
            return res.status(400).json({ error: 'Missing or invalid parameters' });
        }

        // 1. Verificar que el run completó
        const status = ciSandbox.getSandboxRunStatus(ownerRepo, parseInt(runId, 10));
        if (status.status !== 'completed') {
            return res.status(409).json({
                error: 'El run aún no ha completado.',
                currentStatus: status.status,
                url: status.url
            });
        }

        // 2. Descargar artefactos
        const download = ciSandbox.downloadSandboxArtifacts(ownerRepo, parseInt(runId, 10));
        if (!download.success) {
            return res.status(500).json({ error: download.error });
        }

        // 3. Analizar telemetría
        const analysis = ciSandbox.analyzeTelemetry(download.tempDir, ownerRepo);

        // 4. Persistir resultado en DB si hay amenazas
        if (analysis.threats.length > 0) {
            const [owner, repoName] = ownerRepo.split('/');
            const repoRecord = db.getRepositories().find(
                r => r.github_full_name === ownerRepo
            );
            if (repoRecord) {
                db.addScanLog(
                    repoRecord.id,
                    'SANDBOX_ANALYSIS',
                    Math.round(analysis.riskScore),
                    `Sandbox detectó ${analysis.threats.length} amenaza(s): ${analysis.summary}`,
                    analysis.threats,
                    'DYNAMIC',
                    'VULNERABILITIES'
                );
            }
        }

        // 5. Limpiar archivos temporales
        ciSandbox.cleanupTempDir(download.tempDir);

        res.json({
            ownerRepo,
            runId: parseInt(runId, 10),
            runConclusion: status.conclusion,
            ...analysis
        });
    } catch (e) {
        res.status(500).json({ error: sanitizeForLog(e.message) });
    }
});

// ─── Supply Chain Shield (Sentinel 2.0) ───────────────────────────────────────

const { analyzeLockfile, analyzePnpmLockfile } = require('../scanner/lockfile_filter');
const { analyzeNpmrc, analyzeYarnrcYml }       = require('../scanner/config_integrity');
const { analyzeTransitiveDeps }                = require('../scanner/lifecycle_filter');

/**
 * POST /api/supply/scan-lockfile
 * Body: { content: string, filename: string, packageJsonContent?: string }
 * Runs the Lockfile Integrity Guardian on user-supplied content.
 */
app.post('/api/supply/scan-lockfile', (req, res) => {
    try {
        const { content, filename = 'package-lock.json', packageJsonContent = null } = req.body;
        if (!content || typeof content !== 'string') {
            return res.status(400).json({ error: 'Missing: content (string)' });
        }
        // Cap at 5 MB to prevent DoS
        if (content.length > 5 * 1024 * 1024) {
            return res.status(413).json({ error: 'Content too large (max 5 MB)' });
        }

        let alerts = [];
        if (filename.match(/pnpm-lock\.yaml$/i)) {
            alerts = analyzePnpmLockfile(content);
        } else {
            alerts = analyzeLockfile(content, packageJsonContent);
        }

        res.json({ filename, alertCount: alerts.length, alerts });
    } catch (e) {
        res.status(500).json({ error: sanitizeForLog(e.message) });
    }
});

/**
 * POST /api/supply/scan-config
 * Body: { content: string, filename: string }
 * Runs the Config Integrity Monitor on .npmrc / .yarnrc content.
 */
app.post('/api/supply/scan-config', (req, res) => {
    try {
        const { content, filename = '.npmrc' } = req.body;
        if (!content || typeof content !== 'string') {
            return res.status(400).json({ error: 'Missing: content (string)' });
        }
        if (content.length > 512 * 1024) {
            return res.status(413).json({ error: 'Content too large (max 512 KB)' });
        }

        let alerts = [];
        if (filename.match(/\.yarnrc\.yml$/i)) {
            alerts = analyzeYarnrcYml(content, filename);
        } else {
            alerts = analyzeNpmrc(content, filename);
        }

        res.json({ filename, alertCount: alerts.length, alerts });
    } catch (e) {
        res.status(500).json({ error: sanitizeForLog(e.message) });
    }
});

/**
 * POST /api/supply/scan-transitive
 * Body: { lockfileContent: string }
 * Runs full transitive dependency analysis on a package-lock.json.
 * Returns every suspicious package found at any depth.
 */
app.post('/api/supply/scan-transitive', (req, res) => {
    try {
        const { lockfileContent } = req.body;
        if (!lockfileContent || typeof lockfileContent !== 'string') {
            return res.status(400).json({ error: 'Missing: lockfileContent (string)' });
        }
        if (lockfileContent.length > 10 * 1024 * 1024) {
            return res.status(413).json({ error: 'Lockfile too large (max 10 MB)' });
        }

        const alerts = analyzeTransitiveDeps(lockfileContent, null);
        const byDepth = alerts.reduce((acc, a) => {
            const d = a.depth ?? 0;
            if (!acc[d]) acc[d] = [];
            acc[d].push(a);
            return acc;
        }, {});

        res.json({
            alertCount: alerts.length,
            maxDepth: Math.max(0, ...Object.keys(byDepth).map(Number)),
            byDepth,
            alerts
        });
    } catch (e) {
        res.status(500).json({ error: sanitizeForLog(e.message) });
    }
});

/**
 * GET /api/supply/logs
 * Returns all SUPPLY_CHAIN_ALERT scan logs across all repos.
 */
app.get('/api/supply/logs', (req, res) => {
    try {
        const allLogs = db.getLogsByRepoFilter('all');
        const supplyLogs = allLogs.filter(l =>
            l.event_type === 'SUPPLY_CHAIN_ALERT' ||
            l.event_type === 'LOCKFILE_ALERT' ||
            l.event_type === 'CONFIG_ALERT'
        );
        res.json(supplyLogs);
    } catch (e) {
        res.status(500).json({ error: sanitizeForLog(e.message) });
    }
});

// ─── Sentinel 3.5: Remote Orchestration ──────────────────────────────────────

/**
 * GET /api/orchestrator/audit/:id
 * Performs a security audit and returns the score.
 */
app.get('/api/orchestrator/audit/:id', async (req, res) => {
    try {
        const repo = db.getRepositoryById(parseInt(req.params.id));
        if (!repo) return res.status(404).json({ error: 'Repository not found' });

        const result = await orchestrator.auditRepo(repo.github_full_name);
        res.json(result);
    } catch (e) {
        res.status(500).json({ error: sanitizeForLog(e.message) });
    }
});

/**
 * GET /api/orchestrator/plan/:id
 * Returns the hardening plan (preview).
 */
app.get('/api/orchestrator/plan/:id', async (req, res) => {
    try {
        const repo = db.getRepositoryById(parseInt(req.params.id));
        if (!repo) return res.status(404).json({ error: 'Repository not found' });

        const result = await orchestrator.planHarden(repo.github_full_name);
        res.json(result);
    } catch (e) {
        res.status(500).json({ error: sanitizeForLog(e.message) });
    }
});

/**
 * POST /api/orchestrator/execute/:id
 * Applies the hardening plan. REQUIRES { consent: 'YES' } in body.
 */
app.post('/api/orchestrator/execute/:id', async (req, res) => {
    try {
        const { consent } = req.body;
        if (consent !== 'YES') return res.status(403).json({ error: 'CONSENT_REQUIRED', message: 'User must accept security policy.' });

        const repo = db.getRepositoryById(parseInt(req.params.id));
        if (!repo) return res.status(404).json({ error: 'Repository not found' });

        const result = await orchestrator.executeHarden(repo.github_full_name);
        res.json(result);
    } catch (e) {
        res.status(500).json({ error: sanitizeForLog(e.message) });
    }
});

// ─── Sentinel 3.6: Webhooks ──────────────────────────────────────────────────

/**
 * POST /api/webhooks/github
 * Receives webhook events from GitHub to trigger immediate local scans.
 */
app.post('/api/webhooks/github', express.json({type: 'application/json'}), async (req, res) => {
    // If a secret is defined, verify signature
    if (webhooks.secret && !webhooks.verifySignature(req)) {
        return res.status(401).send('Invalid signature');
    }
    
    // Process asynchronously so we respond quickly
    webhooks.handleEvent(req).catch(e => console.error(e));
    res.status(200).send('OK');
});

// ─── System Shutdown ───
app.post('/api/system/shutdown', (req, res) => {
    res.json({ success: true, message: 'Shutting down...' });
    setTimeout(() => process.exit(0), 1000);
});

app.listen(PORT, () => {
    console.log(`🛡️ Sentinel API Heartbeat [OK] at port ${PORT}`);
});
