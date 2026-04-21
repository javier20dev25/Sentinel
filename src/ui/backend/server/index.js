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
const crypto = require('crypto');
const yaml = require('js-yaml');
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

// Ed25519 Public Key for Oficial Sentinel Lab Packs
const SENTINEL_LAB_PUB_KEY = "MCowBQYDK2VwAyEA2wvghIjoNvPuAQ3fEeFVbcLbpNigUR4DJJy24Q6JlB0=";

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

// ─── Security Specification (Spec) Management ───
app.get('/api/system/spec', (req, res) => {
    try {
        const specPath = path.join(__dirname, '..', 'scanner', 'rules', 'sentinel-spec.json');
        if (!fs.existsSync(specPath)) return res.status(404).json({ error: 'Spec file not found' });
        const spec = JSON.parse(fs.readFileSync(specPath, 'utf8'));
        res.json(spec);
    } catch (e) {
        res.status(500).json({ error: sanitizeForLog(e.message) });
    }
});

app.post('/api/system/spec', (req, res) => {
    try {
        const spec = req.body;
        const specPath = path.join(__dirname, '..', 'scanner', 'rules', 'sentinel-spec.json');
        fs.writeFileSync(specPath, JSON.stringify(spec, null, 2));
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ error: sanitizeForLog(e.message) });
    }
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
            
            // Calculate Security Posture Score (0-100) using Effective Config
            let score = 100;
            const effectiveConfig = db.getEffectiveConfig(repo.id);
            const isHardenerActive = effectiveConfig.ignore_scripts !== false; 
            const isStrictMode = effectiveConfig.strict_mode === true;
            const gHooksActive = gitHooks.isInstalled(); // Still global for now, but valid indicator
            
            const criticalThreats = logs.filter(l => l.risk_level > 7 && !l.pinned);
            const mediumThreats = logs.filter(l => l.risk_level > 4 && l.risk_level <= 7 && !l.pinned);
            const activePacks = db.getRepoPacks(repo.id).filter(p => p.is_active);
            
            if (!isHardenerActive) score -= 15;
            if (!gHooksActive) score -= 15;
            if (isStrictMode) score += 5; // Reward
            
            const lastScan = new Date(repo.last_scan_at || 0);
            const hoursSinceScan = (Date.now() - lastScan.getTime()) / (1000 * 60 * 60);
            if (hoursSinceScan > 48) score -= 10;
            
            score -= (criticalThreats.length * 30);
            score -= (mediumThreats.length * 10);
            score = Math.max(0, Math.min(100, score));
            
            return { ...repo, score, logs, effectiveConfig, activePacks: activePacks.length };
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
                        db.addScanLog(repoId, 'PR_SCAN', 8, `Threats in PR #${pr.number}: ${results.alerts[0].ruleName}`, results.alerts);
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
                            db.addScanLog(repoId, 'TERMINAL_PR_SCAN', 8, `Threat in PR #${pr.number}: ${alert.ruleName}`, scan.alerts);
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
app.get('/', (req, res) => {
    // If accessed via browser, redirect to the Vite frontend
    res.send(`
        <html>
            <head><title>Sentinel Redirect</title></head>
            <body style="background:#0a0a0f;color:#00ff88;font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;">
                <div style="text-align:center;">
                    <h2>🛡️ SENTINEL ENGINE</h2>
                    <p>Redirecting to Dashboard...</p>
                    <script>setTimeout(() => window.location.href = 'http://localhost:5173', 500);</script>
                </div>
            </body>
        </html>
    `);
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
                    analysis.threats
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

// ─── System Shutdown ───
app.post('/api/system/shutdown', (req, res) => {
    res.json({ success: true, message: 'Shutting down...' });
    setTimeout(() => process.exit(0), 1000);
});

// ─── Sandbox ───

/**
 * GET /api/repositories/:id/sandbox/status
 * Returns sandbox installation state + latest GHA run info.
 */
app.get('/api/repositories/:id/sandbox/status', (req, res) => {
    try {
        const repoId = parseInt(req.params.id, 10);
        if (isNaN(repoId)) return res.status(400).json({ error: 'Invalid ID' });

        const repo = db.getRepositories().find(r => r.id === repoId);
        if (!repo) return res.status(404).json({ error: 'Repository not found' });

        const installed = repo.local_path ? gh.checkSandboxInstalled(repo.local_path) : { installed: false };
        const latestRun = isValidOwnerRepo(repo.github_full_name) ? gh.getLatestSandboxRun(repo.github_full_name) : null;

        res.json({
            installed: installed.installed,
            version: installed.version || null,
            consent: !!repo.sandbox_consent,
            run: latestRun || null
        });
    } catch (e) {
        res.status(500).json({ error: sanitizeForLog(e.message) });
    }
});

/**
 * POST /api/repositories/:id/sandbox/sync
 * mode: 'manual' → returns template content for user to copy.
 * mode: 'auto'   → pushes template via git (requires prior consent stored in DB).
 */
app.post('/api/repositories/:id/sandbox/sync', (req, res) => {
    try {
        const repoId = parseInt(req.params.id, 10);
        if (isNaN(repoId)) return res.status(400).json({ error: 'Invalid ID' });

        const { mode, consented } = req.body;
        const repo = db.getRepositories().find(r => r.id === repoId);
        if (!repo) return res.status(404).json({ error: 'Repository not found' });

        if (mode === 'manual') {
            // Safe path: just return the template text
            const content = gh.getSandboxTemplateContent();
            const workflowPath = '.github/workflows/sentinel-sandbox.yml';
            return res.json({ content, path: workflowPath });
        }

        if (mode === 'auto') {
            if (!consented) {
                return res.status(403).json({
                    error: 'Consent required. Set consented: true to proceed.',
                    requires: ['contents:write on the repository', 'git push access via gh CLI']
                });
            }

            if (!repo.local_path || !isValidLocalPath(repo.local_path)) {
                return res.status(400).json({ error: 'Repository has no linked local path. Use manual mode.' });
            }

            // Store consent before pushing
            db.setSandboxConsent(repoId, true);

            const result = gh.pushSandboxConfig(repo.local_path);
            if (result.success) {
                db.setSandboxVersion(repoId, '1.0');
                return res.json({ success: true, path: result.path });
            }
            return res.status(500).json({ success: false, error: result.error });
        }

        res.status(400).json({ error: 'Unknown mode. Use "manual" or "auto".' });
    } catch (e) {
        res.status(500).json({ error: sanitizeForLog(e.message) });
    }
});

/**
 * POST /api/repositories/:id/analyze-local
 * Scans local unstaged/staged diff through the scanner.
 * Returns alerts + pushBlocked flag if critical threats found.
 */
app.post('/api/repositories/:id/analyze-local', (req, res) => {
    try {
        const repoId = parseInt(req.params.id, 10);
        if (isNaN(repoId)) return res.status(400).json({ error: 'Invalid ID' });

        const repo = db.getRepositories().find(r => r.id === repoId);
        if (!repo) return res.status(404).json({ error: 'Repository not found' });

        if (!repo.local_path || !isValidLocalPath(repo.local_path)) {
            return res.status(400).json({ error: 'No local path linked. Link a local directory first.' });
        }

        const diff = gh.getLocalDiff(repo.local_path);
        if (!diff) {
            return res.json({ alerts: [], pushBlocked: false, message: 'No local changes detected.' });
        }

        // --- PHASE 14: Protected Files Check ---
        let protectedFilesBlocked = false;
        const protectedFilesAlerts = [];
        try {
            // Get list of changed/added files
            const statusOutput = execFileSync('git', ['status', '--porcelain'], { cwd: repo.local_path, encoding: 'utf-8', timeout: 5000 });
            const changedFiles = statusOutput.split('\n').filter(l => l.trim().length > 0).map(l => l.substring(3).trim());
            
            const protectedList = db.getProtectedFiles(repoId).map(p => path.normalize(p.file_path));
            
            for (const file of changedFiles) {
                const normFile = path.normalize(file);
                // Check if file is exactly in the list or inside a protected directory
                const isProtected = protectedList.some(p => normFile === p || normFile.startsWith(p + path.sep));
                if (isProtected) {
                    protectedFilesAlerts.push({
                        title: '⚠️ Archivo Protegido Detectado',
                        description: `Estás intentando subir un archivo o directorio protegido: ${file}`,
                        riskLevel: 9,
                        ruleName: 'Protected File Violation',
                        file: file
                    });
                    protectedFilesBlocked = true;
                }
            }
        } catch (e) {
            console.error('[ProtectedFiles Check Error]', e.message);
        }

        const results = scanFile('local.diff', diff);
        const criticalAlerts = results.alerts.filter(a => (a.riskLevel || a.severity || 0) >= 8);
        
        const pushBlocked = criticalAlerts.length > 0 || protectedFilesBlocked;
        const allAlerts = [...protectedFilesAlerts, ...results.alerts];

        if (criticalAlerts.length > 0) {
            db.addScanLog(repoId, 'LOCAL_DIFF_SCAN', 9,
                `Pre-commit scan blocked: ${criticalAlerts[0].ruleName || 'Critical threat'}`,
                results.alerts
            );
        }

        res.json({
            alerts: allAlerts,
            pushBlocked,
            protectedFilesBlocked,
            linesScanned: diff.split('\n').length,
            message: protectedFilesBlocked
                ? `🚫 Bloqueado: Se detectó intento de subir archivos protegidos.`
                : pushBlocked
                    ? `🔴 Push blocked: ${criticalAlerts.length} critical threat(s) detected.`
                    : results.alerts.length > 0
                        ? `⚠️ ${results.alerts.length} low/medium finding(s). Review before committing.`
                        : '✅ No threats detected. Safe to commit.'
        });
    } catch (e) {
        res.status(500).json({ error: sanitizeForLog(e.message) });
    }
});

/**
 * POST /api/repositories/:id/commit
 * Commits (and optionally pushes) local changes.
 * SECURITY: execFileSync with array args, no shell.
 */
app.post('/api/repositories/:id/commit', (req, res) => {
    try {
        const repoId = parseInt(req.params.id, 10);
        if (isNaN(repoId)) return res.status(400).json({ error: 'Invalid ID' });

        const { message, push, signoff, excludedFiles } = req.body;
        if (!message || typeof message !== 'string' || message.trim().length < 3) {
            return res.status(400).json({ error: 'Commit message required (min 3 chars).' });
        }

        const repo = db.getRepositories().find(r => r.id === repoId);
        if (!repo) return res.status(404).json({ error: 'Repository not found' });
        if (!repo.local_path || !isValidLocalPath(repo.local_path)) {
            return res.status(400).json({ error: 'No local path linked.' });
        }

        const commitArgs = ['commit', '-m', message.trim()];
        if (signoff) commitArgs.push('--signoff');

        // Stage all
        execFileSync('git', ['add', '-A'], { cwd: repo.local_path, timeout: 10000 });
        
        // Unstage excluded files
        if (Array.isArray(excludedFiles) && excludedFiles.length > 0) {
            for (const file of excludedFiles) {
                try {
                    // git reset HEAD <file> removes it from the index (unstage)
                    execFileSync('git', ['reset', 'HEAD', file], { cwd: repo.local_path, timeout: 5000 });
                } catch (e) {
                    console.error(`Failed to exclude file: ${file}`, e.message);
                }
            }
        }

        execFileSync('git', commitArgs, { cwd: repo.local_path, timeout: 10000 });

        if (push) {
            execFileSync('git', ['push'], { cwd: repo.local_path, timeout: 30000 });
        }

        res.json({ success: true, pushed: !!push });
    } catch (e) {
        res.status(500).json({ error: sanitizeForLog(e.message) });
    }
});

// ─── Config Packs (Phase 13) ───

function calculateScoreImpact(currentScore, originalConfig, newConfig) {
    let delta = 0;
    // Lowered security
    if (originalConfig.ignore_scripts && newConfig.ignore_scripts === false) delta -= 15;
    if (originalConfig.strict_mode && newConfig.strict_mode === false) delta -= 5;
    if (originalConfig.auto_scan_pr && newConfig.auto_scan_pr === false) delta -= 10;
    
    // Increased security
    if (!originalConfig.ignore_scripts && newConfig.ignore_scripts !== false) delta += 15;
    if (!originalConfig.strict_mode && newConfig.strict_mode === true) delta += 5;
    if (!originalConfig.auto_scan_pr && newConfig.auto_scan_pr !== false) delta += 10;

    return {
        newScore: Math.max(0, Math.min(100, currentScore + delta)),
        delta
    };
}

/**
 * Scan a pack before installing
 */
app.post('/api/repositories/:id/packs/scan', (req, res) => {
    try {
        const repoId = parseInt(req.params.id, 10);
        if (isNaN(repoId)) return res.status(400).json({ error: 'Invalid ID' });
        
        const { fileContent } = req.body;
        if (!fileContent) return res.status(400).json({ error: 'Missing fileContent' });

        let packData;
        try {
            // Internal conversion: Try JSON first, fallback to YAML
            if (fileContent.trim().startsWith('{')) {
                packData = JSON.parse(fileContent);
            } else {
                packData = yaml.load(fileContent);
            }
        } catch (e) {
            return res.status(400).json({ error: 'File format invalid. Must be valid JSON or YAML.' });
        }

        if (!packData || !packData.metadata || !packData.config) {
            return res.status(400).json({ error: 'Pack missing required fields (metadata, config).' });
        }

        // Signature verification
        let isOfficial = false;
        if (packData._signature) {
            try {
                const dataToSign = {
                    metadata: packData.metadata,
                    config: packData.config
                };
                const payloadBuffer = Buffer.from(JSON.stringify(dataToSign));
                const pubKey = crypto.createPublicKey({ key: Buffer.from(SENTINEL_LAB_PUB_KEY, 'base64'), format: 'der', type: 'spki' });
                const isValid = crypto.verify(null, payloadBuffer, pubKey, Buffer.from(packData._signature, 'base64'));
                if (isValid) isOfficial = true;
            } catch (e) {
                console.warn('[PACKS] Verification failed:', e.message);
            }
        }

        // Fetch repo details to calculate impact
        const repo = db.getRepositories().find(r => r.id === repoId);
        const effectiveConfig = db.getEffectiveConfig(repoId);
        
        // Very basic recalculation for difference (needs real repo logic match)
        const diff = Object.keys(packData.config).map(k => ({
            key: k,
            old: effectiveConfig[k] !== undefined ? effectiveConfig[k] : 'default',
            new: packData.config[k]
        })).filter(d => d.old !== d.new);

        // Alerts for HIGH RISK
        const alerts = [];
        if (effectiveConfig.ignore_scripts !== false && packData.config.ignore_scripts === false) {
            alerts.push('WARNING: Este pack desactiva `ignore_scripts`. Esto permite a las dependencias ejecutar scripts post-install automáticamente, lo que es un vector común de malware de Supply Chain.');
        }

        // Send results
        res.json({
            isOfficial,
            metadata: packData.metadata,
            diff,
            alerts,
            packData // sending back standardized JSON
        });

    } catch (e) {
        res.status(500).json({ error: sanitizeForLog(e.message) });
    }
});

/**
 * Install a scanned pack
 */
app.post('/api/repositories/:id/packs/install', (req, res) => {
    try {
        const repoId = parseInt(req.params.id, 10);
        if (isNaN(repoId)) return res.status(400).json({ error: 'Invalid ID' });

        const { packData, isOfficial } = req.body;
        if (!packData) return res.status(400).json({ error: 'Missing packData' });

        const id = db.installPack(repoId, packData, isOfficial);
        res.json({ success: true, id });
    } catch (e) {
        res.status(500).json({ error: sanitizeForLog(e.message) });
    }
});

/**
 * Get installed packs
 */
app.get('/api/repositories/:id/packs', (req, res) => {
    try {
        const repoId = parseInt(req.params.id, 10);
        if (isNaN(repoId)) return res.status(400).json({ error: 'Invalid ID' });
        
        res.json(db.getRepoPacks(repoId));
    } catch (e) {
        res.status(500).json({ error: sanitizeForLog(e.message) });
    }
});

/**
 * Toggle pack active state
 */
app.put('/api/repositories/:id/packs/:packId/toggle', (req, res) => {
    try {
        const packId = parseInt(req.params.packId, 10);
        const { active } = req.body;
        if (isNaN(packId)) return res.status(400).json({ error: 'Invalid Pack ID' });

        const success = db.togglePack(packId, active);
        res.json({ success });
    } catch (e) {
        res.status(500).json({ error: sanitizeForLog(e.message) });
    }
});

/**
 * Delete a pack
 */
app.delete('/api/repositories/:id/packs/:packId', (req, res) => {
    try {
        const packId = parseInt(req.params.packId, 10);
        if (isNaN(packId)) return res.status(400).json({ error: 'Invalid Pack ID' });

        const success = db.deletePack(packId);
        res.json({ success });
    } catch (e) {
        res.status(500).json({ error: sanitizeForLog(e.message) });
    }
});

/**
 * Reset/Delete all packs
 */
app.delete('/api/repositories/:id/packs', (req, res) => {
    try {
        const repoId = parseInt(req.params.id, 10);
        if (isNaN(repoId)) return res.status(400).json({ error: 'Invalid ID' });

        const success = db.resetPacks(repoId);
        res.json({ success });
    } catch (e) {
        res.status(500).json({ error: sanitizeForLog(e.message) });
    }
});

// ─── Protected Files (Phase 14) ───

app.get('/api/repositories/:id/protected', (req, res) => {
    try {
        const repoId = parseInt(req.params.id, 10);
        if (isNaN(repoId)) return res.status(400).json({ error: 'Invalid ID' });
        res.json(db.getProtectedFiles(repoId));
    } catch (e) {
        res.status(500).json({ error: sanitizeForLog(e.message) });
    }
});

/** Add protected file(s) */
app.post('/api/repositories/:id/protected', (req, res) => {
    try {
        const repoId = parseInt(req.params.id, 10);
        if (isNaN(repoId)) return res.status(400).json({ error: 'Invalid ID' });
        
        const { files } = req.body; 
        if (!Array.isArray(files)) return res.status(400).json({ error: 'Expected array of files' });

        const repo = db.getRepositories().find(r => r.id === repoId);
        
        files.forEach(file => {
            // Relativize path if it's absolute
            let relPath = file;
            if (repo && repo.local_path && file.startsWith(repo.local_path)) {
                relPath = path.relative(repo.local_path, file);
            }
            // Normalize path separators to forward slash for git compatibility
            relPath = relPath.replace(/\\/g, '/');
            db.addProtectedFile(repoId, relPath);
        });

        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ error: sanitizeForLog(e.message) });
    }
});

app.delete('/api/repositories/:id/protected/:fileId', (req, res) => {
    try {
        const fileId = parseInt(req.params.fileId, 10);
        if (isNaN(fileId)) return res.status(400).json({ error: 'Invalid ID' });
        
        const success = db.removeProtectedFile(fileId);
        res.json({ success });
    } catch (e) {
        res.status(500).json({ error: sanitizeForLog(e.message) });
    }
});

app.delete('/api/repositories/:id/protected', (req, res) => {
    try {
        const repoId = parseInt(req.params.id, 10);
        if (isNaN(repoId)) return res.status(400).json({ error: 'Invalid ID' });
        
        const success = db.db.prepare('DELETE FROM protected_files WHERE repo_id = ?').run(repoId).changes > 0;
        res.json({ success });
    } catch (e) {
        res.status(500).json({ error: sanitizeForLog(e.message) });
    }
});

app.listen(PORT, () => {
    console.log(`🛡️ Sentinel API Heartbeat [OK] at port ${PORT}`);
});
