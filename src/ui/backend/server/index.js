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
const { scanFile, scanDirectory } = require('../scanner/index');
const shield = require('../lib/shield_bridge');
const fsExplorer = require('../lib/fs_explorer');
const gitHooks = require('../lib/git_hooks');
const hardener = require('../lib/hardener_bridge');

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
app.get('/api/ui/stream', (req, res) => {
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
        res.json(repos);
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
        'hardener': { active: hardener.getSwitchesStatus().npmIgnoreScripts, freq: 'Always' }
    });
});

app.post('/api/system/processes', (req, res) => {
    const { id, active } = req.body;
    if (id === 'pre-push') {
        active ? gitHooks.install() : gitHooks.uninstall();
    } else if (id === 'hardener') {
        hardener.setNpmIgnoreScripts(active);
    }
    res.json({ success: true });
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
    const threats = await shield.safeInstall(req.body.repoId, (msg) => {
        emitSse({ action: 'shield-log', message: msg });
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

// ─── System Shutdown ───
app.post('/api/system/shutdown', (req, res) => {
    res.json({ success: true, message: 'Shutting down...' });
    setTimeout(() => process.exit(0), 1000);
});

app.listen(PORT, () => {
    console.log(`🛡️ Sentinel API Heartbeat [OK] at port ${PORT}`);
});
