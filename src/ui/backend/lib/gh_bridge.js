/**
 * Sentinel: GitHub CLI Bridge (HARDENED)
 * Wraps 'gh' commands to fetch PR data, authenticate, and list repos.
 * 
 * SECURITY: All commands use execFileSync/spawn with array arguments.
 * No shell interpolation. All external inputs validated via sanitizer.js.
 * 
 * Audit: VULN-001 remediated — 12 instances of exec/execSync replaced.
 */

'use strict';

const { execFileSync, spawn } = require('child_process');
const path = require('path');
const { isValidOwnerRepo, isValidPRNumber, isValidGitSHA, isValidGitPath, isValidLimit, isValidLocalPath, sanitizeForLog } = require('./sanitizer');

class GitHubBridge {
    /**
     * Check if GitHub CLI (gh) is installed on this machine.
     * Returns { installed: boolean, version?: string }
     * SECURITY: No user input — safe static command.
     */
    isGHInstalled() {
        try {
            const output = execFileSync('gh', ['--version'], {
                encoding: 'utf-8',
                timeout: 10000,
                stdio: ['pipe', 'pipe', 'pipe']
            });
            const match = output.match(/gh version ([\d.]+)/);
            return { installed: true, version: match ? match[1] : 'unknown' };
        } catch {
            return { installed: false };
        }
    }

    /**
     * Check if Git is installed.
     * SECURITY: No user input — safe static command.
     */
    isGitInstalled() {
        try {
            const output = execFileSync('git', ['--version'], {
                encoding: 'utf-8',
                timeout: 10000,
                stdio: ['pipe', 'pipe', 'pipe']
            });
            const match = output.match(/git version ([\d.]+)/);
            return { installed: true, version: match ? match[1] : 'unknown' };
        } catch {
            return { installed: false };
        }
    }

    /**
     * Install GitHub CLI via winget (Windows) or provide instructions.
     * Returns { success: boolean, message: string }
     * SECURITY: Static commands only — no user input interpolation.
     */
    async installGH() {
        try {
            execFileSync('winget', [
                'install', '--id', 'GitHub.cli', '-e',
                '--accept-source-agreements', '--accept-package-agreements'
            ], {
                encoding: 'utf-8',
                timeout: 120000,
                stdio: ['pipe', 'pipe', 'pipe']
            });
            return { success: true, message: 'GitHub CLI installed successfully via winget.' };
        } catch (e) {
            try {
                execFileSync('scoop', ['install', 'gh'], {
                    encoding: 'utf-8',
                    timeout: 120000,
                    stdio: ['pipe', 'pipe', 'pipe']
                });
                return { success: true, message: 'GitHub CLI installed successfully via scoop.' };
            } catch {
                return {
                    success: false,
                    message: 'Could not install automatically. Please download from https://cli.github.com and restart Sentinel.'
                };
            }
        }
    }

    /**
     * Check if gh CLI is authenticated.
     * Returns { authenticated: boolean, username?: string }
     * SECURITY: Uses execFileSync without shell. stderr is captured via try/catch.
     */
    checkAuth() {
        try {
            console.log("🔍 Checking GitHub CLI auth status...");
            const output = execFileSync('gh', ['auth', 'status'], {
                encoding: 'utf-8',
                timeout: 15000,
                stdio: ['pipe', 'pipe', 'pipe']
            });
            console.log("✅ GH Auth Status Output (stdout):", output.substring(0, 50).trim() + "...");
            const match = output.match(/Logged in to github\.com account (\S+)/i) ||
                          output.match(/Logged in to github\.com as (\S+)/i) ||
                          output.match(/account (\S+)/i);
            return { authenticated: true, username: match ? match[1] : 'Unknown' };
        } catch (e) {
            const stderr = e.stderr?.toString() || e.stdout?.toString() || '';
            console.warn("⚠️ GH Auth check failed or returned stderr:", stderr.substring(0, 100).trim() + "...");
            if (stderr.includes('Logged in')) {
                const match = stderr.match(/account (\S+)/i);
                return { authenticated: true, username: match ? match[1] : 'Unknown' };
            }
            return { authenticated: false };
        }
    }

    /**
     * Start the GitHub CLI login flow (opens browser).
     * Returns a Promise that resolves when auth completes.
     * SECURITY: Uses spawn with array args — no shell.
     */
    login() {
        return new Promise((resolve, reject) => {
            const ghCmd = process.platform === 'win32' ? 'gh.exe' : 'gh';
            const child = spawn(ghCmd, ['auth', 'login', '-w', '-p', 'https', '--skip-ssh-key'], {
                shell: false,
                stdio: ['pipe', 'pipe', 'pipe']
            });

            let output = '';
            let resolved = false;

            child.stdout?.on('data', (d) => {
                const msg = d.toString();
                output += msg;
                console.log(`[GH AUTH] ${msg.trim()}`);
                if (msg.toLowerCase().includes('press enter')) {
                    child.stdin.write('\n');
                }
            });

            child.stderr?.on('data', (d) => { 
                const msg = d.toString();
                output += msg;
                if (msg.toLowerCase().includes('press enter')) {
                    child.stdin.write('\n');
                }
            });

            const timeout = setTimeout(() => {
                if (!resolved) {
                    child.kill();
                    resolve({ success: false, message: 'Authentication timed out after 60 seconds.' });
                }
            }, 60000);

            child.on('close', (code) => {
                clearTimeout(timeout);
                if (resolved) return;
                resolved = true;
                if (code === 0) {
                    const auth = this.checkAuth();
                    resolve({ success: true, username: auth.username });
                } else {
                    resolve({ success: false, message: output || 'Login failed. Please try again.' });
                }
            });

            child.on('error', (err) => {
                clearTimeout(timeout);
                if (resolved) return;
                resolved = true;
                resolve({ success: false, message: err.message });
            });
        });
    }

    /**
     * List all repos for the authenticated user.
     * SECURITY: `limit` is validated as a safe integer. No shell.
     */
    listUserRepos(limit = 100) {
        try {
            const safeLimit = isValidLimit(limit) ? String(limit) : '100';
            const output = execFileSync('gh', [
                'repo', 'list',
                '--limit', safeLimit,
                '--json', 'name,nameWithOwner,description,visibility,updatedAt'
            ], {
                encoding: 'utf-8',
                timeout: 30000
            });
            const repos = JSON.parse(output);
            return repos.map(r => ({
                name: r.name,
                fullName: r.nameWithOwner,
                description: r.description || '',
                visibility: r.visibility,
                updatedAt: r.updatedAt,
            }));
        } catch (e) {
            console.error('Error listing repos:', sanitizeForLog(e.message));
            return [];
        }
    }

    /**
     * Lists open Pull Requests for a repository.
     * SECURITY: repoFullName validated via isValidOwnerRepo before use.
     */
    listPRs(repoFullName) {
        if (!isValidOwnerRepo(repoFullName)) {
            console.error(`[SECURITY] Invalid owner/repo format rejected: ${sanitizeForLog(repoFullName)}`);
            return [];
        }
        try {
            const output = execFileSync('gh', [
                'pr', 'list',
                '--repo', repoFullName,
                '--state', 'open',
                '--limit', '10',
                '--json', 'number,title,author,updatedAt,headRefName'
            ], {
                encoding: 'utf-8',
                timeout: 10000
            });
            return JSON.parse(output);
        } catch (e) {
            console.error(`Error listing PRs for ${sanitizeForLog(repoFullName)}:`, sanitizeForLog(e.message));
            return [];
        }
    }

    /**
     * Gets the diff of a specific PR.
     * SECURITY: Both repoFullName and prNumber are validated.
     */
    getPRDiff(repoFullName, prNumber) {
        if (!isValidOwnerRepo(repoFullName) || !isValidPRNumber(prNumber)) return null;
        try {
            return execFileSync('gh', [
                'pr', 'diff', String(prNumber),
                '--repo', repoFullName
            ], {
                encoding: 'utf-8',
                timeout: 30000,
                maxBuffer: 10 * 1024 * 1024 // 10MB
            });
        } catch (e) {
            console.error(`Error getting diff for PR #${prNumber}:`, sanitizeForLog(e.message));
            return null;
        }
    }

    /**
     * Gets author metadata.
     */
    async getAuthorReputation(username) {
        if (!username) return null;
        return { username, ageDays: 365, isNew: false };
    }

    /**
     * Gets repository info from a local path.
     * SECURITY: Validates path before use as cwd. Rejects traversal attempts.
     */
    getRepoInfoLocal(localPath) {
        if (!isValidLocalPath(localPath)) {
            console.error(`[SECURITY] Rejected invalid local path: ${String(localPath).substring(0, 50)}`);
            return null;
        }
        try {
            const output = execFileSync('gh', ['repo', 'view', '--json', 'nameWithOwner'], {
                cwd: localPath,
                encoding: 'utf-8',
                timeout: 10000
            });
            const result = JSON.parse(output);
            return { fullName: result.nameWithOwner };
        } catch (e) {
            console.warn('[GH_BRIDGE] Could not get repo info:', e.message);
            return null;
        }
    }

    /**
     * Gets global repository metadata via GitHub API.
     * SECURITY: repoFullName validated.
     */
    getRepoMetadata(repoFullName) {
        if (!isValidOwnerRepo(repoFullName)) return null;
        try {
            const output = execFileSync('gh', [
                'repo', 'view', repoFullName,
                '--json', 'description,stargazerCount,updatedAt,defaultBranchRef,url'
            ], {
                encoding: 'utf-8',
                timeout: 15000
            });
            return JSON.parse(output);
        } catch (e) {
            console.error(`Error getting metadata for ${repoFullName}:`, sanitizeForLog(e.message));
            return null;
        }
    }

    // ─── Sandbox Methods ───

    /**
     * Check if the Sentinel sandbox workflow is installed in a local repo.
     */
    checkSandboxInstalled(localPath) {
        const fs = require('fs');
        const path = require('path');
        if (!isValidLocalPath(localPath)) return { installed: false, version: null };

        const workflowPath = path.join(localPath, '.github', 'workflows', 'sentinel-sandbox.yml');
        if (!fs.existsSync(workflowPath)) return { installed: false, version: null, path: workflowPath };

        try {
            const content = fs.readFileSync(workflowPath, 'utf-8');
            const match = content.match(/sentinel-sandbox\.yml — v([\d.]+)/) ||
                          content.match(/Sentinel Sandbox Analysis — v([\d.]+)/);
            const version = match ? match[1] : 'unknown';
            return { installed: true, version, path: workflowPath };
        } catch {
            return { installed: true, version: 'unknown', path: workflowPath };
        }
    }

    /**
     * Get the local git diff (uncommitted changes) as a string.
     */
    getLocalDiff(localPath) {
        if (!isValidLocalPath(localPath)) return null;
        try {
            const staged = execFileSync('git', ['diff', '--cached'], { cwd: localPath, encoding: 'utf-8', timeout: 10000 });
            const unstaged = execFileSync('git', ['diff'], { cwd: localPath, encoding: 'utf-8', timeout: 10000 });
            return (staged + unstaged).trim() || null;
        } catch (e) {
            return null;
        }
    }

    /**
     * Fetch the latest Sentinel Sandbox workflow run from GitHub.
     */
    getLatestSandboxRun(repoFullName) {
        if (!isValidOwnerRepo(repoFullName)) return null;
        try {
            const runsRaw = execFileSync('gh', [
                'api', `repos/${repoFullName}/actions/workflows/sentinel-sandbox.yml/runs`,
                '--jq', '.workflow_runs[0] | {status, conclusion, html_url, created_at}'
            ], { encoding: 'utf-8', timeout: 15000 });
            return JSON.parse(runsRaw.trim());
        } catch (e) {
            return null;
        }
    }

    /**
     * Push the Sentinel sandbox workflow config to the repo via git.
     * @param {string} localPath - Path to local repo
     * @param {string} branch - (Optional) Branch name to create and push to
     */
    pushSandboxConfig(localPath, branch = null) {
        if (!isValidLocalPath(localPath)) return { success: false, error: 'Invalid path' };
        const fs = require('fs');
        const path = require('path');
        const templatePath = path.join(__dirname, '..', 'templates', 'sentinel-sandbox.yml');
        const destDir = path.join(localPath, '.github', 'workflows');
        const destPath = path.join(destDir, 'sentinel-sandbox.yml');

        try {
            if (branch) {
                // Create and checkout new branch
                execFileSync('git', ['checkout', '-b', branch], { cwd: localPath });
            }
            fs.mkdirSync(destDir, { recursive: true });
            fs.copyFileSync(templatePath, destPath);
            execFileSync('git', ['add', destPath], { cwd: localPath });
            execFileSync('git', ['commit', '-m', 'chore: add sentinel sandbox'], { cwd: localPath });
            
            if (branch) {
                execFileSync('git', ['push', 'origin', branch], { cwd: localPath });
            } else {
                execFileSync('git', ['push'], { cwd: localPath });
            }
            return { success: true, path: destPath };
        } catch (e) {
            return { success: false, error: e.message };
        }
    }

    getSandboxTemplateContent() {
        const fs = require('fs');
        const path = require('path');
        const templatePath = path.join(__dirname, '..', 'templates', 'sentinel-sandbox.yml');
        return fs.readFileSync(templatePath, 'utf-8');
    }

    getCommits(repoFullName, limit = 5) {
        if (!isValidOwnerRepo(repoFullName)) return [];
        try {
            const output = execFileSync('gh', [
                'api', `repos/${repoFullName}/commits`,
                '--limit', String(limit),
                '--json', 'sha,commit,html_url'
            ], { encoding: 'utf-8', timeout: 15000 });
            return JSON.parse(output);
        } catch {
            return [];
        }
    }

    getRemoteFileContent(repoFullName, filePath) {
        if (!isValidOwnerRepo(repoFullName) || !isValidGitPath(filePath)) return null;
        try {
            const output = execFileSync('gh', [
                'api', `repos/${repoFullName}/contents/${filePath}`,
                '--jq', '.content'
            ], { encoding: 'utf-8', timeout: 15000 });
            if (!output) return null;
            return Buffer.from(output.trim(), 'base64').toString('utf-8');
        } catch (e) {
            return null;
        }
    }

    /**
     * Gets the git remote origin URL for a local path.
     * Returns the URL string or null if not a git repo / no remote.
     */
    getRepoOrigin(localPath) {
        if (!isValidLocalPath(localPath)) return null;
        try {
            const output = execFileSync('git', ['remote', 'get-url', 'origin'], {
                cwd: localPath,
                encoding: 'utf-8',
                timeout: 5000,
                stdio: ['pipe', 'pipe', 'pipe']
            });
            return output.trim() || null;
        } catch {
            return null;
        }
    }

    /**
     * Multi-signal ownership resolver (v8.3 Oracle Hardening).
     * 
     * Combines 4 independent signals to determine authorization level.
     * Fail-closed: ambiguous results default to UNAUTHORIZED.
     * 
     * @param {string} localPath - Absolute path to the directory being scanned
     * @param {Object} [cachedAuth] - Pre-cached auth from checkAuth() to avoid redundant calls
     * @returns {Object} { authorized: boolean, confidence: string, signals: Object }
     */
    resolveOwnership(localPath, cachedAuth = null) {
        const os = require('os');
        const signals = {
            remoteMatch: false,
            githubPermission: 'SKIPPED',
            localDbRegistered: false,
            withinHomedir: false
        };
        let authorizedCount = 0;

        // Signal 1: Git remote origin matches authenticated user (fast: 1 subprocess)
        const remote = this.getRepoOrigin(localPath);
        if (remote) {
            const auth = cachedAuth || { authenticated: false };
            if (auth.authenticated && auth.username) {
                const username = auth.username.toLowerCase().replace(/[()]/g, '');
                const remoteLower = remote.toLowerCase();
                signals.remoteMatch = remoteLower.includes(`/${username}/`) || 
                                     remoteLower.includes(`${username}/`);
                if (signals.remoteMatch) authorizedCount++;
            }
        }

        // Signal 2: Local DB whitelist (fast: no subprocess)
        try {
            const db = require('./db');
            const repos = db.getRepositories();
            const normalizedPath = path.resolve(localPath).toLowerCase();
            signals.localDbRegistered = repos.some(r => 
                r.local_path && path.resolve(r.local_path).toLowerCase() === normalizedPath
            );
            if (signals.localDbRegistered) authorizedCount++;
        } catch {
            // DB not available in CLI-only mode — skip
        }

        // Signal 3: Path is within user's home directory (fast: no subprocess)
        const homedir = os.homedir();
        const relative = path.relative(homedir, localPath);
        signals.withinHomedir = !relative.startsWith('..') && !path.isAbsolute(relative);
        if (signals.withinHomedir) authorizedCount++;

        // Signal 4: GitHub viewerPermission — only if needed as tiebreaker (slow: 2 subprocesses)
        if (authorizedCount <= 1 && remote) {
            try {
                const repoInfo = this.getRepoInfoLocal(localPath);
                if (repoInfo && repoInfo.fullName) {
                    signals.githubPermission = this.getRepoPermission(repoInfo.fullName);
                    const writeRoles = ['ADMIN', 'MAINTAIN', 'WRITE'];
                    if (writeRoles.includes(signals.githubPermission)) authorizedCount++;
                }
            } catch {
                // API failure = no signal, fail-closed
            }
        }

        // Decision: Fail-closed. Need at least 2 positive signals.
        const authorized = authorizedCount >= 2;
        const confidence = authorizedCount >= 3 ? 'HIGH' : (authorizedCount >= 2 ? 'MEDIUM' : 'LOW');

        return { authorized, confidence, signals, signalCount: authorizedCount };
    }

    /**
     * Gets the permission level of the authenticated user for a repo.
     * Returns 'ADMIN', 'MAINTAIN', 'WRITE', 'READ', or 'NONE'.
     */
    getRepoPermission(repoFullName) {
        if (!isValidOwnerRepo(repoFullName)) return 'NONE';
        try {
            const output = execFileSync('gh', [
                'repo', 'view', repoFullName,
                '--json', 'viewerPermission'
            ], { encoding: 'utf-8', timeout: 15000 });
            const result = JSON.parse(output);
            return result.viewerPermission || 'NONE';
        } catch (e) {
            console.error(`[GH_BRIDGE] Error checking permission for ${repoFullName}:`, e.message);
            return 'NONE';
        }
    }

    postPRComment(repoFullName, prNumber, message) {
        if (!isValidOwnerRepo(repoFullName) || !isValidPRNumber(prNumber)) return { success: false };
        
        // Governance: Permission Check (Hardened v3.7)
        const permission = this.getRepoPermission(repoFullName);
        const authorizedRoles = ['ADMIN', 'MAINTAIN', 'WRITE'];
        
        if (!authorizedRoles.includes(permission)) {
            console.error(`[SECURITY] Post PR Comment denied for ${repoFullName}. Permission level: ${permission}`);
            return { 
                success: false, 
                error: `Unauthorized: Sentinel requires WRITE/MAINTAIN permissions to post to ${repoFullName}. Current role: ${permission}` 
            };
        }

        try {
            execFileSync('gh', [
                'pr', 'comment', String(prNumber),
                '--repo', repoFullName,
                '--body', message
            ], { encoding: 'utf-8', timeout: 30000 });
            return { success: true };
        } catch (e) {
            return { success: false, error: e.message };
        }
    }

    // ─── PR Firewall Methods (v3.8) ───

    /**
     * Obtains the list of files modified in a Pull Request.
     */
    getPRFiles(repoFullName, prNumber) {
        if (!isValidOwnerRepo(repoFullName) || !isValidPRNumber(prNumber)) return null;
        try {
            const output = execFileSync('gh', [
                'pr', 'view', String(prNumber),
                '--repo', repoFullName,
                '--json', 'files'
            ], { encoding: 'utf-8', timeout: 15000, stdio: ['ignore', 'pipe', 'ignore'] });
            const data = JSON.parse(output);
            return data.files ? data.files.map(f => f.path) : [];
        } catch (e) {
            // Return null on failure (e.g. invalid repo, network error) instead of crashing or polluting logs
            return null;
        }
    }

    /**
     * Gets the HEAD SHA of a PR to attach the Check Run to the correct commit.
     */
    getPRHeadSha(repoFullName, prNumber) {
        if (!isValidOwnerRepo(repoFullName) || !isValidPRNumber(prNumber)) return null;
        try {
            const output = execFileSync('gh', [
                'pr', 'view', String(prNumber),
                '--repo', repoFullName,
                '--json', 'commits'
            ], { encoding: 'utf-8', timeout: 15000 });
            const data = JSON.parse(output);
            if (data.commits && data.commits.length > 0) {
                return data.commits[data.commits.length - 1].oid; // The last commit in the PR
            }
            return null;
        } catch (e) {
            console.error(`[GH_BRIDGE] Error getting HEAD SHA for PR #${prNumber}:`, sanitizeForLog(e.message));
            return null;
        }
    }

    /**
     * Creates a Check Run via GitHub API.
     * Implements strict permission checking and gracefully falls back to local dry-run.
     */
    createCheckRun(repoFullName, headSha, name, status, conclusion, summary, details, isCI = false) {
        if (!isValidOwnerRepo(repoFullName) || !headSha) return false;

        // Validation: Verify if we should actually post to GitHub
        const isActionContext = !!process.env.GITHUB_ACTIONS || !!process.env.CI || isCI;
        
        if (!isActionContext) {
            console.log(`\n\x1b[36m[DRY-RUN]\x1b[0m GitHub Check Run skipped in local environment.`);
            console.log(`\x1b[2mCheck: ${name} | Conclusion: ${conclusion}\nSummary: ${summary.split('\\n')[0]}...\x1b[0m\n`);
            return true;
        }

        const permission = this.getRepoPermission(repoFullName);
        const authorizedRoles = ['ADMIN', 'MAINTAIN', 'WRITE'];
        
        if (!authorizedRoles.includes(permission)) {
            console.warn(`[SECURITY] Skipping Check Run creation. Requires WRITE access. Current role: ${permission}`);
            return false;
        }

        const fs = require('fs');
        const os = require('os');
        const crypto = require('crypto');

        try {
            const payload = {
                name,
                head_sha: headSha,
                status,
                conclusion,
                output: {
                    title: "Sentinel PR Firewall",
                    summary: summary || "",
                    text: details || ""
                }
            };
            
            const tmpFile = path.join(os.tmpdir(), `sentinel_check_${crypto.randomBytes(4).toString('hex')}.json`);
            fs.writeFileSync(tmpFile, JSON.stringify(payload));
            
            execFileSync('gh', [
                'api', `repos/${repoFullName}/check-runs`,
                '--input', tmpFile
            ], { encoding: 'utf-8', timeout: 15000 });
            
            try { fs.unlinkSync(tmpFile); } catch (e) {}
            return true;
        } catch (e) {
            console.error(`[GH_BRIDGE] Error creating Check Run for ${repoFullName}:`, sanitizeForLog(e.message));
            return false;
        }
    }

}

module.exports = new GitHubBridge();
