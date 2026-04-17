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
            // SECURITY: Static command and safe arguments. Using .exe on Windows for GH CLI.
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
                
                // If it asks to press Enter, do it automatically
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
            // Validate limit to prevent injection
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
                '--limit', '20',
                '--json', 'number,title,author,updatedAt'
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
        if (!isValidOwnerRepo(repoFullName)) return null;
        if (!isValidPRNumber(prNumber)) return null;

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
     * Helper to detect if a PR modifies package.json or sensitive security files.
     */
    async analyzePRContent(repoFullName, prNumber, author) {
        const diff = this.getPRDiff(repoFullName, prNumber);
        if (!diff) return { hasSensitiveChanges: false };

        const changedFiles = [];
        const diffLines = diff.split('\n');
        
        for (const line of diffLines) {
            if (line.startsWith('diff --git')) {
                const match = line.match(/b\/(.+)$/);
                if (match) changedFiles.push(match[1]);
            }
        }

        const isPackageJsonModified = changedFiles.some(f => f.endsWith('package.json'));
        const reputation = await this.getAuthorReputation(author);

        return {
            hasSensitiveChanges: isPackageJsonModified,
            changedFiles,
            authorReputation: reputation,
            diff
        };
    }

    /**
     * Gets author metadata to assess risk.
     * Returns { ageDays: number, isNew: boolean, username: string }
     */
    async getAuthorReputation(username) {
        if (!username) return null;
        const createdAt = this.getUserCreatedAt(username);
        if (!createdAt) return { ageDays: 365, isNew: false, username };

        const ageMs = Date.now() - createdAt.getTime();
        const ageDays = ageMs / (1000 * 60 * 60 * 24);
        
        return {
            username,
            ageDays: Math.floor(ageDays),
            isNew: ageDays < 30, // New accounts (less than 30 days) are higher risk
        };
    }

    /**
     * Gets repository info from a local path.
     * SECURITY: Validates path before use as cwd. Rejects traversal attempts.
     */
    getRepoInfoLocal(localPath) {
        // SECURITY: Validate the local path to prevent path traversal
        if (!isValidLocalPath(localPath)) {
            console.error(`[SECURITY] Rejected invalid local path: ${String(localPath).substring(0, 50)}`);
            return null;
        }
        try {
            return JSON.parse(execFileSync('gh', ['repo', 'view', '--json', 'fullName'], {
                cwd: localPath,
                encoding: 'utf-8',
                timeout: 10000
            }));
        } catch {
            return null;
        }
    }
    // ─── Sandbox Methods ───

    /**
     * Check if the Sentinel sandbox workflow is installed in a local repo.
     * Returns { installed: boolean, version: string|null, path: string }
     */
    checkSandboxInstalled(localPath) {
        const fs = require('fs');
        const path = require('path');
        if (!isValidLocalPath(localPath)) return { installed: false, version: null };

        const workflowPath = path.join(localPath, '.github', 'workflows', 'sentinel-sandbox.yml');
        if (!fs.existsSync(workflowPath)) return { installed: false, version: null, path: workflowPath };

        try {
            const content = fs.readFileSync(workflowPath, 'utf-8');
            const match = content.match(/Template managed by Sentinel Local[^\n]+\n# .*?--- v([\d.]+)/s) ||
                          content.match(/sentinel-sandbox\.yml — v([\d.]+)/) ||
                          content.match(/Sentinel Sandbox Analysis — v([\d.]+)/);
            const version = match ? match[1] : 'unknown';
            return { installed: true, version, path: workflowPath };
        } catch {
            return { installed: true, version: 'unknown', path: workflowPath };
        }
    }

    /**
     * Get the local git diff (uncommitted changes) as a string.
     * SECURITY: Uses execFileSync without shell. No code is executed from the diff.
     */
    getLocalDiff(localPath) {
        if (!isValidLocalPath(localPath)) {
            console.error(`[SECURITY] getLocalDiff: invalid path rejected`);
            return null;
        }
        try {
            // Get staged + unstaged changes vs HEAD
            const staged = execFileSync('git', ['diff', '--cached'], { cwd: localPath, encoding: 'utf-8', timeout: 10000, maxBuffer: 5 * 1024 * 1024 });
            const unstaged = execFileSync('git', ['diff'], { cwd: localPath, encoding: 'utf-8', timeout: 10000, maxBuffer: 5 * 1024 * 1024 });
            return (staged + unstaged).trim() || null;
        } catch (e) {
            console.error('[getLocalDiff]', sanitizeForLog(e.message));
            return null;
        }
    }

    /**
     * Fetch the latest Sentinel Sandbox workflow run from GitHub.
     * Returns { status, conclusion, html_url, created_at } or null.
     */
    getLatestSandboxRun(repoFullName) {
        if (!isValidOwnerRepo(repoFullName)) return null;
        try {
            // List workflow runs for sentinel-sandbox.yml
            const runsRaw = execFileSync('gh', [
                'api', `repos/${repoFullName}/actions/workflows/sentinel-sandbox.yml/runs`,
                '--jq', '.workflow_runs[0] | {status, conclusion, html_url, created_at}'
            ], { encoding: 'utf-8', timeout: 15000 });
            return JSON.parse(runsRaw.trim());
        } catch (e) {
            // Workflow might not exist yet
            console.warn('[getLatestSandboxRun]', sanitizeForLog(e.message));
            return null;
        }
    }

    /**
     * Push the Sentinel sandbox workflow config to the repo via git.
     * SECURITY: Uses execFileSync array args only. Requires contents:write permission.
     * Only called after explicit user consent (sandbox_consent stored in DB).
     */
    pushSandboxConfig(localPath) {
        if (!isValidLocalPath(localPath)) {
            return { success: false, error: 'Invalid local path.' };
        }
        const fs = require('fs');
        const path = require('path');
        const templatePath = path.join(__dirname, '..', 'templates', 'sentinel-sandbox.yml');
        const destDir = path.join(localPath, '.github', 'workflows');
        const destPath = path.join(destDir, 'sentinel-sandbox.yml');

        try {
            fs.mkdirSync(destDir, { recursive: true });
            fs.copyFileSync(templatePath, destPath);

            execFileSync('git', ['add', destPath], { cwd: localPath, timeout: 10000 });
            execFileSync('git', ['commit', '-m', 'chore: add Sentinel sandbox workflow v1.0'], { cwd: localPath, timeout: 10000 });
            execFileSync('git', ['push'], { cwd: localPath, timeout: 30000 });

            return { success: true, path: destPath };
        } catch (e) {
            return { success: false, error: sanitizeForLog(e.message) };
        }
    }

    /**
     * Return the template content as a string (for manual copy mode).
     */
    getSandboxTemplateContent() {
        const fs = require('fs');
        const path = require('path');
        const templatePath = path.join(__dirname, '..', 'templates', 'sentinel-sandbox.yml');
        return fs.readFileSync(templatePath, 'utf-8');
    }
}

module.exports = new GitHubBridge();
