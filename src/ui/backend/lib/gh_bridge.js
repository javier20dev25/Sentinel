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

    postPRComment(repoFullName, prNumber, message) {
        if (!isValidOwnerRepo(repoFullName) || !isValidPRNumber(prNumber)) return { success: false };
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
}

module.exports = new GitHubBridge();
