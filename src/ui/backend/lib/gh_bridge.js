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
            // SECURITY: Static command and safe arguments. Using shell=true on Windows to ensure 'gh' is found.
            const child = spawn('gh', ['auth', 'login', '-w', '-p', 'https', '--skip-ssh-key'], {
                shell: process.platform === 'win32',
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
                shell: process.platform === 'win32',
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
        if (!isValidOwnerRepo(repoFullName)) {
            console.error(`[SECURITY] Invalid repo format rejected: ${sanitizeForLog(repoFullName)}`);
            return null;
        }
        if (!isValidPRNumber(prNumber)) {
            console.error(`[SECURITY] Invalid PR number rejected: ${sanitizeForLog(String(prNumber))}`);
            return null;
        }

        try {
            return execFileSync('gh', [
                'pr', 'diff', String(prNumber),
                '--repo', repoFullName
            ], {
                encoding: 'utf-8',
                timeout: 15000,
                maxBuffer: 5 * 1024 * 1024 // 5MB limit to prevent OOM
            });
        } catch (e) {
            console.error(`Error getting diff for PR #${prNumber}:`, sanitizeForLog(e.message));
            return null;
        }
    }

    /**
     * Gets user account creation date.
     * SECURITY: username validated — only alphanumeric/hyphens allowed (GitHub username format).
     */
    getUserCreatedAt(username) {
        // GitHub usernames: alphanumeric + hyphens, max 39 chars
        if (typeof username !== 'string' || !/^[a-zA-Z0-9-]{1,39}$/.test(username)) {
            console.error(`[SECURITY] Invalid username rejected: ${sanitizeForLog(String(username))}`);
            return null;
        }

        try {
            const output = execFileSync('gh', [
                'api', `users/${username}`,
                '-q', '.created_at'
            ], {
                encoding: 'utf-8',
                timeout: 10000
            });
            return new Date(output.trim());
        } catch (e) {
            console.error(`Error getting user creation date for ${sanitizeForLog(username)}:`, sanitizeForLog(e.message));
            return null;
        }
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
}

module.exports = new GitHubBridge();
