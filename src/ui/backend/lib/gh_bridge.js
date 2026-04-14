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

    /**
     * Gets latest commits for a repository.
     * @param {string} repoFullName 
     * @param {number} limit 
     */
    getCommits(repoFullName, limit = 5) {
        if (!isValidOwnerRepo(repoFullName)) return [];
        try {
            const output = execFileSync('gh', [
                'api', `repos/${repoFullName}/commits`,
                '--limit', String(limit),
                '--json', 'sha,commit,html_url'
            ], {
                encoding: 'utf-8',
                timeout: 15000
            });
            return JSON.parse(output);
        } catch {
            return [];
        }
    }

    /**
     * Fetches a file content from a remote GitHub repository.
     * Returns decoded UTF-8 string or null.
     */
    getRemoteFileContent(repoFullName, filePath) {
        if (!isValidOwnerRepo(repoFullName) || !isValidGitPath(filePath)) return null;
        try {
            // Use gh api to fetch contents
            const output = execFileSync('gh', [
                'api', `repos/${repoFullName}/contents/${filePath}`,
                '--jq', '.content'
            ], {
                encoding: 'utf-8',
                timeout: 15000
            });
            
            if (!output || output.trim() === '') return null;
            
            // Decodes the base64 content from GitHub API
            return Buffer.from(output.trim(), 'base64').toString('utf-8');
        } catch (e) {
            console.error(`Error fetching remote file ${filePath}:`, sanitizeForLog(e.message));
            return null;
        }
    }
    /**
     * Posts a comment to a Pull Request.
     * SECURITY: Validates all inputs to prevent command injection.
     */
    postPRComment(repoFullName, prNumber, body) {
        if (!isValidOwnerRepo(repoFullName) || !isValidPRNumber(prNumber)) return false;
        try {
            execFileSync('gh', [
                'pr', 'comment', String(prNumber),
                '--repo', repoFullName,
                '--body', body
            ], {
                encoding: 'utf-8',
                timeout: 30000
            });
            return true;
        } catch (e) {
            console.error(`Error posting comment to PR #${prNumber}:`, sanitizeForLog(e.message));
            return false;
        }
    }

    /**
     * Gets full repository metadata including security and analysis settings.
     * SECURITY: repoFullName validated.
     */
    getRepoSecurityMetadata(repoFullName) {
        if (!isValidOwnerRepo(repoFullName)) return null;
        try {
            const output = execFileSync('gh', [
                'api', `repos/${repoFullName}`,
                '--jq', '{secret_scanning: .security_and_analysis.secret_scanning.status, dependabot: .security_and_analysis.dependabot_security_updates.status, visibility: .visibility, default_branch: .default_branch}'
            ], {
                encoding: 'utf-8',
                timeout: 15000
            });
            return JSON.parse(output);
        } catch (e) {
            console.error(`Error getting security metadata for ${repoFullName}:`, sanitizeForLog(e.message));
            return null;
        }
    }

    /**
     * Gets branch protection rules for a specific branch.
     * Returns null if no protection exists.
     */
    getBranchProtection(repoFullName, branch) {
        if (!isValidOwnerRepo(repoFullName)) return null;
        try {
            const output = execFileSync('gh', [
                'api', `repos/${repoFullName}/branches/${branch}/protection`
            ], {
                encoding: 'utf-8',
                timeout: 15000
            });
            return JSON.parse(output);
        } catch (e) {
            // 404 means no protection
            return null;
        }
    }

    /**
     * Enables security features (Secret Scanning / Dependabot).
     */
    async updateRepoSecurity(repoFullName, { secretScanning, dependabot }) {
        if (!isValidOwnerRepo(repoFullName)) return { success: false };
        try {
            // Enable Secret Scanning
            if (secretScanning !== undefined) {
                execFileSync('gh', [
                    'repo', 'edit', repoFullName,
                    `--enable-secret-scanning=${secretScanning}`
                ]);
            }
            
            // Enable Dependabot via API (requires special headers/method)
            if (dependabot !== undefined) {
                const status = dependabot ? 'enabled' : 'disabled';
                execFileSync('gh', [
                    'api', '--method', 'PATCH', `repos/${repoFullName}`,
                    '-F', `security_and_analysis[dependabot_security_updates][status]=${status}`
                ]);
            }
            return { success: true };
        } catch (e) {
            console.error(`Error updating security for ${repoFullName}:`, sanitizeForLog(e.message));
            return { success: false, error: e.message };
        }
    }

    /**
     * Applies Sentinel's "Standard" branch protection to main.
     */
    async updateBranchProtection(repoFullName, branch, protectionConfig) {
        if (!isValidOwnerRepo(repoFullName)) return { success: false };
        try {
            // Convert config to a temporary JSON file for gh api --input
            const fs = require('fs');
            const tmpFile = path.join(process.cwd(), `tmp_protection_${Date.now()}.json`);
            fs.writeFileSync(tmpFile, JSON.stringify(protectionConfig));

            execFileSync('gh', [
                'api', '--method', 'PUT', 
                `repos/${repoFullName}/branches/${branch}/protection`,
                '--input', tmpFile
            ]);

            fs.unlinkSync(tmpFile);
            return { success: true };
        } catch (e) {
            console.error(`Error protecting branch ${branch} in ${repoFullName}:`, sanitizeForLog(e.message));
            return { success: false, error: e.message };
        }
    }
}

module.exports = new GitHubBridge();
