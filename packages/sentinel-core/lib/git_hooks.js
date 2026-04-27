/**
 * Sentinel: Global Git Hooks Manager (HARDENED)
 * Installs a global git hook delegator to protect all local repos.
 * 
 * SECURITY: All git commands use execFileSync with array args.
 * No shell interpolation. Directory paths are not user-controlled.
 * 
 * Audit: VULN-001 remediated — 3 instances of execSync replaced.
 */

'use strict';

const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

class GitHooksManager {
    constructor() {
        this.sentinelDir = path.join(os.homedir(), '.sentinel');
        this.hooksDir = path.join(this.sentinelDir, 'hooks');
    }

    /**
     * Checks if the global hook is currently installed.
     * SECURITY: Uses execFileSync with array args — no shell.
     */
    isInstalled() {
        try {
            const currentPath = execFileSync('git', ['config', '--global', 'core.hooksPath'], {
                encoding: 'utf-8',
                timeout: 10000
            }).trim();
            return currentPath === this.hooksDir;
        } catch {
            return false;
        }
    }

    /**
     * Installs the global git hooks.
     * SECURITY: hooksDir is derived from os.homedir() — not user input.
     * Uses execFileSync with array args — no shell.
     */
    install() {
        try {
            if (!fs.existsSync(this.hooksDir)) {
                fs.mkdirSync(this.hooksDir, { recursive: true });
            }

            const prePushContent = `#!/bin/sh
# SENTINEL GLOBAL PRE-PUSH HOOK
# Pass diff to sentinel cli (assume sentinel is globally installed or linked)
# We force stdin to connect to /dev/tty so interactive prompts work
exec < /dev/tty
sentinel hook pre-push || exit 1

# If a local hook exists, delegate to it
if [ -f "\\$GIT_DIR/hooks/pre-push" ]; then
    "\\$GIT_DIR/hooks/pre-push" "\\$@"
fi
`;

            const postMergeContent = `#!/bin/sh
# SENTINEL GLOBAL POST-MERGE HOOK
exec < /dev/tty
sentinel hook post-merge || exit 1

# Delegate
if [ -f "\\$GIT_DIR/hooks/post-merge" ]; then
    "\\$GIT_DIR/hooks/post-merge" "\\$@"
fi
`;

            fs.writeFileSync(path.join(this.hooksDir, 'pre-push'), prePushContent, { mode: 0o755 });
            fs.writeFileSync(path.join(this.hooksDir, 'post-merge'), postMergeContent, { mode: 0o755 });

            // Apply global config — uses array args, no shell
            execFileSync('git', ['config', '--global', 'core.hooksPath', this.hooksDir], {
                encoding: 'utf-8',
                timeout: 10000
            });

            return { success: true };
        } catch (e) {
            return { success: false, error: e.message };
        }
    }

    /**
     * Uninstalls the global hooks.
     * SECURITY: Uses execFileSync with array args — no shell.
     */
    uninstall() {
        try {
            execFileSync('git', ['config', '--global', '--unset', 'core.hooksPath'], {
                encoding: 'utf-8',
                timeout: 10000
            });
            return { success: true };
        } catch (e) {
            // Unset fails if not set, that's fine
            return { success: true, message: 'Already uninstalled' };
        }
    }
}

module.exports = new GitHooksManager();
