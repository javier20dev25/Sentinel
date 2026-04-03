/**
 * Sentinel: Git Local Bridge
 * Handles staged changes, unstaging, and .gitignore management.
 */

'use strict';

const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const { isValidLocalPath, isValidGitPath, sanitizeForLog } = require('./sanitizer');

class GitBridge {
    /**
     * Get list of staged files in a local repository.
     * @param {string} repoPath 
     */
    getStagedFiles(repoPath) {
        if (!isValidLocalPath(repoPath)) return [];
        try {
            const output = execFileSync('git', ['diff', '--cached', '--name-only'], {
                cwd: repoPath,
                encoding: 'utf-8',
                timeout: 10000
            });
            return output.split('\n').filter(Boolean);
        } catch (e) {
            console.error(`Error getting staged files: ${sanitizeForLog(e.message)}`);
            return [];
        }
    }

    /**
     * Get the exact content of a staged file (the version in the index).
     * @param {string} repoPath 
     * @param {string} filePath 
     */
    getStagedContent(repoPath, filePath) {
        if (!isValidLocalPath(repoPath) || !isValidGitPath(filePath)) return null;
        try {
            // Using :filePath gets the content from the stage (index)
            return execFileSync('git', ['show', `:${filePath}`], {
                cwd: repoPath,
                encoding: 'utf-8',
                timeout: 10000
            });
        } catch (e) {
            console.error(`Error reading staged content for ${filePath}: ${sanitizeForLog(e.message)}`);
            return null;
        }
    }

    /**
     * Remove a file from staging (git reset).
     * @param {string} repoPath 
     * @param {string} filePath 
     */
    unstageFile(repoPath, filePath) {
        if (!isValidLocalPath(repoPath) || !isValidGitPath(filePath)) return { success: false };
        try {
            execFileSync('git', ['reset', 'HEAD', filePath], {
                cwd: repoPath,
                encoding: 'utf-8',
                timeout: 10000
            });
            return { success: true };
        } catch (e) {
            return { success: false, error: e.message };
        }
    }

    /**
     * Add a pattern to .gitignore.
     * @param {string} repoPath 
     * @param {string} pattern 
     */
    addToIgnore(repoPath, pattern) {
        if (!isValidLocalPath(repoPath)) return { success: false };
        try {
            const ignorePath = path.join(repoPath, '.gitignore');
            fs.appendFileSync(ignorePath, `\n${pattern}\n`);
            return { success: true };
        } catch (e) {
            return { success: false, error: e.message };
        }
    }

    /**
     * Safely trigger git push.
     * Returns { success, hash }
     * @param {string} repoPath 
     */
    push(repoPath) {
        if (!isValidLocalPath(repoPath)) return { success: false };
        try {
            execFileSync('git', ['push'], {
                cwd: repoPath,
                encoding: 'utf-8',
                timeout: 30000
            });
            
            // Get the commit hash that was just pushed
            const hash = execFileSync('git', ['rev-parse', 'HEAD'], {
                cwd: repoPath,
                encoding: 'utf-8',
                timeout: 5000
            }).trim();

            return { success: true, hash };
        } catch (e) {
            return { success: false, error: e.message };
        }
    }
}

module.exports = new GitBridge();
