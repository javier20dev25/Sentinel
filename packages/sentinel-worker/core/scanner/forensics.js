/**
 * Sentinel: Forensic Audit Engine (v1.0)
 * 
 * Traces security findings back to specific Git commits and authors.
 * Provides accountability and timeline for risk introduction.
 */

'use strict';

const { execSync } = require('child_process');
const path = require('path');

class ForensicAudit {
    /**
     * Finds the commit and author responsible for a specific line in a file.
     * @param {string} repoPath - Path to the local git repository
     * @param {string} filePath - Path to the file relative to repo root
     * @param {number} lineNumber - 1-indexed line number
     */
    static blame(repoPath, filePath, lineNumber) {
        try {
            // git blame -L <line>,<line> --porcelain <file>
            const cmd = `git blame -L ${lineNumber},${lineNumber} --porcelain "${filePath}"`;
            const output = execSync(cmd, { cwd: repoPath, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
            
            const lines = output.split('\n');
            const commitHash = lines[0].split(' ')[0];
            const author = lines.find(l => l.startsWith('author ')).replace('author ', '');
            const authorTime = lines.find(l => l.startsWith('author-time ')).replace('author-time ', '');
            const summary = lines.find(l => l.startsWith('summary ')).replace('summary ', '');

            return {
                hash: commitHash,
                author,
                timestamp: new Date(parseInt(authorTime) * 1000).toISOString(),
                summary,
                line: lineNumber
            };
        } catch (e) {
            return { error: 'Blame failed', details: e.message };
        }
    }

    /**
     * Gets the full history of a file to detect when a specific pattern was introduced.
     * @param {string} repoPath 
     * @param {string} filePath 
     * @param {string} pattern - Regex or string to search in history
     */
    static tracePattern(repoPath, filePath, pattern) {
        try {
            // git log -p -G<pattern> -- <file>
            const cmd = `git log -n 5 -p -G"${pattern}" --format="%H|%an|%ai|%s" -- "${filePath}"`;
            const output = execSync(cmd, { cwd: repoPath, encoding: 'utf8' });
            
            if (!output) return [];

            const commits = output.split('\n\n').filter(c => c.trim()).map(chunk => {
                const lines = chunk.split('\n');
                const [hash, author, date, summary] = lines[0].split('|');
                return { hash, author, date, summary };
            });

            return commits;
        } catch (e) {
            return [];
        }
    }
}

module.exports = ForensicAudit;
