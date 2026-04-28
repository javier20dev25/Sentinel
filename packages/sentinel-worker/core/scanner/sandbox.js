/**
 * Sentinel: Sandbox Execution Engine (v1.0)
 * 
 * Handles controlled execution of untrusted code (npm install, scripts)
 * inside restricted Docker containers.
 */

'use strict';

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

class SandboxScanner {
    /**
     * Executes a command inside a restricted Docker sandbox.
     * @param {string} workDir - Local path to mount in the sandbox
     * @param {string} command - Command to run (e.g. 'npm install')
     */
    static async run(workDir, command) {
        const absolutePath = path.resolve(workDir);

        // 1. Check Docker Availability
        try {
            execSync('docker --version', { stdio: 'ignore' });
        } catch (e) {
            console.warn(`[SANDBOX WARNING] Docker not found. Isolation is disabled.`);
            return { 
                success: false, 
                error: 'DOCKER_NOT_FOUND', 
                details: 'Docker is required for restricted sandbox execution. Please install Docker or run in a compliant environment.'
            };
        }
        
        // Security Rule: Restricted Docker flags
        const dockerCmd = [
            'docker run --rm',
            '--network none',
            '--memory 512m',
            '--cpus 0.5',
            `-v "${absolutePath}:/sandbox"`,
            '-w /sandbox',
            'node:18-slim',
            `sh -c "${command}"`
        ].join(' ');

        try {
            console.log(`[SANDBOX] Starting controlled execution: ${command}`);
            const output = execSync(dockerCmd, { encoding: 'utf8' });
            return { success: true, output };
        } catch (e) {
            return { success: false, error: 'EXECUTION_FAILED', output: e.stdout };
        }
    }

    /**
     * Specialized Supply Chain Sandbox: Installs deps and scans node_modules
     */
    static async scanSupplyChain(repoPath) {
        // 1. Install in sandbox WITHOUT ignoring scripts.
        // This allows malicious 'preinstall' or 'postinstall' hooks to execute 
        // inside the isolated container, revealing their behavior (e.g. curling a RAT).
        const installResult = await this.run(repoPath, 'npm install --package-lock-only && npm install');
        
        if (!installResult.success) {
            return { error: 'Sandbox installation failed', details: installResult.error };
        }

        // 2. Scan the resulting node_modules statically
        // (This would call the main Sentinel scanner on the node_modules dir)
        return { success: true, message: 'Dependencies installed and ready for static audit.' };
    }
}

module.exports = SandboxScanner;
