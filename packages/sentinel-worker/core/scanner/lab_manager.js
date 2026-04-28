/**
 * Sentinel: Native Lab Manager (v1.0)
 * 
 * Provides robust, programmatic provisioning of testing corpora.
 * Replaces fragile bash scripts with Node.js managed execution,
 * strict error handling, and file system integrity checks.
 */

'use strict';

const fs = require('fs');
const fsPromises = require('fs').promises;
const path = require('path');
const { execSync } = require('child_process');

class LabManager {
    constructor(baseDir) {
        this.baseDir = path.resolve(baseDir);
        if (!fs.existsSync(this.baseDir)) {
            fs.mkdirSync(this.baseDir, { recursive: true });
        }
    }

    /**
     * Safely clones a Git repository with depth 1.
     */
    async provisionGitRepo(url, targetName) {
        const targetPath = path.join(this.baseDir, targetName);
        console.log(`\x1b[36m[LAB MANAGER] Provisioning Git Repo: ${targetName}\x1b[0m`);

        if (fs.existsSync(targetPath)) {
            console.log(`  -> Directory already exists. Skipping clone.`);
            return { success: true, path: targetPath, cached: true };
        }

        try {
            const cmd = `git clone --depth 1 ${url} "${targetPath}"`;
            execSync(cmd, { stdio: 'ignore' });
            console.log(`  -> \x1b[32mSuccessfully cloned.\x1b[0m`);
            return { success: true, path: targetPath, cached: false };
        } catch (e) {
            console.error(`  -> \x1b[31mFailed to clone ${url}\x1b[0m`);
            return { success: false, error: e.message };
        }
    }

    /**
     * Downloads and extracts an NPM package securely without executing scripts.
     */
    async provisionNpmPackage(packageName, targetName) {
        const targetPath = path.join(this.baseDir, targetName);
        console.log(`\x1b[36m[LAB MANAGER] Provisioning NPM Package: ${packageName}\x1b[0m`);

        if (fs.existsSync(targetPath)) {
            console.log(`  -> Directory already exists. Skipping download.`);
            return { success: true, path: targetPath, cached: true };
        }

        try {
            fs.mkdirSync(targetPath, { recursive: true });
            
            // 1. Pack the tarball
            console.log(`  -> Packing ${packageName}...`);
            const packOutput = execSync(`npm pack ${packageName} --ignore-scripts`, { cwd: targetPath, encoding: 'utf8' }).trim();
            const tarballName = packOutput.split('\n').pop().trim();
            
            // 2. Extract the tarball natively using node or standard tar (with absolute paths)
            console.log(`  -> Extracting ${tarballName}...`);
            const tarballPath = path.join(targetPath, tarballName);
            
            // Note: npm pack creates a 'package' folder inside the tarball. 
            // --strip-components=1 removes it so files land directly in targetPath.
            execSync(`tar -xzf "${tarballName}" --strip-components=1`, { cwd: targetPath, stdio: 'ignore' });
            
            // 3. Cleanup tarball
            fs.unlinkSync(tarballPath);

            console.log(`  -> \x1b[32mSuccessfully provisioned.\x1b[0m`);
            return { success: true, path: targetPath, cached: false };
        } catch (e) {
            console.error(`  -> \x1b[31mFailed to provision ${packageName}\x1b[0m`);
            return { success: false, error: e.message };
        }
    }
}

module.exports = LabManager;
