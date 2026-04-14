/**
 * Sentinel: Project Shield Bridge
 * Manages project hardening and safe installations.
 */

const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const db = require('./db');
const astInspector = require('../scanner/ast_inspector');

class ShieldBridge {
    /**
     * Hardens the project by setting secure configs in .npmrc and package.json
     */
    async hardenProject(repoId) {
        const repo = db.getRepositoryById(repoId);
        if (!repo) throw new Error('Repository not found in database.');

        const repoPath = repo.local_path;
        const npmrcPath = path.join(repoPath, '.npmrc');
        const pkgPath = path.join(repoPath, 'package.json');

        // 1. Endurecer .npmrc
        const securityConfigs = [
            'ignore-scripts=true',
            'save-exact=true',
            'engine-strict=true',
            'audit=true'
        ];

        let currentNpmrc = '';
        if (fs.existsSync(npmrcPath)) {
            currentNpmrc = fs.readFileSync(npmrcPath, 'utf8');
        }

        let updatedNpmrc = currentNpmrc;
        securityConfigs.forEach(cfg => {
            const [key, value] = cfg.split('=');
            if (!updatedNpmrc.includes(key)) {
                updatedNpmrc += `\n${cfg}`;
            } else {
                // Update existing key
                updatedNpmrc = updatedNpmrc.replace(new RegExp(`${key}=.*`, 'g'), cfg);
            }
        });

        fs.writeFileSync(npmrcPath, updatedNpmrc.trim() + '\n');

        // 2. Endurecer package.json (engines)
        if (fs.existsSync(pkgPath)) {
            const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
            if (!pkg.engines) pkg.engines = {};
            if (!pkg.engines.node) pkg.engines.node = ">=18.0.0";
            if (!pkg.engines.npm) pkg.engines.npm = ">=9.0.0";
            
            fs.writeFileSync(pkgPath, JSON.stringify(pkg, null, 2));
        }

        return { success: true, message: 'Security policies applied successfully.' };
    }

    /**
     * Performs a safe installation intercepted by Sentinel
     */
    async safeInstall(repoId, onProgress) {
        const repo = db.getRepositoryById(repoId);
        if (!repo) throw new Error('Repository not found.');

        const repoPath = repo.local_path;
        
        // Determine package manager
        let cmd = 'npm';
        if (fs.existsSync(path.join(repoPath, 'pnpm-lock.yaml'))) cmd = 'pnpm';
        else if (fs.existsSync(path.join(repoPath, 'yarn.lock'))) cmd = 'yarn';

        onProgress(`[Step 1/3] Launching ${cmd} install with --ignore-scripts...`);

        return new Promise((resolve, reject) => {
            const platformCmd = process.platform === 'win32' ? `${cmd}.cmd` : cmd;
            const child = spawn(platformCmd, ['install', '--ignore-scripts'], {
                cwd: repoPath,
                shell: false
            });

            child.stdout.on('data', (data) => onProgress(data.toString()));
            child.stderr.on('data', (data) => onProgress(data.toString()));

            child.on('close', async (code) => {
                if (code !== 0) {
                    onProgress(`\n[ERROR] ${cmd} install failed with code ${code}`);
                    return reject(new Error('Installation failed.'));
                }

                onProgress(`\n[Step 2/3] ${cmd} install complete. Starting AST Deep Scan on node_modules...`);
                
                try {
                    const scanResults = await this.scanNodeModules(repo.id, repoPath, onProgress);
                    onProgress(`\n[Step 3/3] Analysis complete. Detected ${scanResults.length} potential threats.`);
                    resolve(scanResults);
                } catch (err) {
                    reject(err);
                }
            });
        });
    }

    /**
     * Recursively scans node_modules for malicious AST patterns
     */
    async scanNodeModules(repoId, repoPath, onProgress) {
        const nodeModulesPath = path.join(repoPath, 'node_modules');
        if (!fs.existsSync(nodeModulesPath)) return [];

        const allThreats = [];
        const filesToScan = this._getAllJsFiles(nodeModulesPath);
        
        onProgress(`\nScanning ${filesToScan.length} files for malicious intent...`);

        for (const file of filesToScan) {
            try {
                const code = fs.readFileSync(file, 'utf8');
                const relativePath = path.relative(nodeModulesPath, file);
                const threats = astInspector.analyze(code, relativePath);
                
                if (threats.length > 0) {
                    threats.forEach(t => {
                        t.file = relativePath;
                        allThreats.push(t);
                        onProgress(`\n⚠️  [CRITICAL] Possible exfiltration in ${relativePath}: ${t.message}`);
                    });

                    // Log to DB
                    db.addScanLog(repoId, 'SUPPLY_CHAIN_AST_ALERT', 
                        threats[0].severity === 'CRITICAL' ? 10 : 7, 
                        `Malicious code pattern in node_modules: ${threats[0].message}`,
                        { file: relativePath, detail: threats[0] },
                        'STATIC', 'SUPPLY_CHAIN'
                    );

                }
            } catch (err) {
                // Silent skip small/problematic files
            }
        }

        return allThreats;
    }

    _getAllJsFiles(dirPath, arrayOfFiles) {
        const files = fs.readdirSync(dirPath);
        arrayOfFiles = arrayOfFiles || [];

        files.forEach((file) => {
            if (fs.statSync(dirPath + "/" + file).isDirectory()) {
                // Small optimization: skip deep tests or obvious paths
                if (file === 'test' || file === 'doc' || file === 'example') return;
                arrayOfFiles = this._getAllJsFiles(dirPath + "/" + file, arrayOfFiles);
            } else {
                if (file.endsWith(".js") || file.endsWith(".mjs")) {
                    arrayOfFiles.push(path.join(dirPath, "/", file));
                }
            }
        });

        return arrayOfFiles;
    }
}

module.exports = new ShieldBridge();
