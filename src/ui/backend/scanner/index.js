/**
 * Sentinel: Main Scanner Orchestrator (Dynamic YAML Engine)
 * 
 * SECURITY: 
 * - YAML rule filenames validated to prevent path traversal
 * - Resolved paths verified to stay within trusted rule directories
 * - Regex patterns from custom rules protected against ReDoS with length limits
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const yaml = require('js-yaml');
const vm = require('vm');
const { detectInvisibleChars } = require('./detector_unicode');
const { detectHighEntropy } = require('./detector_entropy');
const { analyzeLifecycleScripts, analyzeTransitiveDeps } = require('./lifecycle_filter');
const { analyzeLockfile, analyzePnpmLockfile } = require('./lockfile_filter');
const { analyzeNpmrc, analyzeYarnrcYml } = require('./config_integrity');
const astInspector = require('./ast_inspector');
const { isValidRuleFilename, isPathWithinRoot } = require('../lib/sanitizer');

let compiledRules = [];

// Maximum regex pattern length to prevent ReDoS
const MAX_REGEX_LENGTH = 500;
// Maximum lines per scan to prevent DoS via massive files
const MAX_SCAN_LINES = 10000;

function loadRules() {
    compiledRules = [];
    const ruleDirs = [
        path.join(__dirname, 'rules'),
        path.join(os.homedir(), '.sentinel', 'rules')
    ];

    for (const dir of ruleDirs) {
        if (!fs.existsSync(dir)) continue;
        const files = fs.readdirSync(dir).filter(f => f.endsWith('.yaml') || f.endsWith('.yml'));
        
        for (const file of files) {
            // SECURITY: Validate filename to prevent path traversal
            if (!isValidRuleFilename(file)) {
                console.error(`[SECURITY] Rejected rule file with suspicious name: ${file.substring(0, 50)}`);
                continue;
            }

            // SECURITY: Verify resolved path stays within the rules directory
            const resolvedPath = path.resolve(dir, file);
            if (!isPathWithinRoot(resolvedPath, dir)) {
                console.error(`[SECURITY] Path traversal attempt blocked: ${file.substring(0, 50)}`);
                continue;
            }

            try {
                const content = fs.readFileSync(resolvedPath, 'utf8');
                const rules = yaml.load(content) || [];
                rules.forEach(rule => {
                    if (rule.pattern) {
                        try {
                            // SECURITY: Reject overly complex regex patterns (ReDoS protection)
                            if (typeof rule.pattern !== 'string' || rule.pattern.length > MAX_REGEX_LENGTH) {
                                console.error(`[SECURITY] Rejected rule ${rule.id || 'unknown'}: pattern too long (${String(rule.pattern).length} chars, max ${MAX_REGEX_LENGTH})`);
                                return;
                            }
                            // Compile Regex
                            rule.regex = new RegExp(rule.pattern, 'g');
                            compiledRules.push(rule);
                        } catch (e) {
                            console.error(`Invalid regex in rule ${rule.id}: ${e.message}`);
                        }
                    }
                });
            } catch (err) {
                console.error(`Failed to load rules from ${file}: ${err.message}`);
            }
        }
    }
}

// Initial load (safe — missing rules dir is non-fatal)
try { loadRules(); } catch (e) { console.warn('[SCANNER] Rule loading failed (non-fatal):', e.message); }

// Helper to prevent ReDoS hanging the Node event loop
function safeRegexTest(regex, string, timeoutMs = 50) {
    try {
        const context = vm.createContext({ regex, string, result: false });
        const script = new vm.Script('result = regex.test(string);');
        script.runInContext(context, { timeout: timeoutMs });
        return context.result;
    } catch (err) {
        throw new Error(`Regex execution error or timed out after ${timeoutMs}ms`);
    }
}

function scanFile(filename, content, authorMeta = null) {
    const results = {
        filename,
        timestamp: new Date().toISOString(),
        alerts: [],
        authorMeta // Store for downstream consumers
    };

    // 1. Run Dynamic YAML Rules
    // ... (rest of logic)
    const lines = content.split('\n');

    // SECURITY: Limit total lines to prevent DoS via massive files
    const linesToScan = lines.slice(0, MAX_SCAN_LINES);

    linesToScan.forEach((line, index) => {
        compiledRules.forEach(rule => {
            try {
                rule.regex.lastIndex = 0; // reset
                if (safeRegexTest(rule.regex, line)) {
                    // Capture snippet: 2 lines before, current line, 2 lines after
                    const start = Math.max(0, index - 2);
                    const end = Math.min(lines.length, index + 3);
                    const snippet = lines.slice(start, end).map((l, i) => `${start + i + 1}: ${l}`).join('\n');

                    results.alerts.push({
                        ruleName: rule.name,
                        category: rule.category || 'general',
                        riskLevel: rule.severity || 5,
                        description: rule.description,
                        line: line.trim().substring(0, 400),
                        evidence: snippet.substring(0, 2000), // Max snippet length
                        line_number: index + 1
                    });
                }
            } catch (e) {
                // ReDoS protection: if regex execution fails or times out, skip silently
                console.error(`[SECURITY] Regex execution failed for rule ${rule.name}: ${e.message}`);
            }
        });
    });

    // 2. Run Hardcoded/Heuristic Detectors
    results.alerts.push(...detectInvisibleChars(content));
    results.alerts.push(...detectHighEntropy(content));

    // 3. Package Manager checks — lifecycle scripts (npm / pnpm / yarn / bun)
    if (filename.match(/(package\.json|pnpm-lock\.yaml|yarn\.lock|bun\.lockb)$/i)) {
        results.alerts.push(...analyzeLifecycleScripts(content, authorMeta));
    }

    // 4. Lockfile Integrity Guardian (Sentinel 2.0)
    if (filename.match(/package-lock\.json$/i)) {
        results.alerts.push(...analyzeLockfile(content, null));
        // Transitive dependency analysis — catches attacks 2+ levels deep
        results.alerts.push(...analyzeTransitiveDeps(content, authorMeta));
    }
    if (filename.match(/pnpm-lock\.yaml$/i)) {
        results.alerts.push(...analyzePnpmLockfile(content));
    }

    // 5. Config Integrity Monitor (Sentinel 2.0)
    if (filename.match(/\.npmrc(\.local)?$/i) || filename === '.npmrc') {
        results.alerts.push(...analyzeNpmrc(content, filename));
    }
    if (filename.match(/\.yarnrc\.yml$/i)) {
        results.alerts.push(...analyzeYarnrcYml(content, filename));
    }
    if (filename.match(/\.yarnrc$/i)) {
        // Classic Yarn 1 format (INI-like) — reuse npmrc parser
        results.alerts.push(...analyzeNpmrc(content, filename));
    }

    // 6. AST Behavior Analysis (Sentinel 2.0) — Source→Sink chain detection
    // Run on JS/TS/MJS files but NOT on package manager manifests (already handled above)
    const isJsFile = filename.match(/\.(js|mjs|cjs|ts|mts|cts)$/i);
    const isPkgManagerFile = filename.match(/(package(-lock)?\.json|lockfile|yarn\.lock|\.npmrc|\.yarnrc)/i);
    if (isJsFile && !isPkgManagerFile) {
        try {
            const astAlerts = astInspector.analyze(content, filename);
            results.alerts.push(...astAlerts.filter(a => a.severity !== 'INFO'));
        } catch (e) {
            // AST analysis is non-fatal
            console.warn(`[AST] Analysis failed for ${filename}: ${e.message}`);
        }
    }

    // 7. GitHub Actions Workflow Scanner (Sentinel 3.0) ──────────────────────
    // Detecta configuraciones maliciosas dentro de .github/workflows/*.yml
    // como registry overrides, download-and-exec, y auto-publish sin review.
    // Las reglas YAML están en scanner/rules/github-actions.yaml y se cargan
    // automáticamente junto con el resto de reglas en loadRules().
    //
    // Activación: Solo para archivos .yml/.yaml que estén en una ruta de workflow
    // (el caller debe pasar la ruta relativa como filename para que funcione).
    const isWorkflowFile = filename.match(/\.(yml|yaml)$/i) &&
        (filename.includes('.github/workflows') || filename.includes('github/workflows'));
    if (isWorkflowFile) {
        // Re-aplicar las reglas de CI sobre el contenido YAML del workflow.
        // Esto captura patrones que el scanner de reglas genérico ya aplica,
        // pero ahora también incluye las reglas específicas de github-actions.yaml.
        // No hay lógica extra aquí — las reglas YAML ya se compilan en loadRules()
        // y se aplican en el bloque 1 (Dynamic YAML Rules) de arriba.
        // Este bloque sirve para añadir alertas contextuales adicionales:
        results.alerts.push(
            // Verificar si el CI_ENVIRONMENT_EVASION está activo en workflows también
            ...detectWorkflowEvasionPatterns(content, filename)
        );
    }

    return results;
}

/**
 * Detecta patrones de evasión específicos de GitHub Actions workflows.
 * Complementa las reglas YAML con lógica contextual más sofisticada.
 *
 * @param {string} content  - Contenido del archivo .yml
 * @param {string} filename - Nombre del archivo (para contexto en alertas)
 * @returns {Array}         - Lista de alertas adicionales
 */
function detectWorkflowEvasionPatterns(content, filename) {
    const alerts = [];

    // a) Detectar si el workflow desactiva debug/logging antes de pasos sensibles
    if (/no[-_]?log|disable[-_]?log|ACTIONS_RUNNER_DEBUG.*false/i.test(content)) {
        alerts.push({
            ruleName: 'Workflow Logging Disabled',
            category: 'ci-evasion',
            riskLevel: 8,
            description: `${filename} desactiva el logging de runner. Técnica usada para suprimir telemetría durante exfiltración.`,
            line: 'See workflow logging configuration',
            evidence: 'ACTIONS_RUNNER_DEBUG or similar logging disabling detected'
        });
    }

    // b) Detectar if-conditions que saltan pasos según el entorno
    if (/if:.*GITHUB_ACTIONS|if:.*CI.*==|if:.*runner\.os/i.test(content)) {
        alerts.push({
            ruleName: 'Conditional CI Evasion in Workflow',
            category: 'ci-evasion',
            riskLevel: 7,
            description: `${filename} tiene condiciones if: basadas en el entorno CI/runner. Puede usarse para comportarse diferente según el entorno, evadiendo sandbox.`,
            line: 'Conditional if: block detected',
            evidence: 'if: ${{ env.CI }} or runner-based condition detected'
        });
    }

    return alerts;
}


function scanLocalFile(filepath, content) {
    // For CLI wrapper
    return scanFile(path.basename(filepath), content);
}

function scanDirectory(dirPath, repoId = null, depth = 5) {
    const results = {
        threats: 0,
        filesScanned: 0,
        details: []
    };

    if (!fs.existsSync(dirPath) || depth < 0) return results;

    const excluded = ['node_modules', '.git', 'dist', 'build', '.next', 'out', 'vendor'];
    
    try {
        const items = fs.readdirSync(dirPath);
        for (const item of items) {
            if (excluded.includes(item)) continue;

            const fullPath = path.join(dirPath, item);
            const stats = fs.statSync(fullPath);

            if (stats.isDirectory()) {
                const subResults = scanDirectory(fullPath, repoId, depth - 1);
                results.threats += subResults.threats;
                results.filesScanned += subResults.filesScanned;
                results.details.push(...subResults.details);
            } else if (stats.isFile()) {
                try {
                    const content = fs.readFileSync(fullPath, 'utf8');
                    const scan = scanFile(item, content);
                    results.filesScanned++;
                    
                    if (scan.alerts.length > 0) {
                        results.threats += scan.alerts.length;
                        scan.alerts.forEach(alert => {
                            results.details.push(`${item}: ${alert.ruleName} (${alert.category})`);
                        });
                    }
                } catch (e) {
                    // Skip binary or unreadable files
                }
            }
        }
    } catch (err) {
        console.error(`[SCANNER] Error scanning directory ${dirPath}:`, err.message);
    }

    return results;
}

module.exports = { scanFile, scanLocalFile, scanDirectory, loadRules, analyzeLifecycleScripts };
