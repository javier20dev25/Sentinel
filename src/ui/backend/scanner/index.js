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
const ConfidenceScorer = require('./confidence_scorer');
const TriggerLevelOrchestrator = require('./trigger_levels');
const { analyzeBinary, isBinaryAsset } = require('./detector_binary');
const { isValidRuleFilename, isPathWithinRoot } = require('../lib/sanitizer');
const GateOrchestrator = require('./gate_orchestrator');
const { detectMasquerading } = require('./magic_bytes');

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

function scanFile(filename, content, authorMeta = null, options = { mode: 'local' }) {
    const SAFE_MODE = options.mode !== 'sandbox';
    const ALLOW_DYNAMIC = !SAFE_MODE;

    const results = {
        filename,
        timestamp: new Date().toISOString(),
        alerts: [],
        authorMeta, // Store for downstream consumers
        gateLevel: options.gateLevel || 0
    };

    // 1. Run Dynamic YAML Rules
    // ... (rest of logic)
    const lines = content.split('\n');

    // SECURITY: Limit total lines to prevent DoS via massive files
    const linesToScan = lines.slice(0, MAX_SCAN_LINES);

    linesToScan.forEach((line, index) => {
        compiledRules.forEach(rule => {
            if (options.fast) {
                const isCriticalScore = (rule.severity || 0) >= 8;
                const isCriticalFamily = rule.id && (rule.id.includes('EXEC') || rule.id.includes('NET') || rule.id.includes('EXFIL') || rule.id.includes('obfuscation'));
                if (!isCriticalScore && !isCriticalFamily) return;
            }
            try {
                rule.regex.lastIndex = 0; // reset
                // PERFORMANCE: Avoid vm context for every line test. 
                // Only use safeRegexTest for complex/massive files if needed.
                if (rule.regex.test(line)) {
                    // Capture snippet: 2 lines before, current line, 2 lines after
                    const start = Math.max(0, index - 2);
                    const end = Math.min(lines.length, index + 3);
                    const snippet = lines.slice(start, end).map((l, i) => `${start + i + 1}: ${l}`).join('\n');

                    results.alerts.push({
                        rule_id: `SARB-STATIC-${Math.floor(Math.random() * 899 + 100)}`,
                        ruleName: rule.name,
                        category: rule.category || 'general',
                        classification: 'SECURITY', // Static heuristics are always security findings
                        riskLevel: rule.severity || 5,
                        description: rule.description,
                        explanation: `Sentinel matched static YAML heuristic pattern: ${rule.regex.source}`,
                        matched_patterns: [rule.regex.source],
                        line: line.trim().substring(0, 400),
                        evidence: snippet.substring(0, 2000), // Max snippet length
                        line_number: index + 1
                    });
                }
            } catch (e) {
                console.error(`[SECURITY] Regex execution failed for rule ${rule.name}: ${e.message}`);
            }
        });
    });

    // 2. Run Hardcoded/Heuristic Detectors
    const heuristicAlerts = detectInvisibleChars(content);
    heuristicAlerts.forEach(a => a.classification = 'SECURITY');
    results.alerts.push(...heuristicAlerts);

    if (!options.fast) {
        const entropyAlerts = detectHighEntropy(content);
        entropyAlerts.forEach(a => a.classification = 'SECURITY');
        results.alerts.push(...entropyAlerts);
    }

    // 3. Package Manager checks — lifecycle scripts (npm / pnpm / yarn / bun)
    if (filename.match(/(package\.json|pnpm-lock\.yaml|yarn\.lock|bun\.lockb)$/i)) {
        const policyAlerts = analyzeLifecycleScripts(content, authorMeta);
        policyAlerts.forEach(a => a.classification = 'POLICY'); // Lifecycle scripts are policy violations
        results.alerts.push(...policyAlerts);
    }

    // 4. Lockfile Integrity Guardian (Sentinel 2.0)
    if (filename.match(/package-lock\.json$/i)) {
        const lockAlerts = analyzeLockfile(content, null);
        lockAlerts.forEach(a => a.classification = 'POLICY');
        results.alerts.push(...lockAlerts);
        
        const transitiveAlerts = analyzeTransitiveDeps(content, authorMeta);
        transitiveAlerts.forEach(a => a.classification = 'POLICY');
        results.alerts.push(...transitiveAlerts);
    }
    if (filename.match(/pnpm-lock\.yaml$/i)) {
        const pnpmAlerts = analyzePnpmLockfile(content);
        pnpmAlerts.forEach(a => a.classification = 'POLICY');
        results.alerts.push(...pnpmAlerts);
    }

    // 5. Config Integrity Monitor (Sentinel 2.0)
    if (filename.match(/\.npmrc(\.local)?$/i) || filename === '.npmrc') {
        const npmrcAlerts = analyzeNpmrc(content, filename);
        npmrcAlerts.forEach(a => a.classification = 'POLICY');
        results.alerts.push(...npmrcAlerts);
    }
    if (filename.match(/\.yarnrc\.yml$/i)) {
        const yarnrcAlerts = analyzeYarnrcYml(content, filename);
        yarnrcAlerts.forEach(a => a.classification = 'POLICY');
        results.alerts.push(...yarnrcAlerts);
    }
    if (filename.match(/\.yarnrc$/i)) {
        // Classic Yarn 1 format (INI-like) — reuse npmrc parser
        results.alerts.push(...analyzeNpmrc(content, filename));
    }

    // 6. Adaptive AST & Semantic Analysis (Sentinel 3.3)
    // Reemplaza el análisis AST binario por el motor de Confidence Scoring y Trigger Levels.
    const isJsFile = filename.match(/\.(js|mjs|cjs|ts|mts|cts)$/i);
    const isPkgManagerFile = filename.match(/(package(-lock)?\.json|lockfile|yarn\.lock|\.npmrc|\.yarnrc)/i);
    
    if (isJsFile && !isPkgManagerFile) {
        try {
            // Inicializar motor adaptativo para este archivo
            const scorer = new ConfidenceScorer();
            const orchestrator = new TriggerLevelOrchestrator(scorer);

            // Ejecutar pipeline adaptativo (Trigger Levels 1 & 2)
            orchestrator.analyze(content, filename);

            // Extraer amenazas basadas en el Confidence Score acumulado
            const semanticThreats = scorer.evaluateAll();
            
            if (semanticThreats.length > 0) {
                results.alerts.push(...semanticThreats.map((t, idx) => {
                    // Governance: SARB ID Injection
                    let sarbFamily = 'HEUR';
                    if (t.intentFingerprint?.intent_signature?.includes('EXECUTION')) sarbFamily = 'EXEC';
                    else if (t.intentFingerprint?.intent_signature?.includes('EVASION')) sarbFamily = 'EVASION';
                    else if (t.intentFingerprint?.intent_signature?.includes('NETWORK')) sarbFamily = 'NET';
                    else if (t.intentFingerprint?.intent_signature?.includes('EXFILTRATION')) sarbFamily = 'EXFIL';
                    
                    const ruleId = `SARB-${sarbFamily}-${Math.floor(Math.random() * 899 + 100)}`;
                    const matchedPatterns = t._rawRecord?.signals?.map(s => s.type) || [];
                    const evidenceClean = (t.evidence || '').substring(0, 400);

                    return {
                        rule_id: ruleId,
                        ruleName: t.ruleName,
                        category: t.category || 'semantic',
                        classification: 'SECURITY',
                        riskLevel: t.riskLevel,
                        description: t.description,
                        explanation: `Sentinel adaptive engine caught ${sarbFamily} behavior chaining ${matchedPatterns.join(' -> ')}. Trigger limit breached at score ${t.riskLevel}.`,
                        matched_patterns: matchedPatterns,
                        line: evidenceClean,
                        evidence: t.evidence,
                        severity: t.severity,
                        _rawRecord: t._rawRecord,
                        intentFingerprint: t.intentFingerprint
                    };
                }));
            }
        } catch (e) {
            console.warn(`[Adaptive Engine] Analysis failed for ${filename}: ${e.message}`);
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
            classification: 'POLICY',
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
            classification: 'POLICY',
            riskLevel: 7,
            description: `${filename} tiene condiciones if: basadas en el entorno CI/runner. Puede usarse para comportarse diferente según el entorno, evadiendo sandbox.`,
            line: 'Conditional if: block detected',
            evidence: 'if: ${{ env.CI }} or runner-based condition detected'
        });
    }

    return alerts;
}


function scanLocalFile(filepath, content, options = { mode: 'local' }) {
    // For CLI wrapper
    return scanFile(path.basename(filepath), content, null, options);
}

function scanDirectory(dirPath, repoId = null, depth = 5, options = { mode: 'local' }) {
    if (typeof repoId === 'object' && repoId !== null) {
        // Handle case where options was passed as second argument
        options = repoId;
        repoId = null;
    }

    const SAFE_MODE = options.mode !== 'sandbox';
    const finalDepth = options.fast ? 1 : depth;
    const isForensic = options.gateLevel === 4 || options.forensic;
    
    const results = {
        threats: 0,
        filesScanned: 0,
        details: [],
        rawAlerts: [],
        gateLevel: options.gateLevel || 0
    };

    if (!fs.existsSync(dirPath) || finalDepth < 0) return results;

    const excluded = isForensic ? ['.git'] : ['node_modules', '.git', 'dist', 'build', '.next', 'out', 'vendor'];
    
    try {
        const items = fs.readdirSync(dirPath);
        for (const item of items) {
            if (excluded.includes(item)) continue;

            const fullPath = path.join(dirPath, item);
            const stats = fs.statSync(fullPath);

            if (stats.isDirectory()) {
                const subResults = scanDirectory(fullPath, repoId, finalDepth - 1, options);
                results.threats += subResults.threats;
                results.filesScanned += subResults.filesScanned;
                results.details.push(...subResults.details);
                results.rawAlerts.push(...(subResults.rawAlerts || []));
            } else if (stats.isFile()) {
                // [3.3] Binary asset & Masquerading check
                const buffer = fs.readFileSync(fullPath);
                
                // 1. Check for masquerading (extension mismatch)
                const actualExt = detectMasquerading(buffer, path.extname(item));
                if (actualExt) {
                    results.threats++;
                    const alert = {
                        ruleName: 'Binary Masquerading',
                        category: 'artifact-gate',
                        classification: 'POLICY',
                        riskLevel: 9,
                        severity: 'CRITICAL',
                        description: `Archivo '${item}' parece ser un ${actualExt} pero usa una extensión falsa. Técnica típica de droppers de malware.`,
                        evidence: `Declared: ${path.extname(item)} | Detected: ${actualExt}`,
                        _file: item,
                        _fullPath: fullPath
                    };
                    results.rawAlerts.push(alert);
                    results.details.push(`${item}: Binary Masquerading (artifact-gate)`);
                }

                if (isBinaryAsset(item)) {
                    try {
                        const binaryAlerts = analyzeBinary(buffer, item);
                        results.filesScanned++;
                        if (binaryAlerts.length > 0) {
                            results.threats += binaryAlerts.length;
                            binaryAlerts.forEach(alert => {
                                alert.classification = 'POLICY'; // Binaries in repo are policy gated
                                const name = alert.ruleName || 'Binary Threat';
                                const cat = alert.category || 'binary-analysis';
                                results.details.push(`${item}: ${name} (${cat})`);
                                
                                // Export raw alert
                                results.rawAlerts.push({ ...alert, _file: item, _fullPath: fullPath });
                            });
                        }
                    } catch (e) {
                        // Skip unreadable binary files
                    }
                    continue;
                }

                try {
                    const content = fs.readFileSync(fullPath, 'utf8');
                    const scan = scanFile(item, content, null, options);
                    results.filesScanned++;
                    
                    if (scan.alerts.length > 0) {
                        results.threats += scan.alerts.length;
                        scan.alerts.forEach(alert => {
                            const name = alert.ruleName || alert.id || 'Unknown Threat';
                            const cat = alert.category || 'general';
                            results.details.push(`${item}: ${name} (${cat})`);
                            
                            // Adosar el nombre de archivo a cada alert para el CLI render
                            const fileAlert = { 
                                ...alert, 
                                _file: item, 
                                _fullPath: fullPath,
                                _context: {
                                    analysis_mode: options.mode,
                                    execution: options.mode === 'sandbox' ? 'isolated' : 'none'
                                }
                            };
                            results.rawAlerts.push(fileAlert);
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
