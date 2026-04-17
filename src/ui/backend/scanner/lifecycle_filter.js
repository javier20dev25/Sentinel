/**
 * Sentinel: Lifecycle Script Filter (ADVANCED)
 * Analyzes package.json for dangerous pre/postinstall scripts with de-obfuscation.
 * 
 * SECURITY:
 * - JSON deep parsing to avoid regex-only bypasses.
 * - Static de-obfuscation for Base64, Hex, and charCode.
 * - Risk Scoring based on author reputation, obfuscation, and networking.
 */

'use strict';

const DANGEROUS_COMMANDS = [
    'curl', 'wget', 'eval', 'sh', 'bash', 'node -e', 'fetch', 
    'python', 'perl', 'ruby', 'nc', 'netcat', 'powershell', 'pwsh',
    'cmd.exe', '/bin/sh', 'chmod +x', 'rm -rf /'
];

const SENSITIVE_SCRIPTS = [
    'preinstall', 'postinstall', 'install', 
    'prepublish', 'postpublish', 'preprepare', 'prepare',
    'postcheckout', 'postmerge', 'prepush'
];

/**
 * Attempts to normalize/decode potentially obfuscated scripts.
 * Supports: Base64, Hex encoding, and simple string inversion detection.
 */
function normalizeScript(script) {
    if (typeof script !== 'string') return '';
    let normalized = script;
    let detectionEvidence = [];

    // 1. Detect and decode Base64
    // Looking for blocks of 20+ base64 chars
    const b64Regex = /([A-Za-z0-9+/]{20,}=*)/g;
    normalized = normalized.replace(b64Regex, (match) => {
        try {
            const decoded = Buffer.from(match, 'base64').toString('utf8');
            // Only use if it looks like printable ASCII
            if (/^[\x20-\x7E\s]+$/.test(decoded) && decoded.length > 5) {
                detectionEvidence.push(`Base64_Detected: ${decoded}`);
                return decoded;
            }
        } catch (e) {}
        return match;
    });

    // 2. Detect and decode Hex encoding (\x41)
    const hexRegex = /\\x([0-9a-fA-F]{2})/g;
    if (hexRegex.test(normalized)) {
        detectionEvidence.push('Hex_Encoding_Detected');
        normalized = normalized.replace(hexRegex, (match, hex) => {
            return String.fromCharCode(parseInt(hex, 16));
        });
    }

    // 3. Detect string inversion hints (e.g., .split('').reverse().join(''))
    if (normalized.includes('.reverse().join(') || normalized.includes('split("").reverse()')) {
        detectionEvidence.push('String_Inversion_Logic_Detected');
    }

    return { normalized, detectionEvidence };
}

/**
 * Calculates a risk score from 0 to 10.
 */
function calculateRisk(script, evidence, authorReputation = null) {
    let score = 2; // Baseline for having a lifecycle script

    const cmd = script.toLowerCase();
    
    // Critical commands (Shells, downloaders)
    if (DANGEROUS_COMMANDS.some(d => cmd.includes(d))) score += 5;
    
    // Evidence of obfuscation
    if (evidence.length > 0) score += 3;
    
    // Low author reputation (if available)
    if (authorReputation && authorReputation.ageDays < 30) score += 2;
    if (authorReputation && authorReputation.isNew) score += 2;

    return Math.min(10, score);
}

/**
 * Analyzes the contents of a package.json file.
 */
function analyzeLifecycleScripts(packageJsonContent, authorMeta = null) {
    let pkg;
    try {
        pkg = JSON.parse(packageJsonContent);
    } catch (e) {
        return [{ type: 'JSON_ERROR', message: 'Invalid package.json format.', severity: 'CRITICAL', riskLevel: 10 }];
    }

    const scripts = pkg.scripts || {};
    const alerts = [];

    // 1. Scan Scripts
    SENSITIVE_SCRIPTS.forEach(scriptName => {
        if (scripts[scriptName]) {
            const original = scripts[scriptName];
            const { normalized, detectionEvidence } = normalizeScript(original);
            
            const risk = calculateRisk(normalized, detectionEvidence, authorMeta);
            const foundDangerous = DANGEROUS_COMMANDS.filter(cmd => normalized.toLowerCase().includes(cmd));

            if (risk >= 7 || foundDangerous.length > 0) {
                alerts.push({
                    script: scriptName,
                    type: 'MALICIOUS_LIFECYCLE_SCRIPT',
                    message: `High-risk script detected in '${scriptName}'.`,
                    evidence: `Original: ${original}\nNormalized: ${normalized}\nIndicators: ${detectionEvidence.join(', ') || 'Direct execution'}`,
                    riskLevel: risk,
                    severity: 'CRITICAL',
                    author: authorMeta ? authorMeta.username : 'Unknown'
                });
            } else if (risk >= 4) {
                alerts.push({
                    script: scriptName,
                    type: 'SUSPICIOUS_LIFECYCLE_SCRIPT',
                    message: `Suspicious lifecycle script '${scriptName}' detected.`,
                    evidence: `Normalized: ${normalized}`,
                    riskLevel: risk,
                    severity: 'WARNING',
                    author: authorMeta ? authorMeta.username : 'Unknown'
                });
            }
        }
    });

    // 2. Scan Dependencies for direct URLs (Malware Droppers / Invisible Deps)
    const depFields = ['dependencies', 'devDependencies', 'optionalDependencies'];
    depFields.forEach(field => {
        if (pkg[field]) {
            Object.entries(pkg[field]).forEach(([name, version]) => {
                if (typeof version === 'string' && (version.startsWith('http') || version.startsWith('git'))) {
                    alerts.push({
                        script: 'dependency',
                        type: 'DIRECT_URL_DEPENDENCY',
                        message: `Package '${name}' is loaded from a direct URL instead of registry.`,
                        evidence: `${name}: ${version}`,
                        riskLevel: 8,
                        severity: 'CRITICAL',
                        author: authorMeta ? authorMeta.username : 'Unknown'
                    });
                }
            });
        }
    });

    return alerts;
}

/**
 * Builds a dependency graph from a package-lock.json (v2/v3)
 * and scans every node for lifecycle scripts and suspicious resolutions.
 *
 * This closes the "phantom sub-dependency" attack vector used in the
 * real-world Axios supply-chain attack (March 2026), where the malicious
 * package was two levels deep and invisible to surface-only scanners.
 *
 * @param {string} lockfileContent  — Contents of package-lock.json
 * @param {object} authorMeta       — Optional PR author metadata
 * @returns {Array}                 — List of alerts from all transitive deps
 */
function analyzeTransitiveDeps(lockfileContent, authorMeta = null) {
    const alerts = [];
    let lock;

    try {
        lock = JSON.parse(lockfileContent);
    } catch (e) {
        return [{ type: 'LOCKFILE_PARSE_ERROR', message: 'Could not parse lockfile for transitive analysis.', riskLevel: 9 }];
    }

    // Work with package-lock v2/v3 "packages" map
    const packages = lock.packages || {};

    for (const [pkgPath, pkgData] of Object.entries(packages)) {
        if (!pkgPath) continue; // Skip root entry

        const pkgName = pkgPath.replace(/^node_modules\//, '').split('/node_modules/').pop();
        const version  = pkgData.version || 'unknown';
        const scripts  = pkgData.bin || {};  // package-lock stores bin, not scripts directly
        const resolved = pkgData.resolved || '';

        // ── 1. Lifecycle scripts embedded in the lockfile entry ──────────────
        // Some malicious packages declare inline lifecycle hooks via "lifecycle"
        // (not standard, but some bundlers include it)
        if (pkgData.scripts) {
            const pseudoPkg = JSON.stringify({ scripts: pkgData.scripts });
            const scriptAlerts = analyzeLifecycleScripts(
                `{"scripts":${JSON.stringify(pkgData.scripts)}}`,
                authorMeta
            );
            scriptAlerts.forEach(a => {
                alerts.push({
                    ...a,
                    type: `TRANSITIVE_${a.type}`,
                    message: `[Dep transitivo] ${pkgName}@${version}: ${a.message}`,
                    package: pkgName,
                    depth: (pkgPath.match(/node_modules/g) || []).length
                });
            });
        }

        // ── 2. Suspicious registry resolution (deep deps) ────────────────────
        const UNTRUSTED = /^(?!https:\/\/registry\.npmjs\.org|https:\/\/registry\.yarnpkg\.com)/i;
        const GIT_OR_HTTP = /^(git\+https?:\/\/|git:\/\/|file:|github:|bitbucket:|gitlab:|https?:\/\/(?!registry\.npmjs\.org|registry\.yarnpkg\.com))/i;

        if (resolved && GIT_OR_HTTP.test(resolved)) {
            alerts.push({
                type: 'TRANSITIVE_DIRECT_URL_DEP',
                severity: 'CRITICAL',
                riskLevel: 10,
                message: `[Dep transitivo] '${pkgName}@${version}' se resuelve desde URL externa directa (posible dropper en sub-dependencia).`,
                evidence: `resolved: ${resolved}`,
                package: pkgName,
                depth: (pkgPath.match(/node_modules/g) || []).length,
                author: authorMeta ? authorMeta.username : 'Unknown'
            });
        }

        // ── 3. Single-maintainer + new version heuristic ────────────────────
        // We can't do full reputation checks without network, but we flag
        // packs with very short version strings added recently (anomaly signal)
        if (pkgData._integrity === undefined && resolved && resolved.includes('registry.npmjs.org')) {
            alerts.push({
                type: 'TRANSITIVE_MISSING_INTEGRITY',
                severity: 'HIGH',
                riskLevel: 7,
                message: `[Dep transitivo] '${pkgName}@${version}' no tiene campo de integridad en el lockfile (posible manifest-swap en sub-dependencia).`,
                evidence: `Package path: ${pkgPath}`,
                package: pkgName,
                depth: (pkgPath.match(/node_modules/g) || []).length
            });
        }
    }

    return alerts;
}

module.exports = { analyzeLifecycleScripts, analyzeTransitiveDeps };
