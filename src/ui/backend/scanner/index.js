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
const { analyzeLifecycleScripts } = require('./lifecycle_filter');
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

// Initial load
loadRules();

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

function scanFile(filename, content) {
    const results = {
        filename,
        timestamp: new Date().toISOString(),
        alerts: []
    };

    // 1. Run Dynamic YAML Rules
    const lines = content.split('\n');

    // SECURITY: Limit total lines to prevent DoS via massive files
    const linesToScan = lines.slice(0, MAX_SCAN_LINES);

    linesToScan.forEach((line, index) => {
        compiledRules.forEach(rule => {
            try {
                rule.regex.lastIndex = 0; // reset
                if (safeRegexTest(rule.regex, line)) {
                    results.alerts.push({
                        ruleName: rule.name,
                        category: rule.category || 'general',
                        riskLevel: rule.severity || 5,
                        description: rule.description,
                        line: line.trim().substring(0, 500) // Limit evidence length
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

    // 3. Package Manager checks (pnpm, yarn, npm, bun)
    if (filename.match(/(package\.json|pnpm-lock\.yaml|yarn\.lock|bun\.lockb)$/i)) {
        results.alerts.push(...analyzeLifecycleScripts(content));
    }

    return results;
}

function scanLocalFile(filepath, content) {
    // For CLI wrapper
    return scanFile(path.basename(filepath), content);
}

module.exports = { scanFile, scanLocalFile, loadRules };
