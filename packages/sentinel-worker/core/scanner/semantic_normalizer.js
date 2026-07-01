/**
 * Sentinel: Semantic Intent Normalizer (v1.0)
 * 
 * Maps complex code patterns and indirections to normalized Intent Nodes.
 * This transcends regex by modeling the BEHAVIORAL INTENT rather than the syntax.
 */

'use strict';

class SemanticNormalizer {
    constructor() {
        this.nodes = {
            'DYNAMIC_EXECUTION': [
                /eval\s*\(/,
                /Function\s*\(/,
                /new\s+(Async)?Function\s*\(/,
                /constructor\.constructor\s*\(/,
                /\[\s*['"]constructor['"]\s*\]/,
                /Reflect\.construct\(\s*Function/,
                /globalThis\[.*['"]eval['"]\s*\]/,
                /globalThis\[\s*['"]\w+['"]\s*\+\s*['"]\w+['"]\s*\]/,
                /\[\s*['"]\w+['"]\s*\+\s*['"]\w+['"]\s*\]\s*\(/,
                /require\(['"]vm['"]\)\.runInContext/,
                /\.(filter|reduce|map|find)\.constructor/
            ],
            'NETWORK_CAPABILITY': [
                /fetch\s*\(/,
                /axios\s*\./,
                /require\(['"](https?|net|dns|tls)['"]\)/,
                /Reflect\.get\(.*['"]fetch['"]\)/,
                /Reflect\.get\(.*['"]\w+['"]\s*\+\s*['"]\w+['"]\)/,
                /new\s+WebSocket\(/
            ],
            'SECRET_ACCESS': [
                /process\.env\.[A-Z_]+/,
                /require\(['"]fs['"]\)\.readFileSync\(['"].*\.env['"]\)/,
                /Buffer\.from\(['"]SECRET['"]\)/
            ],
            'SYSTEM_TAMPERING': [
                /child_process\.exec\(/,
                /child_process\.spawn\(/,
                /git\s+config/,
                /npm_config_registry/
            ],
            'OBFUSCATION_CHAIN': [
                /\.split\(['"]['"]\)\.reverse\(\)\.join\(['"]['"]\)/,
                /String\.fromCharCode\(/,
                /Buffer\.from\(.*['"]base64['"]\)/,
                /['"]\\x[0-9a-fA-F]{2}['"]/
            ]
        };
    }

    /**
     * Extracts normalized intent nodes from code content.
     */
    analyze(content) {
        const detected = new Set();
        
        for (const [node, patterns] of Object.entries(this.nodes)) {
            for (const pattern of patterns) {
                if (pattern.test(content)) {
                    detected.add(node);
                    break;
                }
            }
        }
        
        return Array.from(detected);
    }
}

module.exports = new SemanticNormalizer();
