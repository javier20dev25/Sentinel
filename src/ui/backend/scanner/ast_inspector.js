/**
 * Sentinel: Advanced AST Inspector
 * Analyzes JavaScript code structure to detect malicious intent.
 */

const acorn = require('acorn');
const walk = require('acorn-walk');

class ASTInspector {
    /**
     * Scans source code for security threats using AST analysis.
     * @param {string} code - The source code to analyze
     * @param {string} filePath - Path for logging/context
     * @returns {Object[]} - List of detected threats
     */
    analyze(code, filePath = 'unknown') {
        const threats = [];
        let ast;

        try {
            ast = acorn.parse(code, { ecmaVersion: 'latest', sourceType: 'module' });
        } catch (e) {
            // If module parsing fails, try script
            try {
                ast = acorn.parse(code, { ecmaVersion: 'latest', sourceType: 'script' });
            } catch (e2) {
                return [{ type: 'PARSE_ERROR', message: 'Could not parse file for AST analysis.', severity: 'LOW' }];
            }
        }

        // State for tracking data flow (simplified)
        let hasProcessEnvAccess = false;
        let envVariables = new Set();

        walk.simple(ast, {
            // 1. Detect process.env access
            MemberExpression(node) {
                if (node.object.type === 'MemberExpression' &&
                    node.object.object.name === 'process' &&
                    node.object.property.name === 'env') {
                    hasProcessEnvAccess = true;
                    if (node.property.type === 'Identifier') {
                        envVariables.add(node.property.name);
                    }
                }
            },

            // 2. Detect Network Calls (fetch, axios, etc.)
            CallExpression(node) {
                const calleeName = this._getCalleeName(node.callee);
                
                const suspiciousNetworkFns = ['fetch', 'axios', 'request', 'get', 'post', 'put', 'patch'];
                
                if (suspiciousNetworkFns.includes(calleeName)) {
                    // Check if arguments include process.env data
                    const argsStr = JSON.stringify(node.arguments);
                    if (hasProcessEnvAccess || argsStr.includes('process.env')) {
                        threats.push({
                            type: 'DATA_EXFILTRATION_PATTERN',
                            message: `Suspicious network call '${calleeName}' detected alongside process.env access. Potential credentials theft.`,
                            severity: 'CRITICAL',
                            context: code.substring(node.start, node.end)
                        });
                    }
                }

                // 3. Detect Dynamic Execution (eval, new Function)
                if (calleeName === 'eval') {
                    threats.push({
                        type: 'DYNAMIC_EXECUTION',
                        message: "Use of 'eval()' detected. This is a common vector for injecting obfuscated malware.",
                        severity: 'HIGH',
                        context: code.substring(node.start, node.end)
                    });
                }
            },

            // 4. Detect New Function (another way to eval)
            NewExpression(node) {
                if (node.callee.name === 'Function') {
                    threats.push({
                        type: 'DYNAMIC_EXECUTION',
                        message: "Use of 'new Function()' detected. Often used to execute strings fetched from remote servers.",
                        severity: 'HIGH'
                    });
                }
            },

            // 5. Detect Sensitive Filesystem Access
            Literal(node) {
                if (typeof node.value === 'string') {
                    const sensitivePaths = ['.env', '.ssh', '.aws', '/etc/passwd', 'id_rsa'];
                    if (sensitivePaths.some(p => node.value.includes(p))) {
                        threats.push({
                            type: 'SENSITIVE_PATH_ACCESS',
                            message: `Hardcoded access to sensitive path/file '${node.value}' detected.`,
                            severity: 'HIGH',
                            context: node.value
                        });
                    }
                }
            }
        }, {
            // Helper to extract callee name recursively for MemberExpressions (e.g., axios.post)
            _getCalleeName(node) {
                if (node.type === 'Identifier') return node.name;
                if (node.type === 'MemberExpression') {
                    if (node.property.type === 'Identifier') return node.property.name;
                }
                return null;
            }
        });

        // 6. Entropy Check (Heuristic for obfuscation)
        if (code.length > 500) {
            const hexMatch = code.match(/[a-f0-9]{50,}/gi);
            if (hexMatch) {
                threats.push({
                    type: 'OBFUSCATED_CODE',
                    message: "Large hexadecimal string detected. This usually indicates obfuscated payload or binary injection.",
                    severity: 'HIGH'
                });
            }
        }

        return threats;
    }
}

module.exports = new ASTInspector();
