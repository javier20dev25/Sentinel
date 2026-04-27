/**
 * Sentinel: Advanced AST Inspector (Zero-Any Edition)
 */

import * as acorn from 'acorn';
import * as walk from 'acorn-walk';
import * as threatIntel from './threat_intel';
import { ForensicFinding } from '@/types';

// Type guards for Acorn nodes to satisfy strict linting
interface IdentifierNode extends acorn.Node {
    type: 'Identifier';
    name: string;
}

interface MemberExpressionNode extends acorn.Node {
    type: 'MemberExpression';
    object: acorn.Node;
    property: acorn.Node;
}

interface CallExpressionNode extends acorn.Node {
    type: 'CallExpression';
    callee: acorn.Node;
    arguments: acorn.Node[];
}

interface NewExpressionNode extends acorn.Node {
    type: 'NewExpression';
    callee: acorn.Node;
    arguments: acorn.Node[];
}

interface LiteralNode extends acorn.Node {
    type: 'Literal';
    value: string | number | boolean | null | RegExp;
}

const NETWORK_SOURCES = new Set(['fetch', 'request', 'get', 'axios', 'got', 'superagent', 'needle', 'http', 'https']);
const EXEC_SINKS      = new Set(['eval', 'exec', 'execSync', 'execFile', 'execFileSync', 'spawn', 'spawnSync',
                                   'Function', 'setTimeout', 'setInterval', 'setImmediate']);
const NETWORK_SINKS   = new Set(['fetch', 'post', 'put', 'send', 'request', 'write']);
const FS_WRITE_SINKS  = new Set(['writeFile', 'writeFileSync', 'appendFile', 'appendFileSync', 'createWriteStream']);

const SENSITIVE_PATHS = ['.env', '.ssh', '.aws', 'id_rsa', 'id_ed25519', '.npmrc', '.npmtoken',
                          '/etc/passwd', '/etc/shadow', 'credentials', 'secrets.json', '.htpasswd'];

const SENSITIVE_ENV_VARS = ['NPM_TOKEN', 'GITHUB_TOKEN', 'AWS_SECRET', 'AWS_ACCESS', 'DATABASE_URL',
                              'SECRET_KEY', 'API_KEY', 'AUTH_TOKEN', 'PRIVATE_KEY', 'GH_TOKEN'];

interface InspectorState {
    hasNetworkCall: boolean;
    hasEnvAccess: boolean;
    hasSensitivePath: boolean;
    hasExecCall: boolean;
    hasWriteCall: boolean;
    sensitiveEnvVars: string[];
    networkCallCtx: string[];
    execCallCtx: string[];
    ciCheckDetected: boolean;
}

function isIdentifier(node: unknown): node is IdentifierNode {
    return (node as acorn.Node)?.type === 'Identifier';
}

function isMemberExpression(node: unknown): node is MemberExpressionNode {
    return (node as acorn.Node)?.type === 'MemberExpression';
}

function isCallExpression(node: unknown): node is CallExpressionNode {
    return (node as acorn.Node)?.type === 'CallExpression';
}

function isLiteral(node: unknown): node is LiteralNode {
    return (node as acorn.Node)?.type === 'Literal';
}

function isNewExpression(node: unknown): node is NewExpressionNode {
    return (node as acorn.Node)?.type === 'NewExpression';
}

function getCallName(node: acorn.Node | null): string | null {
    if (!node) return null;
    if (isIdentifier(node)) return node.name;
    if (isMemberExpression(node)) {
        if (isIdentifier(node.property)) return node.property.name;
    }
    return null;
}

function getRootObject(node: acorn.Node | null): string | null {
    if (!node) return null;
    if (isIdentifier(node)) return node.name;
    if (isMemberExpression(node)) return getRootObject(node.object);
    return null;
}

export function analyze(code: string, filePath: string = 'unknown'): ForensicFinding[] {
    const threats: ForensicFinding[] = [];
    let ast: acorn.Node | null = null;

    for (const sourceType of ['module', 'script'] as const) {
        try {
            ast = acorn.parse(code, { ecmaVersion: 'latest', sourceType });
            break;
        } catch { }
    }

    if (!ast) {
        return [{ type: 'PARSE_ERROR', severity: 'LOW', message: `Could not parse '${filePath}'` }];
    }

    const state: InspectorState = {
        hasNetworkCall: false,
        hasEnvAccess: false,
        hasSensitivePath: false,
        hasExecCall: false,
        hasWriteCall: false,
        sensitiveEnvVars: [],
        networkCallCtx: [],
        execCallCtx: [],
        ciCheckDetected: false,
    };

    const snip = (node: acorn.Node) => code.substring(node.start, Math.min(node.end, node.start + 200)).trim();

    walk.simple(ast, {
        MemberExpression(node: unknown) {
            if (!isMemberExpression(node)) return;
            const root = getRootObject(node);
            
            // Check for process.env access
            if (root === 'process' && isMemberExpression(node.object)) {
                const innerProp = getCallName(node.object);
                if (innerProp === 'env') {
                    state.hasEnvAccess = true;
                    const varName = isIdentifier(node.property) ? node.property.name : '';
                    if (SENSITIVE_ENV_VARS.some(v => varName.toUpperCase().includes(v))) {
                        state.sensitiveEnvVars.push(varName);
                    }
                }
            }

            // Check for CI environment checks
            if (root === 'process' && 
                isMemberExpression(node.object) && 
                getCallName(node.object) === 'env' &&
                isIdentifier(node.property) &&
                ['CI', 'GITHUB_ACTIONS', 'TRAVIS', 'CIRCLECI'].includes(node.property.name)) {
                state.ciCheckDetected = true;
            }
        },
        CallExpression(node: unknown) {
            if (!isCallExpression(node)) return;
            const callName = getCallName(node.callee);
            if (!callName) return;

            if (NETWORK_SOURCES.has(callName)) {
                state.hasNetworkCall = true;
                state.networkCallCtx.push(snip(node));
            }

            if (EXEC_SINKS.has(callName)) {
                state.hasExecCall = true;
                state.execCallCtx.push(snip(node));
                if (callName === 'eval') {
                    threats.push({
                        type: 'DYNAMIC_EXECUTION',
                        severity: 'HIGH',
                        riskLevel: 8,
                        message: `eval() detected in '${filePath}'`,
                        evidence: snip(node)
                    });
                }
            }

            if (FS_WRITE_SINKS.has(callName)) state.hasWriteCall = true;
            if (NETWORK_SINKS.has(callName) && !NETWORK_SOURCES.has(callName)) {
                state.networkCallCtx.push(`SEND: ${snip(node)}`);
            }
        },
        NewExpression(node: unknown) {
            if (!isNewExpression(node)) return;
            if (isIdentifier(node.callee) && node.callee.name === 'Function') {
                state.hasExecCall = true;
                threats.push({
                    type: 'DYNAMIC_EXECUTION',
                    severity: 'HIGH',
                    riskLevel: 8,
                    message: `'new Function()' detected in '${filePath}'`,
                    evidence: snip(node)
                });
            }
        },
        Literal(node: unknown) {
            if (!isLiteral(node)) return;
            if (typeof node.value !== 'string') return;
            const val = node.value;

            if (SENSITIVE_PATHS.some(p => val.includes(p))) {
                state.hasSensitivePath = true;
                threats.push({
                    type: 'SENSITIVE_PATH_ACCESS',
                    severity: 'HIGH',
                    riskLevel: 7,
                    message: `Sensitive path '${val}' in '${filePath}'`,
                    evidence: val.substring(0, 200)
                });
            }

            if (val.startsWith('http')) {
                const iocResult = threatIntel.checkUrl(val, { isLifecycleScript: false });
                if (iocResult.blocked) {
                    threats.push({
                        type: 'KNOWN_C2_DOMAIN',
                        severity: iocResult.severity,
                        riskLevel: iocResult.severity === 'CRITICAL' ? 10 : 8,
                        message: `URL in '${filePath}' matches known C2: ${iocResult.campaign}`,
                        evidence: val.substring(0, 200)
                    });
                    return;
                }
            }
        }
    });

    if (state.hasNetworkCall && state.hasExecCall) {
        threats.push({
            type: 'NETWORK_TO_EXEC_CHAIN',
            severity: 'CRITICAL',
            riskLevel: 10,
            message: `[CRITICAL] Network-to-Exec chain in '${filePath}'`,
            evidence: `Network: ${state.networkCallCtx.slice(0, 2).join(' | ')}`
        });
    }

    if (state.hasEnvAccess && state.sensitiveEnvVars.length > 0 && state.hasNetworkCall) {
        threats.push({
            type: 'CREDENTIAL_EXFILTRATION',
            severity: 'CRITICAL',
            riskLevel: 10,
            message: `[EXFILTRATION] Reading sensitive env vars and making network calls in '${filePath}'`,
            evidence: `Env vars: [${state.sensitiveEnvVars.join(', ')}]`
        });
    }

    return threats;
}
