/**
 * Sentinel Playbook Language — Compiler (v0.1)
 * 
 * Compiles a parsed AST into a validated, executable JSON representation.
 * Validates engine names, context variables, and action parameters.
 */

'use strict';

const SCHEMA_VERSION = '1.0';

// ─── Known engines that the runtime can dispatch to ──────────────────────────

const KNOWN_ENGINES = new Set([
    'risk_orchestrator',
    'supply_chain_shield',
    'pr_policy_engine',
    'policy_engine',
    'trust_engine',
    'risk_graph_enrichment',
    'decision_explainer',
    'ci_sandbox',
    'scanner'
]);

// ─── Known context variable prefixes ─────────────────────────────────────────

const KNOWN_PREFIXES = new Set([
    'repo', 'user', 'event', 'policy', 'risk',
    'signal', 'signals', 'package', 'install'
]);

// ─── Compiler ────────────────────────────────────────────────────────────────

class CompileError extends Error {
    constructor(message, node) {
        const loc = node?.loc ? ` (line ${node.loc.line})` : '';
        super(`CompileError${loc}: ${message}`);
        this.node = node;
    }
}

function compile(ast) {
    const warnings = [];

    function warn(msg, node) {
        const loc = node?.loc ? ` (line ${node.loc.line})` : '';
        warnings.push(`Warning${loc}: ${msg}`);
    }

    function compileWorkflow(wf) {
        const result = {
            name: wf.name,
            target: null,
            profile: 'balanced',
            triggers: [],
            rules: []
        };

        // Separate top-level directives from trigger blocks
        const topLevel = [];
        const blocks = [];

        for (const stmt of wf.body) {
            if (stmt.type === 'Target') {
                result.target = { kind: stmt.kind, value: stmt.value };
            } else if (stmt.type === 'Profile') {
                result.profile = stmt.name;
            } else if (stmt.type === 'When') {
                blocks.push(stmt);
            } else if (stmt.type === 'Rule') {
                result.rules.push(compileRule(stmt));
            } else {
                topLevel.push(stmt);
            }
        }

        // Compile trigger blocks (when ... { ... })
        for (const when of blocks) {
            result.triggers.push({
                condition: compileCondition(when.condition),
                steps: compileBlock(when.body)
            });
        }

        // Any top-level statements outside of when blocks become a default trigger
        if (topLevel.length > 0) {
            result.triggers.push({
                condition: { type: 'always' },
                steps: compileBlock(topLevel)
            });
        }

        if (!result.target) {
            warn(`Workflow '${wf.name}' has no target statement`, wf);
        }

        return result;
    }

    function compileBlock(stmts) {
        const steps = [];
        for (const stmt of stmts) {
            steps.push(compileStatement(stmt));
        }
        return steps;
    }

    function compileStatement(stmt) {
        switch (stmt.type) {
            case 'Run':
                if (!KNOWN_ENGINES.has(stmt.engine)) {
                    warn(`Unknown engine '${stmt.engine}'. Known: ${[...KNOWN_ENGINES].join(', ')}`, stmt);
                }
                return { type: 'run', engine: stmt.engine, args: stmt.args || {} };

            case 'If':
                return {
                    type: 'if',
                    condition: compileCondition(stmt.condition),
                    then: compileBlock(stmt.thenBlock),
                    else: stmt.elseBlock ? compileBlock(stmt.elseBlock) : null
                };

            case 'Action':
                return { type: 'action', action: stmt.action, params: stmt.params || {} };

            case 'When':
                return {
                    type: 'when',
                    condition: compileCondition(stmt.condition),
                    steps: compileBlock(stmt.body)
                };

            case 'Rule':
                return { type: 'rule', ...compileRule(stmt) };

            default:
                warn(`Unexpected statement type '${stmt.type}' in block`, stmt);
                return { type: 'noop' };
        }
    }

    function compileCondition(cond) {
        if (!cond) return { type: 'always' };

        switch (cond.type) {
            case 'ChangeIn':
                return {
                    type: 'change_in',
                    paths: cond.paths.map(p => p.value !== undefined ? p.value : p)
                };

            case 'InstallPackage':
                return { type: 'install_package' };

            case 'BinaryOp':
                return {
                    type: 'binary',
                    op: cond.op,
                    left: compileCondition(cond.left),
                    right: compileCondition(cond.right)
                };

            case 'UnaryOp':
                return {
                    type: 'unary',
                    op: cond.op,
                    operand: compileCondition(cond.operand)
                };

            case 'Comparison':
                return {
                    type: 'comparison',
                    left: compileValue(cond.left),
                    op: cond.op,
                    right: compileValue(cond.right)
                };

            case 'Identifier':
                // Bare identifier used as truthy check
                validateContextVar(cond.name, cond);
                return { type: 'truthy', variable: cond.name };

            case 'Literal':
                return { type: 'literal', value: cond.value };

            default:
                return { type: 'unknown', raw: cond };
        }
    }

    function compileValue(node) {
        if (node.type === 'Identifier') {
            validateContextVar(node.name, node);
            return { type: 'variable', name: node.name };
        }
        if (node.type === 'Literal') {
            return { type: 'literal', value: node.value };
        }
        if (node.type === 'List') {
            return { type: 'list', items: node.items.map(compileValue) };
        }
        return { type: 'raw', value: node };
    }

    function compileRule(rule) {
        return { name: rule.name, properties: rule.props };
    }

    function validateContextVar(name, node) {
        if (!name) return;
        const prefix = name.split('.')[0];
        if (!KNOWN_PREFIXES.has(prefix) && !/^[A-Z_]+$/.test(name)) {
            warn(`Unknown context variable '${name}'`, node);
        }
    }

    // ── Main ─────────────────────────────────────────────────────────────

    if (ast.type !== 'Program') {
        throw new CompileError('Expected a Program node at root', ast);
    }

    const compiled = {
        schema_version: SCHEMA_VERSION,
        compiled_at: new Date().toISOString(),
        workflows: ast.workflows.map(compileWorkflow)
    };

    return { compiled, warnings };
}

module.exports = { compile, CompileError, KNOWN_ENGINES, SCHEMA_VERSION };
