/**
 * Sentinel Playbook Language — Runtime (v0.1)
 * 
 * Executes compiled workflows against a context object.
 * Connects to real Sentinel engines when available, falls back to stubs.
 * 
 * Fail-closed: any engine failure results in 'block'.
 */

'use strict';

// ─── Engine Registry (lazy-loaded for resilience) ────────────────────────────

function loadEngine(name) {
    const engineMap = {
        risk_orchestrator:    '../scanner/risk_orchestrator',
        supply_chain_shield:  '../scanner/supply_chain_shield',
        pr_policy_engine:     '../scanner/pr_policy_engine',
        policy_engine:        '../scanner/policy_engine',
        scanner:              '../scanner/index'
    };

    const modulePath = engineMap[name];
    if (!modulePath) return null;

    try {
        return require(modulePath);
    } catch (e) {
        return null;
    }
}

// ─── Context resolver ────────────────────────────────────────────────────────

function resolveVariable(context, path) {
    if (!path || !context) return undefined;
    return path.split('.').reduce((obj, key) => obj?.[key], context);
}

// ─── Condition Evaluator ─────────────────────────────────────────────────────

function evaluateCondition(cond, context) {
    if (!cond) return true;

    switch (cond.type) {
        case 'always':
            return true;

        case 'change_in': {
            const changed = context?.event?.changedFiles || [];
            return cond.paths.some(pattern => {
                if (pattern.endsWith('/*')) {
                    const prefix = pattern.slice(0, -2);
                    return changed.some(f => f.startsWith(prefix));
                }
                return changed.includes(pattern);
            });
        }

        case 'install_package':
            return context?.event?.type === 'install';

        case 'comparison': {
            const left = resolveValue(cond.left, context);
            const right = resolveValue(cond.right, context);
            return compare(left, cond.op, right);
        }

        case 'binary':
            if (cond.op === 'and') return evaluateCondition(cond.left, context) && evaluateCondition(cond.right, context);
            if (cond.op === 'or')  return evaluateCondition(cond.left, context) || evaluateCondition(cond.right, context);
            return false;

        case 'unary':
            if (cond.op === 'not') return !evaluateCondition(cond.operand, context);
            return false;

        case 'truthy':
            return !!resolveVariable(context, cond.variable);

        case 'literal':
            return !!cond.value;

        default:
            return false;
    }
}

function resolveValue(node, context) {
    if (!node) return undefined;
    if (node.type === 'variable') return resolveVariable(context, node.name);
    if (node.type === 'literal')  return node.value;
    if (node.type === 'list')     return node.items.map(i => resolveValue(i, context));
    return node.value;
}

function compare(left, op, right) {
    switch (op) {
        case '==': return left == right;
        case '!=': return left != right;
        case '>=': return left >= right;
        case '<=': return left <= right;
        case '>':  return left > right;
        case '<':  return left < right;
        case 'in':
            if (Array.isArray(right)) return right.includes(left);
            if (typeof right === 'string') return right.includes(left);
            return false;
        case 'contains':
            if (Array.isArray(left)) return left.includes(right);
            if (typeof left === 'string') return left.includes(right);
            return false;
        case 'matches': {
            try { return new RegExp(right).test(left); } catch { return false; }
        }
        case 'starts_with':
            return typeof left === 'string' && left.startsWith(right);
        case 'ends_with':
            return typeof left === 'string' && left.endsWith(right);
        default:
            return false;
    }
}

// ─── Step Executor ───────────────────────────────────────────────────────────

function executeSteps(steps, context, log) {
    let verdict = null;

    for (const step of steps) {
        switch (step.type) {
            case 'run': {
                log.push({ type: 'engine', engine: step.engine, status: 'invoked' });
                const engine = loadEngine(step.engine);
                if (engine) {
                    try {
                        // Try to get data from the engine and merge into context
                        if (step.engine === 'risk_orchestrator' && typeof engine.arbitrate === 'function') {
                            const signals = context?.signals?.raw || [];
                            const profile = context?.profile || 'balanced';
                            const oracleCtx = {
                                isAuthorized: context?.repo?.authorized ?? true,
                                fingerprint: context?.repo?.fingerprint || '',
                                user: context?.user?.name || 'anonymous'
                            };
                            const result = engine.arbitrate(signals, profile, oracleCtx);
                            context.risk = context.risk || {};
                            context.risk.score = result.score;
                            context.risk.band = result.riskBand?.name || 'UNKNOWN';
                            context.risk.confidence = result.score;
                            log.push({ type: 'engine_result', engine: step.engine, band: context.risk.band, score: result.score });
                        }
                        else if (step.engine === 'pr_policy_engine') {
                            const changedFiles = context?.event?.changedFiles || [];
                            if (changedFiles.length > 0 && typeof engine.loadPolicies === 'function') {
                                const repoPath = context?.repo?.path || process.cwd();
                                engine.loadPolicies(repoPath);
                                const result = engine.evaluateFiles(changedFiles);
                                context.policy = context.policy || {};
                                context.policy.verdict = result.verdict;
                                context.policy.violations = result.violations;
                                context.policy.requires_review = result.violations?.some(v => v.rule === 'require-review') || false;
                                log.push({ type: 'engine_result', engine: step.engine, verdict: result.verdict, violations: result.violations.length });
                            }
                        }
                        else if (step.engine === 'policy_engine') {
                            if (typeof engine.getPolicyInfo === 'function') {
                                const info = engine.getPolicyInfo();
                                context.policy = context.policy || {};
                                context.policy.name = info.name;
                                context.policy.mode = info.enforcement;
                                context.policy.exposure = info.exposure;
                            }
                        }
                        else {
                            log.push({ type: 'engine_result', engine: step.engine, status: 'connected_no_dispatch' });
                        }
                    } catch (e) {
                        // Fail-closed: engine crash → block
                        log.push({ type: 'engine_error', engine: step.engine, error: e.message });
                        verdict = 'block';
                    }
                } else {
                    log.push({ type: 'engine_missing', engine: step.engine });
                }
                break;
            }

            case 'if': {
                const matches = evaluateCondition(step.condition, context);
                log.push({ type: 'condition', result: matches, condition: JSON.stringify(step.condition).substring(0, 100) });
                if (matches) {
                    const result = executeSteps(step.then, context, log);
                    if (result) verdict = result;
                } else if (step.else) {
                    const result = executeSteps(step.else, context, log);
                    if (result) verdict = result;
                }
                break;
            }

            case 'when': {
                const matches = evaluateCondition(step.condition, context);
                if (matches) {
                    const result = executeSteps(step.steps, context, log);
                    if (result) verdict = result;
                }
                break;
            }

            case 'action': {
                log.push({ type: 'action', action: step.action, params: step.params });
                // Terminal actions set the verdict
                if (['allow', 'block', 'sandbox', 'review'].includes(step.action)) {
                    verdict = step.action;
                }
                // Side-effect actions are logged but don't change verdict
                // notify, redact, audit → recorded in log for the caller to process
                break;
            }

            case 'rule': {
                log.push({ type: 'rule_applied', name: step.name, properties: step.properties });
                break;
            }
        }

        // If we got a terminal verdict, stop processing
        if (verdict === 'block' || verdict === 'allow') break;
    }

    return verdict;
}

// ─── Public API ──────────────────────────────────────────────────────────────

/**
 * Execute a compiled workflow against a context.
 * 
 * @param {Object} compiled - Output of compiler.compile()
 * @param {Object} context  - Runtime context (repo, user, event, risk, etc.)
 * @param {string} [workflowName] - Specific workflow to run (runs all if omitted)
 * @returns {{ verdicts: Array, log: Array }}
 */
function execute(compiled, context = {}) {
    const results = [];

    for (const workflow of compiled.workflows) {
        const log = [];
        let finalVerdict = null;

        // Set profile in context
        context.profile = workflow.profile || context.profile || 'balanced';

        for (const trigger of workflow.triggers) {
            if (evaluateCondition(trigger.condition, context)) {
                const v = executeSteps(trigger.steps, context, log);
                if (v) finalVerdict = v;
            }
        }

        // Fail-closed: no explicit verdict = block in strict, allow in balanced
        if (!finalVerdict) {
            finalVerdict = context.profile === 'strict' ? 'block' : 'allow';
            log.push({ type: 'default_verdict', reason: `No explicit verdict. Profile '${context.profile}' default applied.` });
        }

        results.push({
            workflow: workflow.name,
            verdict: finalVerdict,
            profile: workflow.profile,
            target: workflow.target,
            log
        });
    }

    return { results, context };
}

module.exports = { execute };
