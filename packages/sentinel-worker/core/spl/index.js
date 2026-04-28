/**
 * Sentinel Playbook Language — Public Facade (v0.1)
 * 
 * Single entry point for the SPL pipeline:
 *   parse()    → tokenize + parse → AST
 *   compile()  → AST → validated JSON
 *   validate() → parse + compile, return errors/warnings only
 *   execute()  → full pipeline with context
 */

'use strict';

const { tokenize, LexerError }  = require('./lexer');
const { parse, ParseError }     = require('./parser');
const { compile, CompileError } = require('./compiler');
const { execute }               = require('./runtime');
const SPLExplainer              = require('./explainer');
const SPLSimulator              = require('./simulator');

/**
 * Parse a .sentinel source string into an AST.
 * @param {string} source
 * @returns {Object} AST (Program node)
 */
function parseSource(source) {
    const tokens = tokenize(source);
    return parse(tokens);
}

/**
 * Compile a .sentinel source string into executable JSON.
 * @param {string} source
 * @returns {{ compiled: Object, warnings: string[] }}
 */
function compileSource(source) {
    const ast = parseSource(source);
    return compile(ast);
}

/**
 * Validate a .sentinel source string (parse + compile, report issues).
 * @param {string} source
 * @returns {{ valid: boolean, errors: string[], warnings: string[] }}
 */
function validate(source) {
    const errors = [];
    const warnings = [];

    try {
        const { warnings: compileWarnings } = compileSource(source);
        warnings.push(...compileWarnings);
    } catch (e) {
        errors.push(e.message);
    }

    return { valid: errors.length === 0, errors, warnings };
}

/**
 * Full pipeline: parse → compile → execute against a context.
 * @param {string} source  - .sentinel file contents
 * @param {Object} context - Runtime context (repo, user, event, risk, etc.)
 * @returns {{ results: Array, context: Object, warnings: string[] }}
 */
async function run(source, context = {}) {
    const { compiled, warnings } = compileSource(source);
    const { results, context: updatedContext } = await execute(compiled, context);
    return { results, context: updatedContext, warnings };
}

/**
 * Generate a human-readable explanation of an execution result.
 * @param {Object} executionResult - Result from run() or execute()
 * @param {Object} [options] - Formatting options
 * @returns {string}
 */
function explain(executionResult, options) {
    return SPLExplainer.explain(executionResult, options);
}

/**
 * Simulate the impact of a playbook.
 * @param {string} source - .sentinel source code
 * @param {Object} context - Runtime context
 * @returns {Object} Impact report data
 */
function simulate(source, context) {
    return SPLSimulator.simulate(source, context);
}

/**
 * Format a simulation result into a human-readable report.
 * @param {Object} impact - Result from simulate()
 * @returns {string}
 */
function formatSimulation(impact) {
    return SPLSimulator.formatImpactReport(impact);
}

module.exports = {
    parse: parseSource,
    compile: compileSource,
    validate,
    run,
    execute,
    explain,
    simulate,
    formatSimulation,
    // Re-export errors for external catch
    LexerError,
    ParseError,
    CompileError
};
