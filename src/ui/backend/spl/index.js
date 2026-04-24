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
function run(source, context = {}) {
    const { compiled, warnings } = compileSource(source);
    const { results, context: updatedContext } = execute(compiled, context);
    return { results, context: updatedContext, warnings };
}

module.exports = {
    parse: parseSource,
    compile: compileSource,
    validate,
    run,
    execute,
    // Re-export errors for external catch
    LexerError,
    ParseError,
    CompileError
};
