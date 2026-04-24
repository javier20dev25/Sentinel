/**
 * Sentinel Playbook Language — Parser (v0.1)
 * 
 * Recursive descent parser that produces a typed AST from a token stream.
 * All errors include line/col for human-friendly diagnostics.
 * 
 * Grammar summary:
 *   Program    = Workflow+
 *   Workflow   = 'workflow' STRING '{' Statement* '}'
 *   Statement  = Target | Profile | When | Run | If | Action | Rule
 *   Target     = 'target' IDENT (STRING | IDENT)
 *   Profile    = 'profile' IDENT
 *   When       = 'when' Condition Block
 *   Run        = 'run' IDENT [Args]
 *   If         = 'if' Condition Block ['else' (If | Block)]
 *   Action     = 'allow'|'block'|'sandbox'|'review'|'notify'|'redact'|'audit' [extras]
 *   Condition  = OrExpr
 *   OrExpr     = AndExpr ('or' AndExpr)*
 *   AndExpr    = NotExpr ('and' NotExpr)*
 *   NotExpr    = 'not' NotExpr | Comparison
 *   Comparison = Atom (OP Atom)?
 */

'use strict';

const { TOKEN_TYPES: T } = require('./lexer');

// ─── Error Class ─────────────────────────────────────────────────────────────

class ParseError extends Error {
    constructor(message, token) {
        const loc = token ? ` line ${token.line}, col ${token.col}` : '';
        super(`ParseError${loc}: ${message}`);
        this.token = token;
    }
}

// ─── AST Node Constructors ───────────────────────────────────────────────────

const AST = {
    Program:   (workflows)                        => ({ type: 'Program', workflows }),
    Workflow:  (name, body, loc)                   => ({ type: 'Workflow', name, body, loc }),
    Target:    (kind, value, loc)                  => ({ type: 'Target', kind, value, loc }),
    Profile:   (name, loc)                         => ({ type: 'Profile', name, loc }),
    When:      (condition, body, loc)              => ({ type: 'When', condition, body, loc }),
    Run:       (engine, args, loc)                 => ({ type: 'Run', engine, args, loc }),
    If:        (condition, thenBlock, elseBlock, loc) => ({ type: 'If', condition, thenBlock, elseBlock, loc }),
    Action:    (action, params, loc)               => ({ type: 'Action', action, params, loc }),
    Rule:      (name, props, loc)                  => ({ type: 'Rule', name, props, loc }),

    // Conditions
    BinaryOp:  (op, left, right)  => ({ type: 'BinaryOp', op, left, right }),
    UnaryOp:   (op, operand)      => ({ type: 'UnaryOp', op, operand }),
    Comparison:(left, op, right)  => ({ type: 'Comparison', left, op, right }),

    // Leaves
    Identifier: (name)  => ({ type: 'Identifier', name }),
    Literal:    (value) => ({ type: 'Literal', value }),
    List:       (items) => ({ type: 'List', items }),

    // Sugar
    ChangeIn:  (paths)  => ({ type: 'ChangeIn', paths }),
    InstallPkg:()       => ({ type: 'InstallPackage' }),
};

// ─── Operator sets ───────────────────────────────────────────────────────────

const COMPARISON_OPS = new Set(['==', '!=', '>=', '<=', '>', '<']);
const KEYWORD_OPS    = new Set(['in', 'contains', 'matches', 'starts_with', 'ends_with']);
const ACTION_WORDS   = new Set(['allow', 'block', 'sandbox', 'review', 'notify', 'redact', 'audit']);

// ─── Parser ──────────────────────────────────────────────────────────────────

function parse(tokens) {
    let pos = 0;

    // ── Helpers ──────────────────────────────────────────────────────────

    function current() { return tokens[pos]; }
    function peek(offset = 0) { return tokens[pos + offset]; }
    function isEOF() { return current().type === T.EOF; }

    function advance() {
        const tok = tokens[pos];
        pos++;
        return tok;
    }

    function expect(type, value) {
        const tok = current();
        if (tok.type !== type || (value !== undefined && tok.value !== value)) {
            const expected = value !== undefined ? `'${value}'` : type;
            const got = tok.value !== null ? `'${tok.value}'` : 'end of file';
            throw new ParseError(`Expected ${expected}, got ${got}`, tok);
        }
        return advance();
    }

    function match(type, value) {
        const tok = current();
        if (tok.type === type && (value === undefined || tok.value === value)) {
            return advance();
        }
        return null;
    }

    function isKeyword(value) {
        return current().type === T.KEYWORD && current().value === value;
    }

    function loc() {
        const t = current();
        return { line: t.line, col: t.col };
    }

    // ── Program ──────────────────────────────────────────────────────────

    function parseProgram() {
        const workflows = [];
        while (!isEOF()) {
            if (isKeyword('workflow')) {
                workflows.push(parseWorkflow());
            } else {
                throw new ParseError(`Expected 'workflow', got '${current().value}'`, current());
            }
        }
        if (workflows.length === 0) {
            throw new ParseError('File contains no workflow definitions', current());
        }
        return AST.Program(workflows);
    }

    // ── Workflow ─────────────────────────────────────────────────────────

    function parseWorkflow() {
        const l = loc();
        expect(T.KEYWORD, 'workflow');
        const name = expect(T.STRING).value;
        expect(T.SYMBOL, '{');
        const body = [];
        while (!isEOF() && !(current().type === T.SYMBOL && current().value === '}')) {
            body.push(parseStatement());
        }
        expect(T.SYMBOL, '}');
        return AST.Workflow(name, body, l);
    }

    // ── Statement ────────────────────────────────────────────────────────

    function parseStatement() {
        const tok = current();

        if (tok.type === T.KEYWORD) {
            switch (tok.value) {
                case 'target':  return parseTarget();
                case 'profile': return parseProfile();
                case 'when':    return parseWhen();
                case 'run':     return parseRun();
                case 'if':      return parseIf();
                case 'rule':    return parseRule();
                default:
                    if (ACTION_WORDS.has(tok.value)) return parseAction();
            }
        }
        throw new ParseError(`Unexpected token '${tok.value}'`, tok);
    }

    // ── Target ───────────────────────────────────────────────────────────

    function parseTarget() {
        const l = loc();
        expect(T.KEYWORD, 'target');
        const kind = advance().value; // repo, pr, package, file, dir
        // Value is optional for some targets (e.g. "target package")
        let value = null;
        if (current().type === T.STRING) {
            value = advance().value;
        }
        return AST.Target(kind, value, l);
    }

    // ── Profile ──────────────────────────────────────────────────────────

    function parseProfile() {
        const l = loc();
        expect(T.KEYWORD, 'profile');
        const name = advance().value;
        return AST.Profile(name, l);
    }

    // ── When ─────────────────────────────────────────────────────────────

    function parseWhen() {
        const l = loc();
        expect(T.KEYWORD, 'when');

        let condition;

        // Sugar: "when change in [...]"
        if (isKeyword('change')) {
            advance();
            expect(T.KEYWORD, 'in');
            const paths = parseList();
            condition = AST.ChangeIn(paths.items);
        }
        // Sugar: "when install package"
        else if (isKeyword('install')) {
            advance();
            if (isKeyword('package')) advance();
            condition = AST.InstallPkg();
        }
        else {
            condition = parseCondition();
        }

        const body = parseBlock();
        return AST.When(condition, body, l);
    }

    // ── Run ──────────────────────────────────────────────────────────────

    function parseRun() {
        const l = loc();
        expect(T.KEYWORD, 'run');
        const engine = advance().value;
        
        // Optional arguments: mode="oracle" or (mode="oracle")
        const args = {};
        // Inline key=value pairs
        while (current().type === T.IDENTIFIER || current().type === T.KEYWORD) {
            // Check if it's actually a key=value pattern (peek for '=')
            if (peek(1) && peek(1).type === T.SYMBOL && peek(1).value === '=') {
                const key = advance().value;
                expect(T.SYMBOL, '=');
                const val = advance().value;
                args[key] = val;
            } else {
                break;
            }
        }
        return AST.Run(engine, Object.keys(args).length > 0 ? args : null, l);
    }

    // ── If / Else ────────────────────────────────────────────────────────

    function parseIf() {
        const l = loc();
        expect(T.KEYWORD, 'if');
        const condition = parseCondition();
        const thenBlock = parseBlock();

        let elseBlock = null;
        if (match(T.KEYWORD, 'else')) {
            if (isKeyword('if')) {
                // else if → wrap in array
                elseBlock = [parseIf()];
            } else {
                elseBlock = parseBlock();
            }
        }

        return AST.If(condition, thenBlock, elseBlock, l);
    }

    // ── Action ───────────────────────────────────────────────────────────

    function parseAction() {
        const l = loc();
        const action = advance().value;
        const params = {};

        // notify admin channel "slack:#secops"
        // redact evidence, file_paths, lines
        // sandbox verify
        // review from "security-team"
        // audit trace

        if (action === 'notify') {
            if (current().type === T.IDENTIFIER || current().type === T.KEYWORD) {
                params.recipient = advance().value;
            }
            if (match(T.KEYWORD, 'channel')) {
                params.channel = expect(T.STRING).value;
            }
        } else if (action === 'redact') {
            const targets = [advance().value];
            while (match(T.SYMBOL, ',')) {
                targets.push(advance().value);
            }
            params.targets = targets;
        } else if (action === 'sandbox') {
            if (current().type === T.IDENTIFIER || current().type === T.KEYWORD) {
                params.subaction = advance().value;
            }
        } else if (action === 'review') {
            if (match(T.KEYWORD, 'from')) {
                params.from = expect(T.STRING).value;
            }
        } else if (action === 'audit') {
            if (current().type === T.IDENTIFIER || current().type === T.KEYWORD) {
                params.kind = advance().value;
            }
        }

        return AST.Action(action, Object.keys(params).length > 0 ? params : null, l);
    }

    // ── Rule ─────────────────────────────────────────────────────────────

    function parseRule() {
        const l = loc();
        expect(T.KEYWORD, 'rule');
        const name = expect(T.STRING).value;
        expect(T.SYMBOL, '{');
        const props = {};
        while (!(current().type === T.SYMBOL && current().value === '}')) {
            const key = advance().value;
            // Consume optional '=' or just take the next value
            if (current().type === T.SYMBOL && current().value === '=') advance();
            const val = advance().value;
            props[key] = val;
        }
        expect(T.SYMBOL, '}');
        return AST.Rule(name, props, l);
    }

    // ── Block ────────────────────────────────────────────────────────────

    function parseBlock() {
        expect(T.SYMBOL, '{');
        const stmts = [];
        while (!(current().type === T.SYMBOL && current().value === '}') && !isEOF()) {
            stmts.push(parseStatement());
        }
        expect(T.SYMBOL, '}');
        return stmts;
    }

    // ── Conditions (precedence climbing) ─────────────────────────────────

    function parseCondition() {
        return parseOr();
    }

    function parseOr() {
        let left = parseAnd();
        while (match(T.KEYWORD, 'or')) {
            const right = parseAnd();
            left = AST.BinaryOp('or', left, right);
        }
        return left;
    }

    function parseAnd() {
        let left = parseNot();
        while (match(T.KEYWORD, 'and')) {
            const right = parseNot();
            left = AST.BinaryOp('and', left, right);
        }
        return left;
    }

    function parseNot() {
        if (match(T.KEYWORD, 'not')) {
            const operand = parseNot();
            return AST.UnaryOp('not', operand);
        }
        return parseComparison();
    }

    function parseComparison() {
        const left = parseAtom();

        const tok = current();
        // Symbol operators: ==, !=, >=, <=, >, <
        if (tok.type === T.OPERATOR && COMPARISON_OPS.has(tok.value)) {
            const op = advance().value;
            const right = parseAtom();
            return AST.Comparison(left, op, right);
        }
        // Keyword operators: in, contains, matches, starts_with, ends_with
        if (tok.type === T.KEYWORD && KEYWORD_OPS.has(tok.value)) {
            const op = advance().value;
            const right = parseAtom();
            return AST.Comparison(left, op, right);
        }

        // Bare identifier used as a truthy check (e.g., `if package.typosquatting`)
        return left;
    }

    function parseAtom() {
        const tok = current();

        // List: [a, b, c]
        if (tok.type === T.SYMBOL && tok.value === '[') {
            return parseList();
        }
        // String literal
        if (tok.type === T.STRING) {
            advance();
            return AST.Literal(tok.value);
        }
        // Number literal
        if (tok.type === T.NUMBER) {
            advance();
            return AST.Literal(tok.value);
        }
        // Boolean literal
        if (tok.type === T.BOOLEAN) {
            advance();
            return AST.Literal(tok.value);
        }
        // Identifier (including dotted like risk.band) or keyword used as enum (HIGH, CRITICAL)
        if (tok.type === T.IDENTIFIER || tok.type === T.KEYWORD) {
            advance();
            // Uppercase identifiers are treated as enum values (HIGH, CRITICAL, etc.)
            if (/^[A-Z_]+$/.test(tok.value)) {
                return AST.Literal(tok.value);
            }
            return AST.Identifier(tok.value);
        }

        throw new ParseError(`Unexpected token '${tok.value}' in expression`, tok);
    }

    // ── List ─────────────────────────────────────────────────────────────

    function parseList() {
        expect(T.SYMBOL, '[');
        const items = [];
        if (!(current().type === T.SYMBOL && current().value === ']')) {
            items.push(parseAtom());
            while (match(T.SYMBOL, ',')) {
                items.push(parseAtom());
            }
        }
        expect(T.SYMBOL, ']');
        return AST.List(items);
    }

    // ── Entry Point ──────────────────────────────────────────────────────

    return parseProgram();
}

module.exports = { parse, ParseError };
