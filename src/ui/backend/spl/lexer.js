/**
 * Sentinel Playbook Language — Lexer (v0.1)
 * 
 * Tokenizes .sentinel files into a stream of typed tokens.
 * Tracks line/column for every token to produce useful error messages.
 * 
 * Supports: keywords, identifiers (dotted), strings, numbers, booleans,
 *           operators, symbols, single-line (//) and block comments.
 */

'use strict';

// ─── Token Types ─────────────────────────────────────────────────────────────

const T = Object.freeze({
    KEYWORD:    'KEYWORD',
    IDENTIFIER: 'IDENTIFIER',
    STRING:     'STRING',
    NUMBER:     'NUMBER',
    BOOLEAN:    'BOOLEAN',
    OPERATOR:   'OPERATOR',
    SYMBOL:     'SYMBOL',
    EOF:        'EOF'
});

// ─── Reserved Keywords ───────────────────────────────────────────────────────

const KEYWORDS = new Set([
    'workflow', 'target', 'profile', 'when', 'run',
    'if', 'else', 'allow', 'block', 'sandbox',
    'review', 'notify', 'redact', 'audit',
    'and', 'or', 'not',
    'in', 'contains', 'matches', 'starts_with', 'ends_with',
    'change', 'install', 'from', 'channel', 'mode',
    'then', 'rule', 'path', 'action', 'package',
    'true', 'false'
]);

// ─── Two-character operators ─────────────────────────────────────────────────

const TWO_CHAR_OPS = new Set(['==', '!=', '>=', '<=']);

// ─── Lexer ───────────────────────────────────────────────────────────────────

class LexerError extends Error {
    constructor(message, line, col) {
        super(`LexError line ${line}, col ${col}: ${message}`);
        this.line = line;
        this.col = col;
    }
}

function tokenize(source) {
    const tokens = [];
    let i = 0;
    let line = 1;
    let col = 1;

    function advance(n = 1) {
        for (let k = 0; k < n; k++) {
            if (source[i] === '\n') { line++; col = 1; }
            else { col++; }
            i++;
        }
    }

    function peek(offset = 0) {
        return source[i + offset];
    }

    function push(type, value, startLine, startCol) {
        tokens.push({ type, value, line: startLine, col: startCol });
    }

    while (i < source.length) {
        const ch = source[i];

        // ── Whitespace ───────────────────────────────────────────────────
        if (/\s/.test(ch)) {
            advance();
            continue;
        }

        // ── Single-line comment ──────────────────────────────────────────
        if (ch === '/' && peek(1) === '/') {
            advance(2);
            while (i < source.length && source[i] !== '\n') advance();
            continue;
        }

        // ── Block comment ────────────────────────────────────────────────
        if (ch === '/' && peek(1) === '*') {
            const startLine = line;
            const startCol = col;
            advance(2);
            while (i < source.length) {
                if (source[i] === '*' && peek(1) === '/') {
                    advance(2);
                    break;
                }
                if (i >= source.length - 1) {
                    throw new LexerError('Unterminated block comment', startLine, startCol);
                }
                advance();
            }
            continue;
        }

        // ── Strings ─────────────────────────────────────────────────────
        if (ch === '"') {
            const startLine = line;
            const startCol = col;
            advance(); // opening quote
            let value = '';
            while (i < source.length && source[i] !== '"') {
                if (source[i] === '\\' && peek(1) === '"') {
                    value += '"';
                    advance(2);
                } else {
                    value += source[i];
                    advance();
                }
            }
            if (i >= source.length) {
                throw new LexerError('Unterminated string literal', startLine, startCol);
            }
            advance(); // closing quote
            push(T.STRING, value, startLine, startCol);
            continue;
        }

        // ── Numbers ─────────────────────────────────────────────────────
        if (/\d/.test(ch) || (ch === '.' && /\d/.test(peek(1)))) {
            const startLine = line;
            const startCol = col;
            let num = '';
            while (i < source.length && /[\d.]/.test(source[i])) {
                num += source[i];
                advance();
            }
            push(T.NUMBER, parseFloat(num), startLine, startCol);
            continue;
        }

        // ── Identifiers / Keywords / Booleans ───────────────────────────
        if (/[a-zA-Z_]/.test(ch)) {
            const startLine = line;
            const startCol = col;
            let id = '';
            // Allow dotted identifiers like risk.band, package.name
            while (i < source.length && /[a-zA-Z0-9_.]/.test(source[i])) {
                id += source[i];
                advance();
            }

            if (id === 'true' || id === 'false') {
                push(T.BOOLEAN, id === 'true', startLine, startCol);
            } else if (KEYWORDS.has(id)) {
                push(T.KEYWORD, id, startLine, startCol);
            } else {
                push(T.IDENTIFIER, id, startLine, startCol);
            }
            continue;
        }

        // ── Two-char operators ───────────────────────────────────────────
        if (i + 1 < source.length) {
            const twoChar = ch + source[i + 1];
            if (TWO_CHAR_OPS.has(twoChar)) {
                const startLine = line;
                const startCol = col;
                advance(2);
                push(T.OPERATOR, twoChar, startLine, startCol);
                continue;
            }
        }

        // ── Single-char operators ────────────────────────────────────────
        if ('><'.includes(ch)) {
            const startLine = line;
            const startCol = col;
            advance();
            push(T.OPERATOR, ch, startLine, startCol);
            continue;
        }

        // ── Symbols ─────────────────────────────────────────────────────
        if ('{}[](),='.includes(ch)) {
            const startLine = line;
            const startCol = col;
            advance();
            push(T.SYMBOL, ch, startLine, startCol);
            continue;
        }

        // ── Unknown character ────────────────────────────────────────────
        throw new LexerError(`Unexpected character '${ch}'`, line, col);
    }

    push(T.EOF, null, line, col);
    return tokens;
}

module.exports = { tokenize, TOKEN_TYPES: T, KEYWORDS, LexerError };
