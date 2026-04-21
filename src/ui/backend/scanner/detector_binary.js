/**
 * Sentinel 3.2: Binary & WASM Asset Inspector
 *
 * Scans binary files (.wasm, .exe, .dll, .so, .dylib) for:
 *   1. Embedded URLs / IP addresses (C2 beacons)
 *   2. Suspicious plaintext strings (shell commands, credential paths)
 *   3. Shannon entropy analysis (packed/encrypted payloads)
 *   4. Known magic bytes validation
 *
 * SECURITY: This module reads files as raw buffers. It never executes them.
 */

'use strict';

// Extensions that should trigger binary inspection
const BINARY_EXTENSIONS = new Set(['.wasm', '.exe', '.dll', '.so', '.dylib', '.bin', '.dat']);

// Minimum file size to bother scanning (skip tiny stubs)
const MIN_SCAN_SIZE = 64;

// Entropy threshold: packed/encrypted data typically scores > 7.0 on a 0-8 scale
const ENTROPY_THRESHOLD = 7.2;

// Known safe WASM producers (partial match on producer section strings)
const KNOWN_SAFE_PRODUCERS = [
    'emscripten', 'rustc', 'assemblyscript', 'Go', 'clang',
    'llvm', 'binaryen', 'wasm-pack', 'webpack'
];

/**
 * Calculate Shannon entropy for a buffer.
 * Returns a value between 0 (uniform) and 8 (perfectly random/encrypted).
 */
function shannonEntropy(buffer) {
    if (!buffer || buffer.length === 0) return 0;

    const freq = new Array(256).fill(0);
    for (let i = 0; i < buffer.length; i++) {
        freq[buffer[i]]++;
    }

    let entropy = 0;
    const len = buffer.length;
    for (let i = 0; i < 256; i++) {
        if (freq[i] === 0) continue;
        const p = freq[i] / len;
        entropy -= p * Math.log2(p);
    }

    return entropy;
}

/**
 * Extract printable ASCII strings from a binary buffer.
 * Returns an array of strings with minimum length of `minLen`.
 */
function extractStrings(buffer, minLen = 6) {
    const strings = [];
    let current = '';

    for (let i = 0; i < buffer.length; i++) {
        const byte = buffer[i];
        // Printable ASCII range
        if (byte >= 0x20 && byte <= 0x7E) {
            current += String.fromCharCode(byte);
        } else {
            if (current.length >= minLen) {
                strings.push(current);
            }
            current = '';
        }
    }
    if (current.length >= minLen) {
        strings.push(current);
    }

    return strings;
}

/**
 * Check if a WASM file has a known safe producer in its custom sections.
 */
function hasKnownProducer(strings) {
    for (const s of strings) {
        for (const producer of KNOWN_SAFE_PRODUCERS) {
            if (s.toLowerCase().includes(producer.toLowerCase())) {
                return producer;
            }
        }
    }
    return null;
}

/**
 * Main analysis function for binary assets.
 *
 * @param {Buffer} buffer   - Raw file content as a Buffer
 * @param {string} filename - Filename for context in alerts
 * @returns {Array}         - List of threat alerts
 */
function analyzeBinary(buffer, filename) {
    const alerts = [];

    if (!buffer || buffer.length < MIN_SCAN_SIZE) return alerts;

    // 1. Shannon entropy analysis
    const entropy = shannonEntropy(buffer);
    if (entropy > ENTROPY_THRESHOLD) {
        const producer = hasKnownProducer(extractStrings(buffer, 4));
        if (!producer) {
            alerts.push({
                ruleName: 'High-Entropy Binary Payload',
                category: 'binary-analysis',
                riskLevel: 7,
                description: `Binary asset '${filename}' has unusually high entropy (${entropy.toFixed(2)}/8.0), ` +
                    `suggesting packed, encrypted, or obfuscated content. No known compiler signature found.`,
                evidence: `Entropy: ${entropy.toFixed(4)} / 8.0 | Size: ${buffer.length} bytes`,
                severity: 'HIGH'
            });
        }
    }

    // 2. Extract and analyze embedded strings
    const strings = extractStrings(buffer, 6);

    // 2a. URL / IP detection
    const urlPatterns = [
        /https?:\/\/[^\s"'<>]{8,}/gi,
        /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/g,
        /[a-z0-9][-a-z0-9]*\.(com|net|org|io|xyz|ru|cn|tk|ml|ga|cf|top|pw|cc|ws)\b/gi
    ];

    const safeUrlPatterns = [
        /npmjs\.org/i, /github\.com/i, /nodejs\.org/i,
        /mozilla\.org/i, /w3\.org/i, /ietf\.org/i,
        /googleapis\.com/i, /cloudflare\.com/i
    ];

    for (const str of strings) {
        for (const pattern of urlPatterns) {
            pattern.lastIndex = 0;
            const matches = str.match(pattern);
            if (matches) {
                for (const url of matches) {
                    const isSafe = safeUrlPatterns.some(sp => sp.test(url));
                    if (!isSafe) {
                        alerts.push({
                            ruleName: 'Embedded URL in Binary Asset',
                            category: 'binary-analysis',
                            riskLevel: 9,
                            description: `Binary file '${filename}' contains an embedded network address. ` +
                                `This is a strong indicator of a Command & Control (C2) beacon or data exfiltration endpoint.`,
                            evidence: `URL: ${url.substring(0, 200)}`,
                            severity: 'CRITICAL'
                        });
                    }
                }
            }
        }
    }

    // 2b. Suspicious command strings inside binaries
    const suspiciousCommands = [
        /(?:\/bin\/sh|\/bin\/bash|cmd\.exe|powershell)/i,
        /(?:curl|wget|nc|ncat)\s/i,
        /(?:id_rsa|\.ssh|\.env|passwd|shadow)/i,
        /(?:eval|exec|spawn|system)\s*\(/i,
        /(?:DROP\s+TABLE|SELECT\s+\*|UNION\s+SELECT)/i
    ];

    for (const str of strings) {
        for (const cmdPattern of suspiciousCommands) {
            if (cmdPattern.test(str)) {
                alerts.push({
                    ruleName: 'Suspicious Command String in Binary',
                    category: 'binary-analysis',
                    riskLevel: 8,
                    description: `Binary file '${filename}' contains shell/system command strings that should not be present in legitimate assets.`,
                    evidence: `String: "${str.substring(0, 200)}"`,
                    severity: 'HIGH'
                });
                break; // One alert per string is enough
            }
        }
    }

    // 3. WASM-specific: Validate magic bytes
    if (filename.endsWith('.wasm')) {
        // Valid WASM magic: \0asm (0x00, 0x61, 0x73, 0x6d)
        const validMagic = buffer[0] === 0x00 && buffer[1] === 0x61 &&
                           buffer[2] === 0x73 && buffer[3] === 0x6d;

        if (!validMagic) {
            alerts.push({
                ruleName: 'Invalid WASM Magic Bytes',
                category: 'binary-analysis',
                riskLevel: 9,
                description: `File '${filename}' has .wasm extension but does not begin with valid WebAssembly magic bytes (\\0asm). ` +
                    `This file may be a disguised payload using a .wasm extension to evade source-code scanners.`,
                evidence: `First 4 bytes: 0x${buffer[0].toString(16)} 0x${buffer[1].toString(16)} 0x${buffer[2].toString(16)} 0x${buffer[3].toString(16)}`,
                severity: 'CRITICAL'
            });
        }

        const producer = hasKnownProducer(strings);
        if (!producer && strings.length > 3) {
            alerts.push({
                ruleName: 'WASM Without Known Compiler Signature',
                category: 'binary-analysis',
                riskLevel: 6,
                description: `WASM file '${filename}' does not contain signatures from known compilers (emscripten, rustc, etc.). ` +
                    `Custom or hand-crafted WASM files are unusual and warrant manual review.`,
                evidence: `Extracted ${strings.length} strings, none matched known producers.`,
                severity: 'MEDIUM'
            });
        }
    }

    return alerts;
}

/**
 * Check if a filename should be scanned as a binary asset.
 */
function isBinaryAsset(filename) {
    const ext = (filename.lastIndexOf('.') !== -1)
        ? filename.substring(filename.lastIndexOf('.')).toLowerCase()
        : '';
    return BINARY_EXTENSIONS.has(ext);
}

module.exports = { analyzeBinary, isBinaryAsset, shannonEntropy, extractStrings };
