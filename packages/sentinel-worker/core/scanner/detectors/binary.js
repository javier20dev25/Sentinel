/**
 * Sentinel 3.3: Binary & WASM Asset Inspector
 * 
 * Scans binary files (.wasm, .exe, .dll, .so, .dylib) for:
 *   1. Shannon entropy analysis (packed/encrypted payloads)
 *   2. WASM Import Bridge Profiling (New in 3.3)
 */

'use strict';

const BINARY_EXTENSIONS = new Set(['.wasm', '.exe', '.dll', '.so', '.dylib', '.bin', '.dat']);
const MIN_SCAN_SIZE = 64;
const ENTROPY_THRESHOLD = 7.2;
const KNOWN_SAFE_PRODUCERS = [
    'emscripten', 'rustc', 'assemblyscript', 'Go', 'clang',
    'llvm', 'binaryen', 'wasm-pack', 'webpack'
];

/**
 * Calculate Shannon entropy for a buffer.
 */
function shannonEntropy(buffer) {
    if (!buffer || buffer.length === 0) return 0;
    const freq = new Array(256).fill(0);
    for (let i = 0; i < buffer.length; i++) freq[buffer[i]]++;
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
 */
function extractStrings(buffer, minLen = 6) {
    const strings = [];
    let current = '';
    for (let i = 0; i < buffer.length; i++) {
        const byte = buffer[i];
        if (byte >= 0x20 && byte <= 0x7E) current += String.fromCharCode(byte);
        else {
            if (current.length >= minLen) strings.push(current);
            current = '';
        }
    }
    if (current.length >= minLen) strings.push(current);
    return strings;
}

/**
 * Check if a WASM file has a known safe producer.
 */
function hasKnownProducer(strings) {
    for (const s of strings) {
        for (const producer of KNOWN_SAFE_PRODUCERS) {
            if (s.toLowerCase().includes(producer.toLowerCase())) return producer;
        }
    }
    return null;
}

/**
 * Decode an unsigned LEB128 integer from a buffer at a specific offset.
 * Returns { value, size }.
 */
function decodeUleb128(buffer, offset) {
    let result = 0;
    let shift = 0;
    let i = offset;
    while (true) {
        const byte = buffer[i++];
        result |= (byte & 0x7f) << shift;
        if ((byte & 0x80) === 0) break;
        shift += 7;
    }
    return { value: result, size: i - offset };
}

/**
 * Decode a WASM-style string (length-prefixed) from a buffer.
 */
function decodeWasmString(buffer, offset) {
    const { value: len, size: lenSize } = decodeUleb128(buffer, offset);
    const str = buffer.toString('utf8', offset + lenSize, offset + lenSize + len);
    return { value: str, size: lenSize + len };
}

/**
 * Basic WASM Section Parser.
 * Extracts a map of sectionId -> { offset, size }
 */
function getWasmSections(buffer) {
    const sections = {};
    if (buffer[0] !== 0x00 || buffer[1] !== 0x61 || buffer[2] !== 0x73 || buffer[3] !== 0x6d) return sections;
    
    // Skip magic (4) and version (4)
    let pos = 8;
    while (pos < buffer.length) {
        const id = buffer[pos++];
        const { value: size, size: sizeLen } = decodeUleb128(buffer, pos);
        pos += sizeLen;
        sections[id] = { offset: pos, size };
        pos += size;
    }
    return sections;
}

/**
 * Extract imports from the WASM Import Section (ID 2).
 */
function getWasmImports(buffer, section) {
    const imports = [];
    if (!section) return imports;
    
    let pos = section.offset;
    const { value: count, size: countLen } = decodeUleb128(buffer, pos);
    pos += countLen;
    
    for (let i = 0; i < count; i++) {
        const { value: mod, size: modLen } = decodeWasmString(buffer, pos);
        pos += modLen;
        const { value: field, size: fieldLen } = decodeWasmString(buffer, pos);
        pos += fieldLen;
        
        const kind = buffer[pos++];
        // Skip description bytes based on kind
        if (kind === 0x00) { // function (type index)
            const { size: typeLen } = decodeUleb128(buffer, pos);
            pos += typeLen;
        } else if (kind === 0x01) { // table
            pos += 1; // elem type
            const { size: minLen } = decodeUleb128(buffer, pos);
            pos += minLen;
            if (buffer[pos-1] === 1) { // has max
                const { size: maxLen } = decodeUleb128(buffer, pos);
                pos += maxLen;
            }
        } else if (kind === 0x02) { // memory
            const hasMax = buffer[pos++];
            const { size: minLen } = decodeUleb128(buffer, pos);
            pos += minLen;
            if (hasMax) {
                const { size: maxLen } = decodeUleb128(buffer, pos);
                pos += maxLen;
            }
        } else if (kind === 0x03) { // global
            pos += 2; // type and mutability
        }
        
        imports.push({ module: mod, field });
    }
    return imports;
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

    // 3. WASM-specific: Deep Profiling (Sentinel 3.3)
    if (filename.endsWith('.wasm')) {
        // Valid WASM magic: \0asm (0x00, 0x61, 0x73, 0x6d)
        const sections = getWasmSections(buffer);
        const hasMagic = sections[1] !== undefined || buffer[0] === 0x00;

        if (!hasMagic) {
            alerts.push({
                ruleName: 'Invalid WASM Magic Bytes',
                category: 'binary-analysis',
                riskLevel: 9,
                description: `File '${filename}' does not have valid WASM magic bytes. Potential disguised payload.`,
                evidence: `Magic: ${buffer.subarray(0, 4).toString('hex')}`,
                severity: 'CRITICAL'
            });
        }

        // Deep Import Analysis (Bridge Profiling)
        const imports = getWasmImports(buffer, sections[2]);
        const suspiciousImports = imports.filter(imp => 
            imp.field.includes('exec') || 
            imp.field.includes('eval') || 
            imp.field.includes('spawn') ||
            imp.module === 'wasi_snapshot_preview1' ||
            imp.module === 'env' && (imp.field === 'process' || imp.field === 'fs' || imp.field === 'net')
        );

        if (suspiciousImports.length > 0) {
            alerts.push({
                ruleName: 'Suspicious WASM Bridge Imports',
                category: 'binary-analysis',
                riskLevel: 9,
                severity: 'CRITICAL',
                description: `WASM file '${filename}' imports sensitive system capabilities from the JS host. ` +
                             `This bypasses source code analysis by executing system calls from a binary module.`,
                evidence: `Suspicious Bridge: ${suspiciousImports.map(i => `${i.module}.${i.field}`).join(', ')}`
            });
        }

        const producer = hasKnownProducer(strings);
        if (!producer && strings.length > 3 && !imports.length) {
            alerts.push({
                ruleName: 'WASM Without Known Compiler Signature',
                category: 'binary-analysis',
                riskLevel: 6,
                description: `WASM file '${filename}' does not contain signatures from known compilers (emscripten, rustc, etc.).`,
                evidence: `Extracted ${strings.length} strings, no typical producer section found.`,
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
