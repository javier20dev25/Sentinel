/**
 * Sentinel: Magic Byte Masquerading Detector
 * 
 * Validates that file content headers match their declared extensions.
 */

'use strict';

const SIGNATURES = {
    '.wasm': [0x00, 0x61, 0x73, 0x6d],
    '.exe': [0x4d, 0x5a],
    '.dll': [0x4d, 0x5a],
    '.so': [0x7f, 0x45, 0x4c, 0x46],
    '.zip': [0x50, 0x4b, 0x03, 0x04],
    '.pdf': [0x25, 0x50, 0x44, 0x46]
};

/**
 * Check if a buffer matches the typical signature of an extension.
 * 
 * @param {Buffer} buffer - File content
 * @param {string} ext - Extension (including dot)
 * @returns {boolean|null} - true if match, false if mismatch, null if unknown extension
 */
function verifySignature(buffer, ext) {
    const signature = SIGNATURES[ext.toLowerCase()];
    if (!signature) return null;

    for (let i = 0; i < signature.length; i++) {
        if (buffer[i] !== signature[i]) return false;
    }
    return true;
}

/**
 * Identify if a file is masquerading (e.g. a .txt that is actually a .wasm).
 * 
 * @param {Buffer} buffer - File content
 * @param {string} declaredExt - Extension as per filename
 * @returns {string|null} - The detected actual extension, or null if no masquerading detected
 */
function detectMasquerading(buffer, declaredExt) {
    if (!buffer || buffer.length < 8) return null;

    for (const [ext, signature] of Object.entries(SIGNATURES)) {
        let match = true;
        for (let i = 0; i < signature.length; i++) {
            if (buffer[i] !== signature[i]) {
                match = false;
                break;
            }
        }
        
        if (match) {
            // Found a matching signature. If it's NOT the declared extension, it's masquerading.
            if (ext !== declaredExt.toLowerCase()) {
                return ext;
            }
            return null; // Legitimate
        }
    }
    
    return null;
}

module.exports = { verifySignature, detectMasquerading };
