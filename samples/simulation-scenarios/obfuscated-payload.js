/**
 * Sentinel Detection Sample: Obfuscated Payloads
 * 
 * DESCRIPTION:
 * Attackers often use obfuscation (Base64, Hex, charCode) to hide malicious
 * strings (like IP addresses or file paths) from simple grep-based scanners.
 * 
 * DETECTION VECTOR:
 * Sentinel's 'AST Inspector' performs static analysis on the code structure.
 * It will flag this for:
 * 1. Excessive use of String.fromCharCode (Entropy detection).
 * 2. Execution of eval() or Function constructor on dynamic strings.
 */

// Obfuscated string for "/etc/passwd" or "C:\\Windows\\System32\\drivers\\etc\\hosts"
// Hex for 'rm -rf /' replacement or similar
const secret = [114, 109, 32, 45, 114, 102, 32, 47].map(c => String.fromCharCode(c)).join('');

console.log("Loading module utilities...");

// Malicious pattern: Building a dynamic command and executing it
try {
    const p = String.fromCharCode(101, 118, 97, 108); // hex for 'eval'
    global[p](`console.log("Simulating execution of: ${secret}")`);
} catch (e) {
    // Sentinel AST catches the "eval" call even if it's renamed or dynamically looked up
}
