/**
 * Sentinel: Entropy and Line Length Detector
 * Detects obfuscated code based on line length and character distribution.
 */

const MAX_LINE_LENGTH = 1000;
const DENSITY_THRESHOLD = 0.20; // 20% of total file size in one line

function detectHighEntropy(content) {
    const totalSize = content.length;
    const alerts = [];
    // Performance Guard: Sparse Sampling vs Top-K
    let chunksToAnalyze = [];
    if (totalSize > 1 * 1024 * 1024) {
        const mid = Math.floor(totalSize / 2);
        chunksToAnalyze = [
            content.substring(0, 8192),
            content.substring(mid, mid + 8192),
            content.substring(totalSize - 8192)
        ];
    } else {
        const lines = content.split('\n');
        chunksToAnalyze = lines
            .map((l, i) => ({ l, i }))
            .sort((a, b) => b.l.length - a.l.length)
            .slice(0, 5)
            .map(item => item.l);
    }

    chunksToAnalyze.forEach((line, index) => {
        const lineSize = line.length;
        if (lineSize < 128) return; // Ignore small noise

        const charMap = {};
        for (const char of line) charMap[char] = (charMap[char] || 0) + 1;
        let entropy = 0;
        for (const char in charMap) {
            const p = charMap[char] / lineSize;
            entropy -= p * Math.log2(p);
        }

        if (entropy > 5.8) {
            alerts.push({
                line: index + 1,
                type: 'ENTROPY_CRITICAL',
                message: `High entropy detected (${entropy.toFixed(2)}). Possible base64 payload / shellcode.`,
                severity: 'CRITICAL',
                _isEarlyExitSignal: true
            });
        }
    });

    return alerts;
}

module.exports = { detectHighEntropy };
