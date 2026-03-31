/**
 * Sentinel: Entropy and Line Length Detector
 * Detects obfuscated code based on line length and character distribution.
 */

const MAX_LINE_LENGTH = 1000;
const DENSITY_THRESHOLD = 0.20; // 20% of total file size in one line

function detectHighEntropy(content) {
    const lines = content.split('\n');
    const totalSize = content.length;
    const alerts = [];

    lines.forEach((line, index) => {
        const lineSize = line.length;
        
        if (lineSize > MAX_LINE_LENGTH) {
            alerts.push({
                line: index + 1,
                type: 'OBFUSCATION_WARNING',
                message: `Line too long (${lineSize} chars). Possible minified/obfuscated code.`,
                severity: 'WARNING'
            });
        }

        if (totalSize > 0 && (lineSize / totalSize) > DENSITY_THRESHOLD && totalSize > 5000) {
            alerts.push({
                line: index + 1,
                type: 'OBFUSCATION_CRITICAL',
                message: `Line represents ${( (lineSize / totalSize) * 100).toFixed(2)}% of total file size.`,
                severity: 'CRITICAL'
            });
        }
    });

    return alerts;
}

module.exports = { detectHighEntropy };
