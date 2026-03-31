/**
 * Sentinel: Invisible Unicode Detector
 * Detects zero-width and non-printable characters used to hide malware.
 */

const INVISIBLE_UNICODE_REGEX = /[\u200B-\u200D\uFEFF]/g;
const CONSECUTIVE_THRESHOLD = 5;

function detectInvisibleChars(content) {
    const lines = content.split('\n');
    const alerts = [];

    lines.forEach((line, index) => {
        const matches = line.match(INVISIBLE_UNICODE_REGEX);
        if (matches) {
            // Check for consecutive characters
            const consecutivePattern = new RegExp(`[\\u200B-\\u200D\\uFEFF]{${CONSECUTIVE_THRESHOLD},}`, 'g');
            if (consecutivePattern.test(line)) {
                alerts.push({
                    line: index + 1,
                    type: 'INVISIBLE_UNICODE_CRITICAL',
                    message: `Detected more than ${CONSECUTIVE_THRESHOLD} consecutive invisible characters.`,
                    severity: 'CRITICAL'
                });
            } else {
                alerts.push({
                    line: index + 1,
                    type: 'INVISIBLE_UNICODE_WARNING',
                    message: `Detected ${matches.length} invisible characters.`,
                    severity: 'WARNING'
                });
            }
        }
    });

    return alerts;
}

module.exports = { detectInvisibleChars };
