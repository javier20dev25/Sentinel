/**
 * Sentinel: Lifecycle Script Filter
 * Analyzes package.json for dangerous pre/postinstall scripts.
 */

const DANGEROUS_COMMANDS = ['curl', 'wget', 'eval', 'sh', 'bash', 'node -e', 'fetch'];
const SENSITIVE_SCRIPTS = ['preinstall', 'postinstall', 'prepublish', 'postpublish', 'preprepare', 'prepare'];

function analyzeLifecycleScripts(packageJsonContent) {
    let pkg;
    try {
        pkg = JSON.parse(packageJsonContent);
    } catch (e) {
        return [{ type: 'JSON_ERROR', message: 'Invalid package.json format.', severity: 'CRITICAL' }];
    }

    const scripts = pkg.scripts || {};
    const alerts = [];

    SENSITIVE_SCRIPTS.forEach(scriptName => {
        if (scripts[scriptName]) {
            const command = scripts[scriptName].toLowerCase();
            const foundDangerous = DANGEROUS_COMMANDS.filter(cmd => command.includes(cmd));

            if (foundDangerous.length > 0) {
                alerts.push({
                    script: scriptName,
                    type: 'DANGEROUS_LIFECYCLE_SCRIPT',
                    message: `Script '${scriptName}' uses dangerous commands: ${foundDangerous.join(', ')}`,
                    severity: 'CRITICAL'
                });
            } else {
                alerts.push({
                    script: scriptName,
                    type: 'SUSPICIOUS_LIFECYCLE_SCRIPT',
                    message: `Suspicious lifecycle script '${scriptName}' detected. Review its purpose.`,
                    severity: 'WARNING'
                });
            }
        }
    });

    return alerts;
}

module.exports = { analyzeLifecycleScripts };
