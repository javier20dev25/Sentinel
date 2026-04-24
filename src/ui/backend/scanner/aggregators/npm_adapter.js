/**
 * Sentinel: NPM Signal Adapter (v1.2)
 * 
 * Maps external NPM / Dependabot audit reports to Sentinel's 
 * internal signal schema for decision arbitration.
 */

'use strict';

class NpmAdapter {
    /**
     * Maps an npm audit v2 JSON report into Sentinel signals.
     * 
     * @param {Object} report - Parsed JSON from `npm audit --json`
     * @param {string} sourceId - Identifier (default: 'external:npm')
     * @returns {Object[]} Normalized signals
     */
    static mapAudit(report, sourceId = 'external:npm') {
        if (!report || !report.vulnerabilities) return [];

        const signals = [];

        for (const [pkgName, vuln] of Object.entries(report.vulnerabilities)) {
            // Severity mapping to riskLevel (1-10)
            const severityLevels = {
                'critical': 10,
                'high': 8,
                'moderate': 6,
                'low': 3,
                'info': 1
            };

            const riskLevel = severityLevels[vuln.severity] || 5;

            // Context extraction: is it a devDependency?
            const affectsRuntime = vuln.nodes ? vuln.nodes.some(n => !n.startsWith('node_modules/')) : true;

            signals.push({
                ruleName: `External Vulnerability: ${pkgName}`,
                category: 'supply-chain',
                classification: 'POLICY',
                riskLevel,
                severity: vuln.severity.toUpperCase(),
                description: `Vulnerabilidad detectada por auditoría externa en el paquete '${pkgName}'.`,
                explanation: `CVE/Finding reportado externamente. Adjudicado a Sentinel para arbitraje de riesgo.`,
                evidence: `Package: ${pkgName} | Range: ${vuln.range} | Fix: ${vuln.fixAvailable ? 'Available' : 'No patch'}`,
                source: sourceId,
                package: pkgName,
                isDevDependency: !affectsRuntime,
                metadata: {
                    original_id: vuln.via?.[0]?.identifier || 'unknown',
                    fix_available: vuln.fixAvailable
                }
            });
        }

        return signals;
    }
}

module.exports = NpmAdapter;
