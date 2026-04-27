/**
 * Sentinel: Decision Explainer (v2.0 — Oracle Hardened)
 * 
 * Translates mathematical risk scores into human-readable, tactical rationale
 * for developers and security teams. Adapts output based on authorization.
 */

'use strict';

class DecisionExplainer {
    /**
     * Generates a tactical summary of a decision.
     * 
     * @param {Object} results - Full results object from finalizeVerdict
     * @returns {string} Human-readable summary
     */
    static explain(results) {
        if (!results || !results.rationale) return 'No rationale provided';

        const { rationale, riskScore, riskBand, decisionConfidence, isAuthorized } = results;
        const { reason, topContributor, counterfactual, contributors } = rationale;
        
        let text = `Veredicto: ${reason}\n`;
        
        // Risk Band (tactical)
        if (riskBand) {
            text += `Risk Band: ${riskBand.name} [${riskBand.priority}] — ${riskBand.label}\n`;
            text += `Recommended Action: ${riskBand.action}\n`;
        }

        if (topContributor) {
            const impact = Math.round((riskScore || 0) * 100);
            text += `Riesgo Acumulado: ${impact}%\n`;
            
            if (decisionConfidence) {
                text += `Decision Confidence: ${Math.round(decisionConfidence * 100)}%\n`;
            }

            const name = topContributor.ruleName || topContributor.rule_id || '[REDACTED]';
            const source = topContributor.source || 'unknown';
            text += `Principal Contribuyente: ${name} (${source})\n`;
        }

        // Counterfactual & ROI (only for authorized users)
        if (isAuthorized !== false && counterfactual && counterfactual.delta > 0.05) {
            const reduction = Math.round(counterfactual.delta * 100);
            const scoreWithoutTop = Math.round(counterfactual.withoutTop * 100);
            const roi = (counterfactual.delta / (riskScore || 1)).toFixed(2);
            
            text += `Potencial de Mitigacion: Si corriges el hallazgo principal, el riesgo bajaria un ${reduction}% (Score Final: ${scoreWithoutTop}%).\n`;
            text += `Mitigation ROI: ${roi} (Eficiencia de reduccion de riesgo prioritaria).\n`;
        }

        // Contributors breakdown (redacted for unauthorized)
        if (contributors && contributors.length > 1) {
            text += `\nDesglose de pesos:\n`;
            contributors.forEach(c => {
                if (isAuthorized !== false) {
                    const p = Math.round((c.risk || 0) * 100);
                    text += ` - [${c.source}] ${c.file || 'global'}: ~${p}% impacto relativo\n`;
                } else {
                    text += ` - [${c.source}] [REDACTED]: impacto no disponible\n`;
                }
            });
        }

        // Oracle mode warning
        if (isAuthorized === false) {
            text += `\n[ORACLE MODE] Resultados limitados. Autorizacion requerida para inteligencia completa.\n`;
        }

        return text;
    }

    /**
     * Formats the final console banner for the decision.
     */
    static formatBanner(verdict, profile) {
        const border = '='.repeat(60);
        return `
${border}
 SENTINEL DECISION ENGINE (Profile: ${profile.toUpperCase()})
 VERDICT: ${verdict.toUpperCase()}
${border}
`;
    }
}

module.exports = DecisionExplainer;
