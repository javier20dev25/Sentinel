/**
 * Sentinel Playbook — Strategic Explainer (v0.1)
 * 
 * Translates SPL execution logs into human-readable tactical justifications.
 * Focuses on "The Why" to build trust with developers and security teams.
 */

'use strict';

class SPLExplainer {
    /**
     * Explains the results of a playbook execution.
     * 
     * @param {Object} executionResult - Result from runtime.execute()
     * @param {Object} [options] - Formatting options { markdown: boolean }
     * @returns {string} Human-readable explanation
     */
    static explain(executionResult, options = {}) {
        if (!executionResult || !executionResult.results) return 'No execution data available.';

        const isMD = !!options.markdown;
        let explanation = '';

        for (const res of executionResult.results) {
            explanation += this._formatWorkflowHeader(res, isMD);
            explanation += this._explainTrigger(res.log, res.target, isMD);
            explanation += this._explainEvidence(res.log, isMD);
            explanation += this._explainLogic(res.log, isMD);
            explanation += this._formatFooter(res.verdict, res.profile, isMD);
            explanation += '\n';
        }

        return explanation;
    }

    static _formatWorkflowHeader(res, isMD) {
        if (isMD) {
            return `## 🛡️ Workflow: ${res.workflow}\n\n`;
        }
        const border = '─'.repeat(50);
        return `\n┌${border}┐\n` +
               `│ WORKFLOW: ${res.workflow.padEnd(41)} │\n` +
               `└${border}┘\n`;
    }

    static _explainTrigger(log, target, isMD) {
        const triggers = log.filter(l => l.type === 'condition' && l.result === true);
        const targetDesc = target ? `Objetivo: [${target.kind}] ${target.value || ''}` : 'Objetivo global';
        
        let text = isMD ? `### 🎯 Disparador\n` : `\n\x1b[1m\ud83c\udfaf Disparador:\x1b[0m\n`;
        text += isMD ? `- **${targetDesc}**\n` : `  ${targetDesc}\n`;
        
        if (triggers.length > 0) {
            const cond = triggers[0].condition;
            let msg = '';
            if (cond.includes('change_in')) {
                msg = `Se detectaron cambios en archivos protegidos por la política.`;
            } else if (cond.includes('install_package')) {
                msg = `Se detectó un evento de instalación de paquete.`;
            } else {
                msg = `La condición de activación se cumplió exitosamente.`;
            }
            text += isMD ? `- ℹ️ ${msg}\n` : `  \u2139\ufe0f ${msg}\n`;
        }
        return text;
    }

    static _explainEvidence(log, isMD) {
        const results = log.filter(l => l.type === 'engine_result');
        if (results.length === 0) return '';

        let text = isMD ? `### 🔍 Evidencia Recolectada\n` : `\n\x1b[1m\ud83d\udd0d Evidencia Recolectada:\x1b[0m\n`;
        for (const res of results) {
            const engineName = res.engine.replace(/_/g, ' ').toUpperCase();
            text += isMD ? `- **[${engineName}]**: ` : `  \u2022 [${engineName}]: `;
            
            if (res.engine === 'risk_orchestrator') {
                text += isMD ? `Riesgo detectado como **${res.band}** (Score: ${Math.round(res.score * 100)}%).\n` : 
                               `Riesgo detectado como \x1b[1m${res.band}\x1b[0m (Score: ${Math.round(res.score * 100)}%).\n`;
            } else if (res.engine === 'pr_policy_engine') {
                text += isMD ? `Veredicto de política: **${res.verdict}** (${res.violations} violaciones encontradas).\n` :
                               `Veredicto de política: \x1b[1m${res.verdict}\x1b[0m (${res.violations} violaciones encontradas).\n`;
            } else {
                text += `Procesamiento completado con éxito.\n`;
            }
        }
        return text;
    }

    static _explainLogic(log, isMD) {
        const steps = log.filter(l => l.type === 'action' || (l.type === 'condition' && l.result !== undefined));
        if (steps.length === 0) return '';

        let text = isMD ? `### 🧠 Lógica de Decisión\n` : `\n\x1b[1m\ud83e\udde0 Lógica de Decisión:\x1b[0m\n`;
        for (const step of steps) {
            if (step.type === 'condition') {
                const icon = step.result ? '✅' : '❌';
                const label = step.result ? 'CUMPLE' : 'NO CUMPLE';
                text += isMD ? `- ${icon} Evaluación: **${label}** (Condición interna evaluada)\n` :
                               `  ${icon} Evaluación: ${label} (Condición interna evaluada).\n`;
            } else if (step.type === 'action') {
                const actionIcon = ['block', 'review'].includes(step.action) ? '🚫' : '✅';
                const actionText = isMD ? `**${step.action.toUpperCase()}**` : `\x1b[1m${step.action.toUpperCase()}\x1b[0m`;
                text += isMD ? `- ${actionIcon} Acción Ejecutada: ${actionText}` :
                               `  ${actionIcon} Acción Ejecutada: ${actionText}`;
                
                if (step.params && Object.keys(step.params).length > 0) {
                    text += ` (Params: \`${JSON.stringify(step.params)}\`)`;
                }
                text += isMD ? '\n' : '.\n';
            }
        }
        return text;
    }

    static _formatFooter(verdict, profile, isMD) {
        if (isMD) {
            const statusColor = verdict === 'block' ? '🔴' : '🟢';
            return `\n---\n> ### ${statusColor} Veredicto Final: **${verdict.toUpperCase()}**\n` +
                   `> **Perfil aplicado:** ${profile} | Justificación estratégica de Sentinel.\n`;
        }

        const color = verdict === 'block' ? '\x1b[41m' : '\x1b[42m';
        const reset = '\x1b[0m';
        const padding = ' '.repeat(Math.max(0, 20 - verdict.length));
        
        return `\n${color}\x1b[1m VEREDICTO FINAL: ${verdict.toUpperCase()}${padding}${reset}\n` +
               `\x1b[2m Perfil aplicado: ${profile} | Justificación estratégica de Sentinel.\x1b[0m\n`;
    }
}

module.exports = SPLExplainer;
