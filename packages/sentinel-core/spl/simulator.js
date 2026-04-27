/**
 * Sentinel Playbook — Impact Simulator (v0.1)
 * 
 * Allows users to simulate a playbook's impact on a target repository
 * before actually enforcing it in CI/CD.
 */

'use strict';

const { compile } = require('./compiler');
const { execute } = require('./runtime');

class SPLSimulator {
    /**
     * Simulates the impact of a playbook.
     * 
     * @param {string} source - .sentinel source code
     * @param {Object} baseContext - The context to use for simulation
     * @returns {Object} Simulation results and impact summary
     */
    static async simulate(source, baseContext = {}) {
        const { compiled, warnings } = compile(require('./parser').parse(require('./lexer').tokenize(source)));
        const executionResult = await execute(compiled, baseContext);
        
        const impact = {
            workflows_evaluated: executionResult.results.length,
            verdicts: executionResult.results.map(r => ({ workflow: r.workflow, verdict: r.verdict })),
            actions_projected: [],
            warnings: warnings
        };

        for (const res of executionResult.results) {
            const actions = res.log.filter(l => l.type === 'action').map(l => l.action);
            impact.actions_projected.push(...actions);
        }

        return impact;
    }

    static formatImpactReport(impact) {
        let text = `\n\x1b[36m\ud83c\udfdb\ufe0f  SENTINEL POLICY SIMULATION REPORT\x1b[0m\n`;
        text += `\x1b[2mSimulando impacto sobre el contexto actual...\x1b[0m\n\n`;

        if (impact.warnings.length > 0) {
            text += `\x1b[33m\u26a0 Warnings detectados en el playbook:\x1b[0m\n`;
            impact.warnings.forEach(w => text += `  - ${w}\n`);
            text += `\n`;
        }

        text += `\x1b[1mAnálisis de Veredictos:\x1b[0m\n`;
        impact.verdicts.forEach(v => {
            const color = v.verdict === 'block' ? '\x1b[31m' : '\x1b[32m';
            text += `  \u2022 Workflow "${v.workflow}": ${color}${v.verdict.toUpperCase()}\x1b[0m\n`;
        });

        text += `\n\x1b[1mAcciones Proyectadas:\x1b[0m\n`;
        const actionCounts = {};
        impact.actions_projected.forEach(a => actionCounts[a] = (actionCounts[a] || 0) + 1);
        
        if (Object.keys(actionCounts).length === 0) {
            text += `  (No se proyectan acciones de respuesta).\n`;
        } else {
            Object.entries(actionCounts).forEach(([action, count]) => {
                text += `  \u2022 ${action.toUpperCase()}: ${count} veces\n`;
            });
        }

        text += `\n\x1b[35m[CONCLUSIÓN]\x1b[0m\n`;
        const blockCount = impact.verdicts.filter(v => v.verdict === 'block').length;
        if (blockCount > 0) {
            text += `\x1b[31mEsta política BLOQUEARÍA la operación bajo el contexto actual.\x1b[0m\n`;
            text += `Asegúrate de que las reglas de exclusión sean correctas antes de activar en modo STRICT.\n`;
        } else {
            text += `\x1b[32mEsta política permitiría la operación bajo el contexto actual.\x1b[0m\n`;
        }

        return text;
    }
}

module.exports = SPLSimulator;
