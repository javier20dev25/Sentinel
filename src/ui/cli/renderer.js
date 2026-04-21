const pc = require('picocolors');

function renderHierarchicalReport(alerts, filesScanned) {
    console.log(pc.bold(pc.blue('\n🛡️  Sentinel Local Analysis Report')));
    console.log(pc.dim('─'.repeat(50)));
    console.log(`${pc.bold('Files Scanned:')} ${filesScanned}`);
    console.log(`${pc.bold('Threats Found:')} ${alerts.length}`);
    console.log(pc.dim('─'.repeat(50)) + '\n');

    if (alerts.length === 0) {
        console.log(pc.green('   ✅ No threats found. Directory is clean.'));
        console.log();
        return;
    }

    // Agrupar por nivel de riesgo
    const critical = alerts.filter(a => a.severity === 'CRITICAL' || a.riskLevel >= 80);
    const high = alerts.filter(a => a.severity === 'HIGH' && a.riskLevel < 80);
    const suspicious = alerts.filter(a => a.severity !== 'CRITICAL' && a.severity !== 'HIGH' && a.riskLevel >= 40 && a.riskLevel < 80);
    
    // Sort
    const sortedAlerts = [...critical, ...high, ...suspicious];

    sortedAlerts.forEach(alert => {
        let tag = pc.bold(pc.white(' SAFE '));
        if (alert.riskLevel >= 80) tag = pc.bgRed(pc.bold(pc.white(` CRITICAL `)));
        else if (alert.riskLevel >= 65) tag = pc.bgYellow(pc.bold(pc.black(` HIGH `)));
        else tag = pc.bgBlue(pc.bold(pc.white(` SUSPICIOUS `)));

        console.log(`${tag} ${pc.bold(alert._file || 'unknown')} ${pc.dim(`(${alert.riskLevel})`)}`);

        // Intent Summary Layer
        if (alert.intentFingerprint) {
            const intents = alert.intentFingerprint.intent_signature || [];
            if (intents.length > 0) {
                console.log(`  ${pc.gray('→')} ${pc.cyan('Intent')}: ${intents.join(' + ')}`);
            }
        } else {
             console.log(`  ${pc.gray('→')} ${pc.cyan('Intent')}: General Threat`);
        }

        // Signals / Pattern Breakdown
        if (alert._rawRecord && alert._rawRecord.signals) {
            const pattern = alert._rawRecord.signals.map(s => s.type).join(' → ');
            console.log(`  ${pc.gray('→')} ${pc.magenta('Pattern')}: ${pattern}`);
        } else {
             console.log(`  ${pc.gray('→')} ${pc.magenta('Rule')}: ${alert.ruleName}`);
        }
        console.log();
    });
}

function renderExplain(threat) {
    console.log(pc.bold(pc.blue('\n🛡️  Sentinel Explainability Deck (Forensic View)')));
    console.log(pc.dim('─'.repeat(60)));
    
    console.log(`${pc.bold('Target:')} ${threat._file || 'Unknown'}`);
    console.log(`${pc.bold('Final Score:')} ${pc.red(threat.riskLevel)}/100`);
    console.log(`${pc.bold('Severity:')} ${threat.severity}`);
    
    const rec = threat._rawRecord;
    if (!rec) {
        console.log(pc.yellow('\n⚠️  No raw mathematical baseline found for this alert. (Legacy/Binary Rule)'));
        return;
    }

    console.log(pc.dim('─'.repeat(60)));
    console.log(pc.bold(pc.cyan('📊 Score Breakdown:')));
    
    if (rec.metrics) {
        console.log(`   ${pc.gray('•')} Max Single Signal Weight: ${rec.metrics.maxWeight.toFixed(1)}`);
        console.log(`   ${pc.gray('•')} Residual Overlap (+Score): ${rec.metrics.restWeight.toFixed(1)}`);
        
        console.log(`   ${pc.gray('•')} Residual Overlap (+Score): ${rec.metrics.restWeight.toFixed(1)} x ${rec.metrics.residualFactor.toFixed(2)}`);
        
        console.log(`   ${pc.gray('→')} Raw Additive Score: ${rec.metrics.rawScore.toFixed(2)}`);
        console.log(`   ${pc.gray('→')} Corporate Noise Cap: Math.min(rawScore, ${rec.metrics.effectiveCap.toFixed(1)})`);
        
        if (rec.metrics.maxWeight >= 85) {
            console.log(pc.red(`   🔥 [ESCAPE HATCH] Single critical vector bypass triggered (Penalty Lifted, Cap Lifted)`));
        }

        console.log(`   ${pc.gray('→')} Logistic Transformation (k=0.15, mid=50): ${rec.metrics.finalScore.toFixed(2)}`);
        
        if (rec.isComposite && rec.metrics.finalScore >= 75) {
             console.log(pc.red(`   🔥 [COMPOSITE BLOCK] High confidence offensive operation detected. Forcing to Critical.`));
        }
    }
    
    console.log(pc.dim('─'.repeat(60)));
    console.log(pc.bold(pc.magenta('🧬 Detected Signals Layer:')));
    rec.signals.forEach(s => {
        console.log(`   [${s.weight}] ${pc.cyan(s.type)}`);
        // Muestra evidencia pero truncada para que el CLI no se ahogue
        const snip = (s.evidence || '').substring(0, 100).replace(/\n/g, ' ');
        console.log(`        ${pc.gray('↳')} ${snip}`);
    });
    
    console.log(pc.dim('─'.repeat(60)) + '\n');
}

function renderTrace(threat) {
    console.log(pc.bold(pc.blue('\n🛡️  Sentinel Attack Trace (Execution Flow)')));
    console.log(pc.dim('─'.repeat(60)));
    const rec = threat._rawRecord;
    if (!rec) {
        console.log(pc.yellow('⚠️  Trace not available.'));
        return;
    }
    
    let step = 1;
    rec.signals.forEach(s => {
        let color = pc.white;
        if (s.type.includes('ACCESS') || s.type.includes('REQUIRE')) color = pc.cyan;
        if (s.type.includes('WARPING') || s.type.includes('OBFUSCATION') || s.type.includes('POLLUTION') || s.type.includes('BASE64')) color = pc.yellow;
        if (s.type.includes('EXECUTION') || s.type.includes('SINK_CALL') || s.type.includes('REVERSE_SHELL')) color = pc.red;
        
        console.log(pc.bold(color(`[ Step ${step} ] ${s.type}`)));
        console.log(`   ${pc.gray(s.evidence)}`);
        if (step !== rec.signals.length) console.log(pc.dim('   │\n   ▼'));
        step++;
    });
    console.log(pc.dim('─'.repeat(60)) + '\n');
}

module.exports = {
    renderHierarchicalReport,
    renderExplain,
    renderTrace
};
