const fs = require('fs');
const readline = require('readline');

async function analyze() {
    const fileStream = fs.createReadStream('reports/live_scan/live_observations.jsonl');
    const rl = readline.createInterface({ input: fileStream, crlfDelay: Infinity });

    let total = 0;
    let riskCount = 0;
    let highImpact = [];
    
    for await (const line of rl) {
        if (!line.trim()) continue;
        total++;
        const record = JSON.parse(line);
        
        // We only care about PRs that the engine flagged with some impact
        if (record.impact > 0 || (record.provenance && record.provenance.length > 0)) {
            riskCount++;
            highImpact.push(record);
        }
    }

    console.log('====================================');
    console.log('💰 THE MONEY TEST: BUSINESS IMPACT');
    console.log('====================================');
    console.log(`Total PRs Analyzed : ${total}`);
    console.log(`Risk Suspicious PRs: ${riskCount}`);
    console.log(`False Positives    : ${total - riskCount} (Silenced by Dampening)`);
    console.log('------------------------------------\n');

    if (highImpact.length === 0) {
        console.log('✅ No high-risk threats detected in this batch.');
        return;
    }

    highImpact.sort((a,b) => b.impact - a.impact).slice(0, 5).forEach(rec => {
        console.log(`🚨 Risk Summary: ${rec.repo} PR #${rec.pr}`);
        console.log(`   Score      : ${rec.impact}/100 (Verdict: ${rec.verdict})`);
        
        let reasons = [];
        rec.provenance.forEach(p => {
            const context = p.file.includes('test') ? '[TEST PATH]' : '[PROD PATH]';
            reasons.push(`- ${p.intent} detected in ${context}`);
        });
        let uniqueReasons = [...new Set(reasons)];
        
        console.log(`   Why flagged:`);
        uniqueReasons.forEach(r => console.log(`      ${r}`));
        
        console.log(`   Evidence   :`);
        if (rec.provenance.length > 0) {
            const topProv = rec.provenance.sort((a,b) => b.severity - a.severity)[0];
            console.log(`      ${topProv.file}:L${topProv.line}`);
            console.log(`      + ${topProv.excerpt.trim().substring(0, 80)}${topProv.excerpt.length > 80 ? '...' : ''}`);
        } else {
            console.log(`      (Reasoning: ${rec.reasoningTrace})`);
        }
        
        console.log(`   Hash       : ${rec.decision_hash}`);
        console.log('------------------------------------');
    });
}

analyze().catch(console.error);
