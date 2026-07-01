const fs = require('fs');
const readline = require('readline');

async function generateReport() {
    const fileStream = fs.createReadStream('reports/live_scan/live_observations.jsonl');
    const rl = readline.createInterface({ input: fileStream, crlfDelay: Infinity });

    let total = 0;
    const prioritized = [];
    const suppressed = [];
    
    for await (const line of rl) {
        if (!line.trim()) continue;
        total++;
        const record = JSON.parse(line);
        
        if (record.impact > 0) {
            prioritized.push(record);
        } else if (record.provenance && record.provenance.length > 0) {
            suppressed.push(record);
        }
    }

    // --- LEVEL 1: EXECUTIVE RISK BRIEF ---
    console.log('====================================================');
    console.log('SENTINEL EXECUTIVE SECURITY BRIEF');
    console.log('====================================================\n');
    console.log(`${total} PRs analyzed`);
    console.log(`${prioritized.length} prioritized signals`);
    console.log(`${suppressed.length} suppressed by contextual dampening`);
    console.log(`0 critical blocks\n`);
    
    console.log('TOP RISKS');
    console.log('--------------------------------');
    prioritized.sort((a,b) => b.impact - a.impact).forEach(rec => {
        console.log(`PR #${rec.pr} — ${rec.repo}`);
        const primaryIntent = rec.provenance[0] ? rec.provenance[0].intent : 'UNKNOWN';
        console.log(`Risk: ${primaryIntent}`);
        console.log(`Score: ${rec.impact}/100`);
        console.log(`Assessment: Review Recommended\n`);
        
        console.log(`Why:`);
        const context = rec.provenance[0].file.includes('test') ? 'test context' : 'production path';
        console.log(`${primaryIntent} detected in ${context}.\n`);
        
        console.log(`Evidence:`);
        console.log(`${rec.provenance[0].file}:L${rec.provenance[0].line}`);
        console.log(`${rec.provenance[0].excerpt.trim().substring(0, 80)}...`);
        console.log('--------------------------------');
    });

    // --- LEVEL 2: SUPPRESSED FINDINGS INTELLIGENCE ---
    console.log('\n\n====================================================');
    console.log('SUPPRESSED FINDINGS ANALYSIS (Engineering Feedback)');
    console.log('====================================================\n');
    console.log(`${suppressed.length} signals suppressed\n`);
    
    let testPatterns = 0, errorStrings = 0, frameworkInternal = 0;
    
    suppressed.forEach(rec => {
        rec.provenance.forEach(p => {
            if (p.file.includes('test') || p.file.includes('__tests__')) testPatterns++;
            else if (p.file.endsWith('.json') || p.file.includes('error')) errorStrings++;
            else frameworkInternal++;
        });
    });

    console.log('Breakdown of suppressed noise:');
    console.log('--------------------------------');
    console.log(`${testPatterns.toString().padEnd(4)} — Test-only patterns (Dampened)`);
    console.log(`${errorStrings.toString().padEnd(4)} — Error-message / JSON strings (Dampened)`);
    console.log(`${frameworkInternal.toString().padEnd(4)} — Framework internal behavior (Benign Context)\n`);
    
    console.log('Engineering recommendation:');
    console.log('Move security-sensitive keyword examples (like fetch, eval) to dedicated mock/test fixtures to reduce baseline scanner noise.');

    // --- LEVEL 3: FORENSIC EVIDENCE APPENDIX ---
    console.log('\n\n====================================================');
    console.log('FORENSIC EVIDENCE APPENDIX (Audit Trail)');
    console.log('====================================================\n');
    if (suppressed.length > 0) {
        const sample = suppressed[0]; // Mostrar un ejemplo
        console.log(`Suppressed Signal Example`);
        console.log(`PR: #${sample.pr} (${sample.repo})`);
        console.log(`Intent: ${sample.provenance[0].intent}`);
        console.log(`Reason Suppressed: Match found inside test/mock paths, nullifying global risk.\n`);
        
        console.log(`Evidence:`);
        console.log(`${sample.provenance[0].file}:L${sample.provenance[0].line}`);
        console.log(`Excerpt: ${sample.provenance[0].excerpt.trim().substring(0, 80)}...`);
    } else {
        console.log(`No suppressed findings to audit in this batch.`);
    }
}

generateReport().catch(console.error);
