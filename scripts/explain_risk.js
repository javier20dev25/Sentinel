const fs = require('fs');
const readline = require('readline');

const args = process.argv.slice(2);
const targetPr = args.find(a => a.startsWith('--pr='))?.split('=')[1];

async function explain() {
    if (!targetPr) return console.log("Please provide --pr=NUMBER");
    
    const fileStream = fs.createReadStream('reports/live_scan/live_observations.jsonl');
    const rl = readline.createInterface({ input: fileStream, crlfDelay: Infinity });

    for await (const line of rl) {
        if (!line.trim()) continue;
        const record = JSON.parse(line);
        
        if (record.pr.toString() === targetPr) {
            console.log(`====================================`);
            console.log(`🔍 FORENSIC DEEP DIVE: PR #${record.pr} (${record.repo})`);
            console.log(`====================================`);
            console.log(`Decision Hash : ${record.decision_hash}`);
            console.log(`Final Verdict : ${record.verdict}`);
            console.log(`Impact Score  : ${record.impact}/100`);
            
            console.log(`\n[ MATHEMATICAL TRACE ]`);
            console.log(`> ${record.reasoningTrace}`);
            
            console.log(`\n[ RAW PROVENANCE EVIDENCE ]`);
            record.provenance.forEach((p, idx) => {
                console.log(`  Evidence #${idx + 1} [Intent: ${p.intent} | Severity: ${p.severity}]`);
                console.log(`  File: ${p.file}:L${p.line}`);
                console.log(`  Code: ${p.excerpt}`);
                console.log(`  ----------------------------------`);
            });
            return;
        }
    }
    console.log(`PR #${targetPr} not found in local evidence.`);
}

explain().catch(console.error);
