/**
 * Sentinel 3.5: SARB Adversarial Mutator
 * 
 * Generates mutated versions of SARB payloads to test detection generalization.
 * Validates that renaming or adding complexity doesn't bypass the 80+ threshold.
 */

const fs = require('fs');
const path = require('path');
const { scanFile } = require('../src/ui/backend/scanner/index');

const TEST_FILE = path.join(__dirname, '../tests/adversarial/sarb_suite.js');

function mutate(code) {
    let mutated = code;

    // 1. Rename Mutation (Smart regex with word boundaries)
    const varNames = ['dangerousAlias', 'encodedInner', 'encodedOuter', 'innocentObj', 'client', 'a', 'b', 'f', 'r', 'encoded'];
    varNames.forEach(v => {
        const randomName = 'var_' + Math.random().toString(36).substring(7);
        // Usar regex con \b para evitar mutar palabras que contienen la letra (ej. 'eval')
        const re = new RegExp('\\b' + v + '\\b', 'g');
        mutated = mutated.replace(re, randomName);
    });

    // 2. Dead Code Injection (Disabled)
    // No-op for now to keep parser stability

    // 3. Redundant Wrapper (Only if not ESM to avoid syntax error in acorn)
    if (!mutated.includes('export ')) {
        mutated = `(function() {\n${mutated}\n})();`;
    }

    return mutated;
}

console.log("=== SENTINEL SARB MUTATOR v3.5 ===");
console.log("- Checking generalization against mutated payloads...");

if (!fs.existsSync(TEST_FILE)) {
    console.error("Error: sarb_suite.js not found.");
    process.exit(1);
}

const content = fs.readFileSync(TEST_FILE, 'utf8');
const cases = content.split(/\n(?=\/\*\*)/g).filter(s => s.trim().length > 0);

let allPassed = true;

cases.forEach((caseBody, idx) => {
    const caseId = idx + 1;
    const mutatedCode = mutate(caseBody);
    
    // Escanear la versión mutada
    const results = scanFile(`sarb_mutated_${caseId}.js`, mutatedCode);
    
    const maxScoreAlert = results.alerts.reduce((max, alert) => {
        const score = alert.riskLevel || 0;
        return score > (max.riskLevel || 0) ? alert : max;
    }, {});

    const score = maxScoreAlert.riskLevel || 0;
    const isDetected = score >= 80;

    console.log(`[MUTATED CASE ${caseId}] Score: ${score}/100 -> ${isDetected ? '✅ DETECTED' : '❌ BYPASSED'}`);
    
    if (!isDetected) {
        allPassed = false;
        console.log("   ⚠️ REGRESSION DETECTED!");
        console.log("   Evidence Snippet:", mutatedCode.substring(0, 300) + "...");
    }
});

console.log("-".repeat(40));
if (allPassed) {
    console.log("✅ RESULT: PASS (All mutated payloads blocked at 80+)");
    process.exit(0);
} else {
    console.error("❌ RESULT: FAIL (Mutations caused escapes below critical threshold)");
    process.exit(1);
}
