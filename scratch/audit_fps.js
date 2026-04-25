const fs = require('fs');
const path = require('path');

const resultsPath = path.join(__dirname, '../src/ui/backend/lab/adversarial_results.json');

try {
    const data = JSON.parse(fs.readFileSync(resultsPath, 'utf8'));
    const fps = data.filter(r => r.outcome.error_type === 'FP');
    
    const triggers = {};
    fps.forEach(fp => {
        // Since we don't have the exact signal in the summary results, 
        // we'll look at the strategy and iteration to infer.
        // In a real scenario, we'd log the specific signal.
        const key = fp.strategy || 'unknown';
        triggers[key] = (triggers[key] || 0) + 1;
    });

    console.log("Top FP Strategies:", Object.entries(triggers).sort((a,b) => b[1] - a[1]));
    console.log("Total FPs analyzed:", fps.length);

} catch (e) {
    console.error("Audit failed:", e.message);
}
