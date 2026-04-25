const lab = require('../src/ui/backend/lab/orchestrator');

(async () => {
    try {
        console.log("Starting Round 6: The Persona Round (Contextual Correlation)...");
        await lab.runTimeLimitedSession(3);
        console.log("Round 6 finished. Measuring impact of Correlation & Persona on FPR.");
    } catch (e) {
        console.error("Round 6 failed:", e);
    }
})();
