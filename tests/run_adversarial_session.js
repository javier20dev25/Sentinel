const lab = require('../src/ui/backend/lab/orchestrator');

(async () => {
    try {
        // Running a 2-minute session for validation (can be adjusted to 5)
        await lab.runTimeLimitedSession(2);
        console.log("Adversarial combat session successful.");
    } catch (e) {
        console.error("Adversarial combat session failed:", e);
    }
})();
