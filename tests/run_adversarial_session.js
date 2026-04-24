const lab = require('../src/ui/backend/lab/orchestrator');

(async () => {
    try {
        await lab.runSession(20, 0.7);
        console.log("Adversarial session successful.");
    } catch (e) {
        console.error("Adversarial session failed:", e);
    }
})();
