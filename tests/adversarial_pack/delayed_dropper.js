const fs = require('fs');

console.log("[Malware] Delayed Dropper inicializado...");
setTimeout(() => {
    console.log("[Malware] Ejecutando payload diferido tras 10s...");
    try {
        fs.writeFileSync('/tmp/malware_dropped.sh', 'echo "Pwned"');
    } catch (e) {}
}, 10000);
